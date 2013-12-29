// Adobe Leaked Email Checker
// Date: December 2013
// Author: Jervis Muindi

// Standard Lib Header
#include <iostream>

#include "common/strings/strutil.h"
#include "common/log/log.h"

#include "third_party/leveldb/leveldb.h"

#include "alec.h" 

using namespace std;

namespace alec {
  bool Credential::operator==(const Credential& other) const {
    return 
      this->email == other.email &&
      this->hash == other.hash &&
      this->username == other.username &&
      this->rec_id == other.rec_id &&
      this->hint == other.hint;
  }

  string Credential::ToString() const {
    string result;
    result += "Email: '" + email + "'\n";
    result += "Username: '" + username + "'\n";
    result += "Record ID: " + rec_id + "\n";
    result += "Password Hint: '" + hint + "'\n";
    return result;
  }

  ostream& operator<<(ostream &out, const Credential& other) {
    string result = other.ToString();
    out << result;
    return out;
  }

  CredentialReader::CredentialReader(const string& filename) : 
    filename_(filename), 
    file_reader_(filename) {
    LOG(INFO) << "Cred reader initd";
  }
  bool CredentialReader::Done() { 
    return file_reader_.Done();
  }
  bool CredentialReader::NextCredential(Credential *output) {
    if (output == NULL) {
      LOG(ERROR) << "Given a NULL output pointer";
      return false;
    }
    
    if (Done()) {
      return false;
    } 

    Credential cred;
    // Find a non-empty credentials line
    bool line_empty;
    string line;
    do {
      line = file_reader_.line();
      line_empty = line.empty();
      if (line_empty) {
	file_reader_.Next();
      }
    } while (line_empty);

    if (!ParseLine(line, &cred)) {
      LOG(ERROR) << "Failed to Parse Line: '" << line << "'";
      return false;
    } else {
        *output = cred;
	file_reader_.Next();
	return true;
    }
  }

  // static class method
  bool CredentialReader::ParseLine(const string& line, Credential* result) {
    bool warnings_occurred = false;
    if (result == NULL) {
      LOG(ERROR) << "Given NULL result pointer";
      return false;
    }

    // line mostly looks like:
    // 000000010-|--|-person10@dls.net-|-IMj2ZmZchtNM=-|-internet|--
    // The format is :
    // <user_id> | <adobe_username> | <email address> | <password hash> | <password hint>
    // which was obtained from a SOPHOS analysis: http://goo.gl/xIEZSe
    
    vector<StringPiece> pieces = strings::Split(line, "|");
    int i = 0;
    for (auto& piece : pieces) {
      VLOG(2) << "piece " << i << ": " << piece;
      ++i;
    }

    // Check all the fields are present
    static const int kExpectedPieces = 6;
    if (pieces.size() != kExpectedPieces) {
      LOG(WARNING) << "Expected line to have " << kExpectedPieces
		 << " '|'-separates pieces but got " << pieces.size()
		 << "\nLine:" << line;
      warnings_occurred = true;
    }

    // Default expected indexes into the 'pieces' string vector
    int rec_id_idx = 0, username_idx = 1, email_idx = 2, 
      hash_idx = 3, hint_idx = 4;
  
    // Sanity Check
    if ( pieces[5].as_string() != "--") {
      LOG(WARNING) << "Index 5 did not contain '--' as expected." 
		   << "Credentials may be incorrectly parsed"
		   << "Line: " << line;
      warnings_occurred = true;
    }

    // There's a special case when 'line' is split into exactly 
    // 7 pieces. In this scenario, the email is split into 
    // separate username and domain parts. This looks like this:
    // 115985151-|--|-kadja_83|@yahoo.es-|-CWWWYFjjxa/ioxG6CatHBw==-|-dra|--
    bool email_special_case = pieces.size() == 7;
    if (email_special_case) { 
      // The hash/hint fields are one away from their normal/expected location
      ++hash_idx;
      ++hint_idx;
    }

    string rec_id = pieces[rec_id_idx].as_string();
    // record id has form "<rec_id>-", so chop off the trailing '-' character
    rec_id = rec_id.substr(0, rec_id.size() - 1);
    
    // username has form "-<username>-", so chop off the leading/trailing '-' character.
    string username = pieces[username_idx].as_string();
    username = username.substr(1, username.size() - 2);

    string email = pieces[email_idx].as_string();
    // email has form "-<email>-", so chop of the leading and trailing '-' character.
    email = email.substr(1, email.size() - 2);
    if (email_special_case) { 
      string domain = pieces[email_idx+1].as_string();
      // Domain looks like: '@yahoo.es-', so get rid of trailing '-'
      domain = domain.substr(0, domain.size() - 1);
      email += domain;
    }

    string hash = pieces[hash_idx].as_string();
    // hash has form "-<hash>-", so chop of the leading and trailing '-' character.
    hash = hash.substr(1, hash.size() - 2);
    
    string hint = pieces[hint_idx].as_string();
    // hint has form "-<hint>", so just chop of the leading '-' character
    hint = hint.substr(1);

    // Okay, save the parsed result
    result->email = email;
    result->username = username;
    result->rec_id = rec_id;
    result->hint = hint;
    result->hash = hash;

    // Print out the Parsed Credential object if warning occured
    if (warnings_occurred) {
      LOG(WARNING) << "Parsed Credential is\n" << *result << "\n---------";
    }
    return true;
  }

  CredentialReader::~CredentialReader() { ; } 

  bool CredentialProcessor::GenerateDiskHashTable(StringPiece filename) {
    // Open a LevelDB Database
    leveldb::DB* db;
    leveldb::Options options;
    leveldb::Status status;
    options.create_if_missing = true;
    const string& filename_string = filename.ToString();
    status = leveldb::DB::Open(options, filename_string, &db);
    if (!status.ok()) {
      LOG(ERROR) << "Failed to Open LevelDB Database: " << filename_string ;
      return false;
    }
    
    // Read and save all credential records
    Credential cred;
    bool success_read;
    int count = 0, failed_reads = 0, failed_writes = 0;
    while (!cred_reader_->Done()) {
      LOG_EVERY_N(INFO, 100000) << "Processing Record #" << count << " ...";
      success_read = cred_reader_->NextCredential(&cred);
      if (!success_read) {
	++failed_reads;
	LOG(WARNING) << "Failed to obtain credential record # " << count
		     << ". Total Read Failures now at: " << failed_reads;
	++count;
	continue;
      }

      // Save the record to disk
      string key = strings::LowerString(cred.email);
      char *cred_data = reinterpret_cast<char*>(&cred);
      int cred_size = sizeof(cred);
      leveldb::Slice value(cred_data, cred_size);
      
      status = db->Put(leveldb::WriteOptions(), key, value);
      if (!status.ok()) {
	++failed_writes;
	LOG(WARNING) << "Failed to save credential record # " << count
		     << ". Total Write Failures now at: " << failed_writes;
      }
      ++count;
    }
    
    // Close the Database
    delete db;

    return true;
  }


} // alec namespace

