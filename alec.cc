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
    const string& line = file_reader_.line();
    if (!ParseLine(line, &cred)) {
      LOG(ERROR) << "Failed to Parse Line: " << line;
      return false;
    } else {
        *output = cred;
	file_reader_.Next();
	return true;
    }
	
  }

  // static class method
  bool CredentialReader::ParseLine(const string& line, Credential* result) {
    if (result == NULL) {
      LOG(ERROR) << "Given NULL result pointer";
      return false;
    }

    // line looks like:
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
      LOG(ERROR) << "Expected line to have " << kExpectedPieces
		 << " '|'-separates pieces but got " << pieces.size()
		 << "\nLine:" << line;
      return false;
    }

    // Sanity Check
    if ( pieces[5].as_string() != "--") {
      LOG(WARNING) << "Index 5 did not contain '--' as expected." 
		   << "Credentials may be incorrectly parsed"
		   << "Line: " << line;
    }

    string rec_id = pieces[0].as_string();
    // record id has form "<rec_id>-", so chop off the trailing '-' character
    rec_id = rec_id.substr(0, rec_id.size() - 1);
    
    // username has form "-<username>-", so chop off the leading/trailing '-' character.
    string username = pieces[1].as_string();
    username = username.substr(1, username.size() - 2);

    string email = pieces[2].as_string();
    // email has form "-<email>-", so chop of the leading and trailing '-' character.
    email = email.substr(1, email.size() - 2);

    string hash = pieces[3].as_string();
    // hash has form "-<hash>-", so chop of the leading and trailing '-' character.
    hash = hash.substr(1, hash.size() - 2);
    
    string hint = pieces[4].as_string();
    // hint has form "-<hint>", so just chop of the leading '-' character
    hint = hint.substr(1);

    // Okay, save the parsed result
    result->email = email;
    result->username = username;
    result->rec_id = rec_id;
    result->hint = hint;
    result->hash = hash;
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
      LOG_EVERY_N(INFO, 10) << "Processing Record #" << count;
      success_read = cred_reader_->NextCredential(&cred);
      if (!success_read) {
	++failed_reads;
	LOG(WARNING) << "Failed to obtain credential record # " << count
		     << ". Total Read Failures now at: " << failed_reads;
	++count;
	continue;
      }

      // Save the record to disk
      string key = cred.email;
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

