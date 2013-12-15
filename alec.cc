// Adobe Leaked Email Checker
// Date: December 2013
// Author: Jervis Muindi

// Standard Lib Header
#include <iostream>

#include "common/strings/strutil.h"
#include "common/log/log.h"

#include "alec.h" 

// Flags
DEFINE_string(file_path, "adobe.db", 
	      "Path to LevelDB file containing leaked Adobe passwords."
	      "Defaults to using 'adobe.db'");
DEFINE_string(dump_file, "adobe_dump.txt", 
	      "File path to the uncompressed raw dump of the adobe credentials.");
DEFINE_bool(process_raw_dump, false, "Assumes that the file path "
	    "in '--dump_file' points to a raw text dump of the credentials and process them"
	    "to generate an on disk LEVELDB hashtable with the name specified in '--output_file'."
            "The LEVELDB hastable will be queryable in O(1) / constant time. ");

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
    for (auto& piece : pieces) {
      
      cout << piece << endl;
    }

    // Check all the fields are present
    static const int kExpectedPieces = 6;
    static const string kEmptyField = "--";
    if (pieces.size() != kExpectedPieces) {
      LOG(ERROR) << "Expected line to have " << expected_pieces 
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


} // alec namespace

