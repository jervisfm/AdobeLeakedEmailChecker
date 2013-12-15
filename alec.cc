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
    // TODO(jervis): Complete and test this method
    // line looks like:
    // 000000010-|--|-person10@dls.net-|-IMj2ZmZchtNM=-|-internet|--
    // The fomrat is :
    // <user_id> | <adobe_username> | <email address> | <password hash> | <password hint>
    // which was obtained from a SOPHOS analysis: http://goo.gl/xIEZSe
    return false;
    
  }

  CredentialReader::~CredentialReader() { ; } 


} // alec namespace

