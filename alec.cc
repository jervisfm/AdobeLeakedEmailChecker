// Adobe Leaked Email Chcker
// Date: December 2013
// Author: Jervis Muindi

// Standard Lib Header
#include <iostream>

#include "common/file/linereader.h"

#include "alec.h"

using namespace std;

namespace alec {

  CredentialReader::CredentialReader(const string& filename) : 
    filename_(filename), 
    file_reader_(filename) {
    
  }
  
  CredentialReader::NextCredential(Crendential *output) {
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
  }

  CredentialReader::~CredentialReader() { } 


} // alec namespace

