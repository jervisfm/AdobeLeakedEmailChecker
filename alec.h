#ifndef _ALEC_H__
#define _ALEC_H__

#include <string>

// Custom Common Code
 #include "common/base/flags.h"
//#include "common/base/init.h"
#include "common/strings/stringpiece.h"
#include "common/file/linereader.h"

// Flags




DECLARE_string(file_path);
DECLARE_string(dump_file);
DECLARE_bool(process_raw_dump);

using std::string;

namespace alec {

  struct Credential {
    string email; // email address 
    string hash; // encrypted hash of the user password
    string adobe_id; // adobe user id
    string hint; // password hint
  };


  // Processes a Raw Password Dumpfile and obtains 
  // Credentials contained in thiem.
  class CredentialReader {
  public:
    // Reads Raw Credentials stored in the given
    // file name
    CredentialReader(const string& filename);

    // Get the next record of credentials from
    // the underlying file. Returns true on success.
    bool NextCredential(Credential *output); 

    // Indicates when we have processed/read all credential
    // Records from the given file. 
    bool Done();

    // Parses a line with credentials data and converts
    // that to a Credentials data object. 
    // 'line' is the line the credential line to parse. 
    // It should look something like this:
    // 000000010-|--|-person10@dls.net-|-IMj2ZmZchtNM=-|-internet|--
    // 'result' - where to stored the parsed Credential
    // Returns true on success.
    static bool ParseLine(const string& line, Credential* result);
    
    ~CredentialReader();

  private:
    string filename_;
    file::FileLineReader file_reader_;
    
  };



} // alec namespace

#endif // _ALEC_H__
