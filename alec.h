#ifndef _ALEC_H__
#define _ALEC_H__

#include <string>
#include <iostream>

// Custom Common Code
 #include "common/base/flags.h"
//#include "common/base/init.h"
#include "common/strings/stringpiece.h"
#include "common/file/linereader.h"

using std::string;
using std::ostream;

namespace alec {

  struct Credential {
    string email; // email address 
    string hash; // encrypted hash of the user password
    string username; // adobe user id / username
    string rec_id; // unique record id of this credential from the original dump file. 
    string hint; // password hint

    // Compares two Credential object. Credential
    // object are considered equal iff their individial
    // string fields match. 
    bool operator==(const Credential& other) const;
    
    // Gets a String representation of all the details
    // stored in this credential object. 
    string ToString() const;

    // Prints the ToString() representation of the 
    // Credential object. 
    friend ostream& operator<<(ostream &out, const Credential& other);
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

  // Reads Credentials from the given Credential Reader
  // and saves them into an Ondisk Hashtable. 
  class CredentialProcessor { 
  public:
    CredentialProcessor(CredentialReader* reader) : cred_reader_(reader) {}
    
    // Reads through all the Credential records available in the Credential
    // Reader and saves them to an on-disk LevelDB Hashtable file that has
    // the name 'filename'. Returns true on success. 
    bool GenerateDiskHashTable(StringPiece filename);
    
    ~CredentialProcessor() {}

  private:
    CredentialReader* cred_reader_; // not owned
  };



} // alec namespace

#endif // _ALEC_H__
