#ifndef _ALEC_H__
#define _ALEC_H__

// Custom Common Code
#include "common/base/flags.h"
#include "common/base/init.h"
#include "common/log/log.h"
#include "common/strings/stringpiece.h"

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

using file::FileLineReader; 

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
    CredentialReader(StringPiece filename);

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
    FileLineReader file_reader_;
    
  };



} // alec namespace

#endif // _ALEC_H__
