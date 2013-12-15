// Adobe Leaked Email Chcker
// Date: December 2013
// Author: Jervis Muindi

// Standard Lib Header
#include <iostream>

// Custom Common Code
#include "common/base/flags.h"
#include "common/base/init.h"
#include "common/log/log.h"

#include "alec.h"

// Program Flags
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

namespace {

  struct Credentials {
    string email; // email address 
    string hash; // encrypted hash of the user password
    string adobe_id; // adobe user id
    string hint; // password hint
  };


  // Processes a Raw Password Dumpfile and obtains 
  // Credentials contained in thiem.
  class CredentialReader {
  public:
    CredentialReader() {

    }

    ~CredentialReader() {

    }

  private:
    int x;
  };


} // anonymous namespace

