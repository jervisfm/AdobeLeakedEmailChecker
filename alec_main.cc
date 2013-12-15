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

static void OutputFlags() {
  LOG(INFO) << "(LevelDB) file_path: " << FLAGS_file_path;
  LOG(INFO) << "dump_file: " << FLAGS_dump_file;
  LOG(INFO) << "process_raw_dump?" << FLAGS_process_raw_dump; 
}


// Program Flags
int main(int argc, char **argv) {
  InitProgram(&argc, &argv);
  LOG(INFO) << "Hello from Alec MAIN" ;
  OutputFlags();
  return 0;
}
