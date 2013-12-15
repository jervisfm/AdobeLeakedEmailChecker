// Adobe Leaked Email Chcker
// Date: December 2013
// Author: Jervis Muindi

// Standard Lib Header
#include <iostream>

// Custom Common Code
#include "common/base/flags.h"
#include "common/base/init.h"

// Program Flags
DEFINE_string(db_path, "adobe.db", 
	      "Path to LevelDB file containing leaked Adobe passwords."
	      "Defaults to using 'adobe.db'");

using namespace std;
int main(int argc, char**argv) {
  InitProgram(&argc, &argv);
  cout << "DB PathFlag is " << FLAGS_db_path;
  return 0;
}
