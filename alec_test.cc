// Adobe Leaked Email Chcker
// Date: December 2013
// Author: Jervis Muindi

// Standard Lib Header
#include <iostream>

// Custom Common Code
//#include "common/base/flags.h"
//#include "common/base/init.h"
//#include "common/log/log.h"


#include "alec.h"
#include "common/test/test.h"
using namespace alec;

TEST(Alec, DummyTest) {
  EXPECT_TRUE( 1 == 1) << "I should fail";
  CredentialReader cred_reader("sample_cred.txt");
}


int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
