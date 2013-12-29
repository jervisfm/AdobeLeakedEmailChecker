// Adobe Leaked Email Chcker
// Date: December 2013
// Author: Jervis Muindi

// Standard Lib Header
#include <iostream>

// Custom Common Code
//#include "common/base/flags.h"
//#include "common/base/init.h"
//#include "common/log/log.h"
#include "common/test/test.h"
#include "common/strings/strutil.h"

#include "alec.h"

using namespace alec;

TEST(Alec, ReadCredentialFile) {
  CredentialReader reader("sample_cred.txt");
  EXPECT_FALSE(reader.Done());

  Credential expected_cred;
  expected_cred.rec_id = "000000006";
  expected_cred.username = "";
  expected_cred.email = "person6@yahoo.com";
  expected_cred.hash = "DGM2c/HbXTIkDDM5y6e6/lQ==";
  expected_cred.hint = "same";

  Credential cred;
  while (!reader.Done()) {
    EXPECT_TRUE(reader.NextCredential(&cred)) << "Failed to get next credential";
    EXPECT_TRUE ( expected_cred == cred ) 
      << "Expected Cred:\n" << expected_cred
      << "**********\nBut Got:\n" << cred;
  }
}

TEST(Alec, ParseLine) {
  string line = "000000006-|--|-person6@yahoo.com-|-DGM2c/HbXTIkDDM5y6e6/lQ==-|-same|--";
  Credential expected_cred;
  Credential actual_cred;

  expected_cred.rec_id = "000000006";
  expected_cred.username = "";
  expected_cred.email = "person6@yahoo.com";
  expected_cred.hash = "DGM2c/HbXTIkDDM5y6e6/lQ==";
  expected_cred.hint = "same";

  EXPECT_TRUE(CredentialReader::ParseLine(line, &actual_cred))
    << "Failed to Parse Line: " << line;
  EXPECT_TRUE ( expected_cred == actual_cred ) 
    << "Expected Cred:\n" << expected_cred
    << "**********\nBut Got:\n" << actual_cred;
}

TEST(Alec, TestLevelDB) {
  EXPECT_TRUE(1 == 2) << "ahh";
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
