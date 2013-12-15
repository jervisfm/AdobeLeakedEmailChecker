Adobe Leaked Email Checker
==========================


# Introduction
There was a recent data leak of the user credentials from Adobe. This leak is notable because it contained
a lot credentials in the range of 150 million records.

The goal of this program is to let you manually check this dump to see if this your email address was compromised
in this leak. Of course, there are currently website that offer this functionality, and that is fine as long as you trust them 
enough to give them your email address. 

The prime motivation in embarking in this endeavor was both pedagogical in terms of learning to dealing with big data dumps and also
provide an independent / manual method to check if your email was compromised.

# Data Sources:
* http://stricture-group.com/files/not-adobe.7z (linked from http://www.troyhunt.com/2013/11/using-high-spec-azure-sql-server-for.html)

# Dependencies
* Repobuild - https://github.com/chrisvana/repobuild. This is an excellent package from Chris that helps with re-using opensource code. 
Do note that this is optional; the project should be buildable from the included/generated makefile. However, significant changes are to 
be made to the code, then it is you'd need a copy of repobuild to regenerate the make file. 




