[

{ "cc_library": {
  "name": "alec",
  "cc_sources": [ "alec.cc" ],
  "cc_headers": [ "alec.h" ], 
  "dependencies": [ "//common/base:flags",
  		    "//common/base:init", 
		    "//common/log:log",
		    "//common/strings:stringpiece" ]
  }
},

{ "cc_binary": {
  "name": "alec_main",
  "cc_sources": [ "alec_main.cc" ],
  "dependencies": [ ":alec" ]
  }
},

{ "cc_test": {
  "name": "alec_test",
  "cc_sources": [ "alec_test.cc" ],
  "dependencies": [ ":alec",
  		    "//common/test:test" ]
  }
}

]