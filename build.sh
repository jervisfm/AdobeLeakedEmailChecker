#!/bin/bash

# Stop on first error
set -e

# Builds main program binary
repobuild ":alec_main" && make -j 8
