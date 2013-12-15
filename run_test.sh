#!/bin/bash

# Stop on first error
set -e

# Build and Run Tests
repobuild ":alec_test" && make -j 8 && ./alec_test
