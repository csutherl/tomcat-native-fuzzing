#!/bin/bash
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Build script for fuzzing harnesses
#
# This script compiles the libFuzzer-based fuzz targets for tomcat-native.
# It must be run after the main library has been configured with --enable-fuzzing.
#
# Usage:
#   ./build_fuzzers.sh
#

set -e

# Determine paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FUZZ_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$FUZZ_DIR")"
NATIVE_DIR="$REPO_ROOT/tomcat-native/native"

# Check if submodule exists
if [ ! -d "$NATIVE_DIR" ]; then
    echo "Error: tomcat-native submodule not found at $NATIVE_DIR" >&2
    echo "Please run:" >&2
    echo "  cd $REPO_ROOT" >&2
    echo "  git submodule update --init --recursive" >&2
    echo "  ./setup.sh" >&2
    exit 1
fi

# Check if native library is built
if [ ! -f "$NATIVE_DIR/.libs/libtcnative-2.so" ] && [ ! -f "$NATIVE_DIR/.libs/libtcnative-2.dylib" ]; then
    echo "Error: Native library not built" >&2
    echo "Please run:" >&2
    echo "  cd $REPO_ROOT" >&2
    echo "  ./setup.sh" >&2
    exit 1
fi

# Extract compiler and flags from parent Makefile
CC="${CC:-clang}"
APR_DIR="${APR_DIR:-/usr}"
SSL_DIR="${SSL_DIR:-/usr}"

# Fuzzer-specific flags
FUZZ_CFLAGS="-fsanitize=fuzzer,address,undefined -g -O1"
FUZZ_CFLAGS="$FUZZ_CFLAGS -I$NATIVE_DIR/include"
FUZZ_CFLAGS="$FUZZ_CFLAGS -I$APR_DIR/include/apr-1"
FUZZ_CFLAGS="$FUZZ_CFLAGS -I$APR_DIR/include/apr-2"
FUZZ_CFLAGS="$FUZZ_CFLAGS -I/usr/include/apr-1"
FUZZ_CFLAGS="$FUZZ_CFLAGS -I/usr/include/apr-2"

FUZZ_LDFLAGS="-fsanitize=fuzzer,address,undefined"
FUZZ_LIBS="-lssl -lcrypto -lapr-1 -lpthread -ldl"

# Check if APR library exists
if [ ! -f "$APR_DIR/lib/libapr-1.a" ] && [ ! -f "/usr/lib64/libapr-1.so" ] && [ ! -f "/usr/lib/x86_64-linux-gnu/libapr-1.so" ]; then
    echo "Warning: APR library not found, build may fail"
fi

echo "Building fuzz targets..."
echo "CC=$CC"
echo "APR_DIR=$APR_DIR"
echo "SSL_DIR=$SSL_DIR"
echo

# Build each fuzzer
for fuzzer_src in "$FUZZ_DIR/harnesses"/fuzz_*.c; do
    fuzzer_name=$(basename "$fuzzer_src" .c)
    echo "Building $fuzzer_name..."

    $CC $FUZZ_CFLAGS $FUZZ_LDFLAGS \
        -o "$SCRIPT_DIR/$fuzzer_name" \
        "$fuzzer_src" \
        $FUZZ_LIBS

    if [ $? -eq 0 ]; then
        echo "  ✓ $fuzzer_name built successfully"
    else
        echo "  ✗ Failed to build $fuzzer_name" >&2
        exit 1
    fi
done

echo
echo "All fuzz targets built successfully!"
echo
echo "To run a fuzzer:"
echo "  cd $SCRIPT_DIR"
echo "  ./fuzz_sni_parsing -max_total_time=60 -dict=../dict/tls.dict ../corpus/sni/"
echo
echo "To run all fuzzers in parallel:"
echo "  ./run_fuzzers.sh"
