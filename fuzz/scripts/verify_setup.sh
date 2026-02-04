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
# Verification script for fuzzing infrastructure
#
# This script verifies that the fuzzing setup is working correctly
# by performing a series of checks and short fuzzing runs.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FUZZ_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$FUZZ_DIR")"
NATIVE_DIR="$REPO_ROOT/tomcat-native/native"

echo "========================================="
echo "Fuzzing Infrastructure Verification"
echo "========================================="
echo

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() {
    echo -e "${GREEN}✓${NC} $1"
}

fail() {
    echo -e "${RED}✗${NC} $1"
    exit 1
}

warn() {
    echo -e "${YELLOW}!${NC} $1"
}

info() {
    echo "  $1"
}

#
# Step 1: Check prerequisites
#
echo "Step 1: Checking prerequisites..."
echo

# Check for clang
if command -v clang &> /dev/null; then
    CLANG_VERSION=$(clang --version | head -1)
    pass "clang found: $CLANG_VERSION"
else
    fail "clang not found - required for fuzzing builds"
fi

# Check for OpenSSL
if command -v openssl &> /dev/null; then
    OPENSSL_VERSION=$(openssl version)
    pass "OpenSSL found: $OPENSSL_VERSION"
else
    warn "openssl command not found - corpus generation may fail"
fi

# Check for APR
if pkg-config --exists apr-1 2>/dev/null; then
    APR_VERSION=$(pkg-config --modversion apr-1)
    pass "APR found: $APR_VERSION"
elif [ -f "/usr/lib64/libapr-1.so" ] || [ -f "/usr/lib/x86_64-linux-gnu/libapr-1.so" ]; then
    pass "APR library found (package config missing)"
else
    warn "APR not found - build may fail"
fi

echo

#
# Step 2: Check build configuration
#
echo "Step 2: Checking build configuration..."
echo

cd "$NATIVE_DIR" 2>/dev/null

if [ ! -f "configure" ]; then
    fail "configure script not found - run ./buildconf first"
fi

if [ ! -f "Makefile" ]; then
    warn "Makefile not found - native library not configured yet"
    info "Run: ./configure --enable-fuzzing --with-apr=/usr --with-ssl=/usr CC=clang"
else
    if grep -q "\-fsanitize=fuzzer" "Makefile"; then
        pass "Fuzzing enabled in Makefile"
    else
        warn "Fuzzing not enabled in Makefile"
        info "Reconfigure with: ./configure --enable-fuzzing --with-apr=/usr --with-ssl=/usr CC=clang"
    fi
fi

echo

#
# Step 3: Check fuzz harnesses
#
echo "Step 3: Checking fuzz harness source files..."
echo

FUZZERS="fuzz_sni_parsing fuzz_pkcs12 fuzz_bio_operations fuzz_handshake"

for fuzzer in $FUZZERS; do
    if [ -f "$FUZZ_DIR/harnesses/${fuzzer}.c" ]; then
        pass "${fuzzer}.c exists"
    else
        fail "${fuzzer}.c not found"
    fi
done

echo

#
# Step 4: Check corpus and dictionary
#
echo "Step 4: Checking corpus and dictionary..."
echo

if [ -f "$FUZZ_DIR/dict/tls.dict" ]; then
    pass "TLS dictionary exists"
else
    fail "TLS dictionary not found"
fi

for corpus in sni pkcs12 bio handshake; do
    if [ -d "$FUZZ_DIR/corpus/$corpus" ]; then
        pass "Corpus directory: corpus/$corpus/"
        file_count=$(find "$FUZZ_DIR/corpus/$corpus" -type f | wc -l)
        if [ "$file_count" -gt 0 ]; then
            info "$file_count seed files"
        else
            warn "Empty corpus - run ./generate_corpus.sh"
        fi
    else
        warn "Corpus directory missing: corpus/$corpus/"
    fi
done

echo

#
# Step 5: Try building fuzzers
#
echo "Step 5: Building fuzz harnesses..."
echo

if [ -x "$SCRIPT_DIR/build_fuzzers.sh" ]; then
    pass "build_fuzzers.sh is executable"

    info "Running build_fuzzers.sh..."
    if "$SCRIPT_DIR/build_fuzzers.sh" 2>&1 | tee /tmp/build_fuzzers.log; then
        pass "Fuzzers built successfully"
    else
        fail "Fuzzer build failed - see /tmp/build_fuzzers.log"
    fi
else
    warn "build_fuzzers.sh not executable"
    chmod +x "$SCRIPT_DIR/build_fuzzers.sh"
fi

echo

#
# Step 6: Verify fuzzer binaries
#
echo "Step 6: Verifying fuzzer binaries..."
echo

for fuzzer in $FUZZERS; do
    if [ -x "$SCRIPT_DIR/$fuzzer" ]; then
        pass "$fuzzer binary exists and is executable"

        # Check if it's actually a fuzzer
        if "$SCRIPT_DIR/$fuzzer" -help=1 2>&1 | grep -q "libFuzzer"; then
            info "libFuzzer confirmed"
        else
            warn "$fuzzer may not be a valid libFuzzer binary"
        fi
    else
        warn "$fuzzer binary not found or not executable"
    fi
done

echo

#
# Step 7: Test ASAN detection (intentional bug)
#
echo "Step 7: Testing AddressSanitizer detection..."
echo

info "Creating test fuzzer with intentional buffer overflow..."
cat > /tmp/test_asan.c << 'EOF'
#include <stdint.h>
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0) {
        char *buf = malloc(1);
        buf[10] = data[0];  // Intentional buffer overflow
        free(buf);
    }
    return 0;
}
EOF

if clang -fsanitize=fuzzer,address /tmp/test_asan.c -o /tmp/test_asan 2>/dev/null; then
    if timeout 5 /tmp/test_asan 2>&1 | grep -q "heap-buffer-overflow"; then
        pass "AddressSanitizer is working (detected intentional bug)"
    else
        warn "AddressSanitizer may not be working correctly"
    fi
    rm -f /tmp/test_asan /tmp/test_asan.c
else
    warn "Could not build ASAN test"
fi

echo

#
# Step 8: Short fuzzing run
#
echo "Step 8: Running short fuzzing campaign (10 seconds each)..."
echo

if [ ! -x "$SCRIPT_DIR/fuzz_sni_parsing" ]; then
    warn "Skipping fuzzing test - binaries not built"
else
    for fuzzer in $FUZZERS; do
        fuzzer_path="$SCRIPT_DIR/$fuzzer"
        # Map fuzzer names to corpus directories
        case "$fuzzer" in
            fuzz_sni_parsing) corpus_name="sni" ;;
            fuzz_pkcs12) corpus_name="pkcs12" ;;
            fuzz_bio_operations) corpus_name="bio" ;;
            fuzz_handshake) corpus_name="handshake" ;;
            *) corpus_name=${fuzzer#fuzz_} ;;
        esac
        corpus_path="$FUZZ_DIR/corpus/$corpus_name"

        if [ -x "$fuzzer_path" ]; then
            info "Running $fuzzer for 10 seconds..."

            mkdir -p /tmp/fuzz_test_$$
            timeout 10 "$fuzzer_path" \
                -max_total_time=10 \
                -timeout=5 \
                -dict="$FUZZ_DIR/dict/tls.dict" \
                /tmp/fuzz_test_$$ \
                "$corpus_path" 2>&1 | tail -5 || true

            if [ -d /tmp/fuzz_test_$$ ]; then
                new_files=$(find /tmp/fuzz_test_$$ -type f | wc -l)
                if [ "$new_files" -gt 0 ]; then
                    pass "$fuzzer executed successfully ($new_files new inputs)"
                else
                    info "$fuzzer executed (no new coverage)"
                fi
                rm -rf /tmp/fuzz_test_$$
            fi
        fi
    done
fi

echo

#
# Step 9: Check OSS-Fuzz integration files
#
echo "Step 9: Checking OSS-Fuzz integration..."
echo

if [ -f "$FUZZ_DIR/oss-fuzz/project.yaml" ]; then
    pass "OSS-Fuzz project.yaml exists"
else
    fail "OSS-Fuzz project.yaml not found"
fi

if [ -f "$FUZZ_DIR/oss-fuzz/Dockerfile" ]; then
    pass "OSS-Fuzz Dockerfile exists"
else
    fail "OSS-Fuzz Dockerfile not found"
fi

if [ -f "$FUZZ_DIR/oss-fuzz/build.sh" ]; then
    pass "OSS-Fuzz build.sh exists"
    if [ -x "$FUZZ_DIR/oss-fuzz/build.sh" ]; then
        info "build.sh is executable"
    else
        warn "build.sh is not executable"
    fi
else
    fail "OSS-Fuzz build.sh not found"
fi

echo

#
# Summary
#
echo "========================================="
echo "Verification Complete!"
echo "========================================="
echo
echo "Next steps:"
echo "  1. Generate seed corpus: ./generate_corpus.sh"
echo "  2. Run short test: ./fuzz_sni_parsing -max_total_time=60 corpus/sni/"
echo "  3. Run full campaign: ./run_fuzzers.sh 3600"
echo "  4. Submit to OSS-Fuzz: Create PR to google/oss-fuzz"
echo
