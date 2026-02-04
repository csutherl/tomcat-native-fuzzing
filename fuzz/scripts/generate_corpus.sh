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
# Generate seed corpus for fuzzing
#
# This script creates initial corpus files for each fuzzer
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FUZZ_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$FUZZ_DIR")"
NATIVE_DIR="$REPO_ROOT/tomcat-native/native"
CORPUS_DIR="$SCRIPT_DIR/corpus"

echo "Generating seed corpus..."
echo

# Create temporary directory for OpenSSL operations
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

cd "$TEMP_DIR"

#
# 1. Generate PKCS12 files
#
echo "Generating PKCS12 corpus..."

# Generate various certificate types
generate_pkcs12() {
    local name=$1
    local keysize=$2
    local days=$3
    local password=$4

    openssl req -x509 -newkey rsa:$keysize \
        -keyout key_$name.pem -out cert_$name.pem \
        -days $days -nodes -subj "/C=US/O=Test/CN=$name" 2>/dev/null

    if [ -z "$password" ]; then
        openssl pkcs12 -export -out test_$name.p12 \
            -inkey key_$name.pem -in cert_$name.pem -passout pass: 2>/dev/null
    else
        openssl pkcs12 -export -out test_$name.p12 \
            -inkey key_$name.pem -in cert_$name.pem -passout "pass:$password" 2>/dev/null
    fi

    cp test_$name.p12 "$CORPUS_DIR/pkcs12/"
    echo "  Created pkcs12/$name.p12"
}

# Generate various PKCS12 files
generate_pkcs12 "rsa2048_nopass" 2048 365 ""
generate_pkcs12 "rsa2048_withpass" 2048 365 "password"
generate_pkcs12 "rsa1024" 1024 1 ""
generate_pkcs12 "rsa4096" 4096 7300 "secretkey"

# Create an EC-based PKCS12
openssl ecparam -genkey -name prime256v1 -out ec_key.pem 2>/dev/null
openssl req -new -x509 -key ec_key.pem -out ec_cert.pem \
    -days 365 -subj "/C=US/O=Test/CN=ec_test" 2>/dev/null
openssl pkcs12 -export -out test_ec.p12 \
    -inkey ec_key.pem -in ec_cert.pem -passout pass: 2>/dev/null
cp test_ec.p12 "$CORPUS_DIR/pkcs12/ec.p12"
echo "  Created pkcs12/ec.p12"

echo

#
# 2. Generate TLS handshake captures (SNI and handshake corpus)
#
echo "Generating TLS handshake corpus..."

# Start a temporary OpenSSL server
openssl req -x509 -newkey rsa:2048 -keyout server_key.pem \
    -out server_cert.pem -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

# Start server in background
openssl s_server -key server_key.pem -cert server_cert.pem \
    -accept 14433 -www > /dev/null 2>&1 &
SERVER_PID=$!

# Give server time to start
sleep 2

# Capture various TLS handshakes
capture_handshake() {
    local name=$1
    local opts=$2

    # Use OpenSSL client to generate handshake
    timeout 5 openssl s_client -connect localhost:14433 \
        $opts -msg < /dev/null 2>&1 | \
        grep -A 100 "ClientHello" | head -200 > "handshake_$name.txt" || true

    # Extract hex bytes if available
    if [ -s "handshake_$name.txt" ]; then
        # This is a simplified extraction - real handshake data would need pcap
        echo "  Generated handshake_$name (placeholder)"
    fi
}

# Different TLS versions and cipher suites
capture_handshake "tls12" "-tls1_2"
capture_handshake "tls13" "-tls1_3"
capture_handshake "sni_localhost" "-servername localhost"
capture_handshake "sni_example" "-servername example.com"

# Kill server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

# Create minimal ClientHello messages manually
echo "Generating minimal TLS ClientHello messages..."

# Minimal TLS 1.2 ClientHello
python3 -c '
import struct
# TLS 1.2 ClientHello with SNI for "localhost"
client_hello = bytes([
    0x16, 0x03, 0x01,                    # Record: Handshake, TLS 1.0 (compat)
    0x00, 0x5f,                          # Length: 95 bytes
    0x01,                                # Handshake type: ClientHello
    0x00, 0x00, 0x5b,                    # Handshake length: 91 bytes
    0x03, 0x03,                          # Version: TLS 1.2
]) + bytes(32) + bytes([                 # Random: 32 zero bytes
    0x00,                                # Session ID length: 0
    0x00, 0x02,                          # Cipher suites length: 2
    0xc0, 0x2f,                          # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0x01, 0x00,                          # Compression: null
    0x00, 0x30,                          # Extensions length: 48 bytes
    0x00, 0x00,                          # Extension: SNI
    0x00, 0x0e,                          # SNI extension length: 14
    0x00, 0x0c,                          # Server name list length: 12
    0x00,                                # Name type: hostname
    0x00, 0x09,                          # Hostname length: 9
]) + b"localhost"

with open("'"$CORPUS_DIR/sni/clienthello_localhost.bin"'", "wb") as f:
    f.write(client_hello)
' 2>/dev/null && echo "  Created sni/clienthello_localhost.bin" || true

# Minimal TLS 1.3 ClientHello
python3 -c '
# TLS 1.3 ClientHello with SNI for "example.com"
client_hello = bytes([
    0x16, 0x03, 0x01,                    # Record: Handshake, TLS 1.0 (compat)
    0x00, 0x63,                          # Length: 99 bytes
    0x01,                                # Handshake type: ClientHello
    0x00, 0x00, 0x5f,                    # Handshake length: 95 bytes
    0x03, 0x03,                          # Version: TLS 1.2 (compat)
]) + bytes(32) + bytes([                 # Random: 32 zero bytes
    0x00,                                # Session ID length: 0
    0x00, 0x02,                          # Cipher suites length: 2
    0x13, 0x01,                          # TLS_AES_128_GCM_SHA256
    0x01, 0x00,                          # Compression: null
    0x00, 0x34,                          # Extensions length: 52 bytes
    0x00, 0x00,                          # Extension: SNI
    0x00, 0x12,                          # SNI extension length: 18
    0x00, 0x10,                          # Server name list length: 16
    0x00,                                # Name type: hostname
    0x00, 0x0d,                          # Hostname length: 13
]) + b"example.com" + bytes([
    0x00, 0x2b,                          # Extension: supported_versions
    0x00, 0x03,                          # Length: 3
    0x02,                                # Versions length: 2
    0x03, 0x04,                          # TLS 1.3
])

with open("'"$CORPUS_DIR/sni/clienthello_example.bin"'", "wb") as f:
    f.write(client_hello)
' 2>/dev/null && echo "  Created sni/clienthello_example.bin" || true

# Copy SNI corpus to handshake corpus
cp "$CORPUS_DIR/sni"/*.bin "$CORPUS_DIR/handshake/" 2>/dev/null || true

echo

#
# 3. Generate BIO operation test data
#
echo "Generating BIO operations corpus..."

# Create various TLS record types
python3 -c '
# Application data record
app_data = bytes([
    0x17, 0x03, 0x03,     # Type: Application data, TLS 1.2
    0x00, 0x10,           # Length: 16 bytes
]) + b"test data here!!"

with open("'"$CORPUS_DIR/bio/app_data.bin"'", "wb") as f:
    f.write(app_data)

# Alert record
alert = bytes([
    0x15, 0x03, 0x03,     # Type: Alert, TLS 1.2
    0x00, 0x02,           # Length: 2 bytes
    0x02, 0x50,           # Fatal: Protocol version
])

with open("'"$CORPUS_DIR/bio/alert.bin"'", "wb") as f:
    f.write(alert)

# Change cipher spec
ccs = bytes([
    0x14, 0x03, 0x03,     # Type: Change Cipher Spec, TLS 1.2
    0x00, 0x01,           # Length: 1 byte
    0x01,                 # CCS message
])

with open("'"$CORPUS_DIR/bio/change_cipher_spec.bin"'", "wb") as f:
    f.write(ccs)
' 2>/dev/null && echo "  Created BIO corpus files" || true

# Copy ClientHello messages to BIO corpus too
cp "$CORPUS_DIR/sni"/*.bin "$CORPUS_DIR/bio/" 2>/dev/null || true

echo
echo "Corpus generation complete!"
echo
echo "Corpus statistics:"
find "$CORPUS_DIR" -type f -exec echo -n "  {} " \; -exec wc -c {} \; | awk '{print $1, $2, "bytes"}'
echo
echo "Total files: $(find "$CORPUS_DIR" -type f | wc -l)"
