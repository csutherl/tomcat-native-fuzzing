#!/bin/bash -eu
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Build script for OSS-Fuzz integration

cd $SRC/tomcat-native/native

# Build the native library with fuzzing enabled
./buildconf --with-apr=/usr
./configure \
    --with-apr=/usr \
    --with-ssl=$WORK/openssl \
    --enable-fuzzing \
    CC="$CC" \
    CFLAGS="$CFLAGS" \
    LDFLAGS="$LDFLAGS"

make

# Compile fuzz targets
FUZZ_DIR="$SRC/tomcat-native/native/fuzz"

for fuzzer in fuzz_sni_parsing fuzz_pkcs12 fuzz_bio_operations fuzz_handshake; do
    echo "Building $fuzzer..."

    $CC $CFLAGS $LIB_FUZZING_ENGINE \
        "$FUZZ_DIR/${fuzzer}.c" \
        -I./include \
        -I/usr/include/apr-1 \
        -I/usr/include/apr-2 \
        -lssl -lcrypto -lapr-1 -lpthread -ldl \
        -o "$OUT/${fuzzer}"

    # Package corpus if it exists
    if [ -d "$FUZZ_DIR/corpus/${fuzzer#fuzz_}" ]; then
        zip -j "$OUT/${fuzzer}_seed_corpus.zip" \
            "$FUZZ_DIR/corpus/${fuzzer#fuzz_}"/* || true
    fi
done

# Copy dictionary
if [ -f "$FUZZ_DIR/dict/tls.dict" ]; then
    cp "$FUZZ_DIR/dict/tls.dict" "$OUT/"
fi

echo "OSS-Fuzz build complete!"
