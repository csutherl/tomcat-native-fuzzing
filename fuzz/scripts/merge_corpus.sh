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
# Script to merge generated corpus into seed corpus
#
# This script uses libFuzzer's merge feature to add only the most interesting
# test cases from corpus-generated/ to the seed corpus, eliminating duplicates
# and redundant cases.
#
# Usage:
#   ./merge_corpus.sh [fuzzer_name]
#
# Examples:
#   ./merge_corpus.sh              # Merge all fuzzers
#   ./merge_corpus.sh sni          # Merge only SNI corpus
#   ./merge_corpus.sh handshake    # Merge only handshake corpus
#

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FUZZ_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$FUZZ_DIR")"
NATIVE_DIR="$REPO_ROOT/tomcat-native/native"

# Check if corpus-generated exists
if [ ! -d "$SCRIPT_DIR/corpus-generated" ]; then
    echo "Error: corpus-generated/ directory not found"
    echo "Run ./run_fuzzers.sh first to generate new corpus entries"
    exit 1
fi

# Determine which corpus to merge
if [ -n "$1" ]; then
    TARGETS="$1"
else
    TARGETS="sni pkcs12 bio handshake"
fi

echo "========================================="
echo "Corpus Merge Tool"
echo "========================================="
echo
echo "This tool merges auto-generated corpus into the seed corpus,"
echo "keeping only unique, interesting test cases."
echo

# Map short names to fuzzer binaries
get_fuzzer_name() {
    case "$1" in
        sni) echo "fuzz_sni_parsing" ;;
        pkcs12) echo "fuzz_pkcs12" ;;
        bio) echo "fuzz_bio_operations" ;;
        handshake) echo "fuzz_handshake" ;;
        *) echo "" ;;
    esac
}

for target in $TARGETS; do
    fuzzer=$(get_fuzzer_name "$target")

    if [ -z "$fuzzer" ]; then
        echo "Error: Unknown fuzzer target '$target'"
        echo "Valid targets: sni, pkcs12, bio, handshake"
        continue
    fi

    if [ ! -f "$SCRIPT_DIR/$fuzzer" ]; then
        echo "Error: Fuzzer binary '$fuzzer' not found. Run ./build_fuzzers.sh first"
        continue
    fi

    seed_corpus="$SCRIPT_DIR/corpus/$target"
    generated_corpus="$SCRIPT_DIR/corpus-generated/$target"

    if [ ! -d "$generated_corpus" ] || [ -z "$(ls -A "$generated_corpus" 2>/dev/null)" ]; then
        echo "[$target] No generated corpus to merge (directory empty or missing)"
        echo
        continue
    fi

    # Count files before merge
    seed_before=$(find "$seed_corpus" -type f 2>/dev/null | wc -l)
    gen_count=$(find "$generated_corpus" -type f 2>/dev/null | wc -l)

    echo "[$target]"
    echo "  Seed corpus:      $seed_before files"
    echo "  Generated corpus: $gen_count files"
    echo "  Merging..."

    # Create temporary directory for merge output
    temp_merged=$(mktemp -d)

    # Use libFuzzer's merge feature:
    # - Reads from both seed_corpus and generated_corpus
    # - Writes minimal set of interesting inputs to temp_merged
    # - Eliminates redundant cases
    "$SCRIPT_DIR/$fuzzer" -merge=1 "$temp_merged" "$seed_corpus" "$generated_corpus" \
        > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "  ⚠️  Merge failed for $target"
        rm -rf "$temp_merged"
        echo
        continue
    fi

    # Count merged results
    merged_count=$(find "$temp_merged" -type f 2>/dev/null | wc -l)
    new_count=$((merged_count - seed_before))

    if [ $new_count -gt 0 ]; then
        # Copy new files from temp_merged to seed_corpus
        # (Files that weren't in seed_corpus originally)
        for file in "$temp_merged"/*; do
            if [ -f "$file" ]; then
                filename=$(basename "$file")
                if [ ! -f "$seed_corpus/$filename" ]; then
                    cp "$file" "$seed_corpus/"
                fi
            fi
        done

        echo "  ✓ Added $new_count new interesting cases to seed corpus"
    else
        echo "  ✓ No new interesting cases found (generated corpus was redundant)"
    fi

    # Clean up
    rm -rf "$temp_merged"

    # Count files after merge
    seed_after=$(find "$seed_corpus" -type f 2>/dev/null | wc -l)
    echo "  Final seed corpus: $seed_after files"
    echo
done

echo "========================================="
echo "Merge complete!"
echo "========================================="
echo
echo "Next steps:"
echo "  1. Review new files in corpus/ directories"
echo "  2. Test that they work: ./fuzz_sni_parsing corpus/sni/"
echo "  3. Commit interesting cases to version control"
echo "  4. Optionally clean up: rm -rf corpus-generated/"
echo
