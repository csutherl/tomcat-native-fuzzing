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
# Script to run all fuzzers
#
# Usage:
#   ./run_fuzzers.sh [duration_seconds] [jobs] [--no-save]
#
# Examples:
#   ./run_fuzzers.sh                  # Run for 3600s (1 hour) with 4 jobs, save to corpus-generated/
#   ./run_fuzzers.sh 60               # Run for 60s with 4 jobs
#   ./run_fuzzers.sh 3600 8           # Run for 1 hour with 8 jobs
#   ./run_fuzzers.sh 60 4 --no-save   # Run for 60s without saving corpus (ephemeral)
#

# Parse arguments
DURATION=3600
JOBS=4
SAVE_CORPUS=true

for arg in "$@"; do
    if [ "$arg" = "--no-save" ] || [ "$arg" = "--ephemeral" ]; then
        SAVE_CORPUS=false
    elif [ -z "$DURATION_SET" ]; then
        DURATION=$arg
        DURATION_SET=true
    elif [ -z "$JOBS_SET" ]; then
        JOBS=$arg
        JOBS_SET=true
    fi
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FUZZ_DIR="$(dirname "$SCRIPT_DIR")"

# Check if fuzzers exist
if [ ! -f "$SCRIPT_DIR/fuzz_sni_parsing" ]; then
    echo "Error: Fuzzers not built. Please run ./build_fuzzers.sh first" >&2
    exit 1
fi

# Setup corpus directories
if [ "$SAVE_CORPUS" = true ]; then
    CORPUS_OUTPUT_DIR="$FUZZ_DIR/corpus-generated"
    mkdir -p "$CORPUS_OUTPUT_DIR"/{sni,pkcs12,bio,handshake}
    echo "Running all fuzzers for $DURATION seconds with $JOBS parallel jobs each..."
    echo "  - Seed corpus: $FUZZ_DIR/corpus/"
    echo "  - Generated corpus: $CORPUS_OUTPUT_DIR/"
else
    CORPUS_OUTPUT_DIR=$(mktemp -d)
    mkdir -p "$CORPUS_OUTPUT_DIR"/{sni,pkcs12,bio,handshake}
    trap "rm -rf $CORPUS_OUTPUT_DIR" EXIT
    echo "Running all fuzzers for $DURATION seconds with $JOBS parallel jobs each (ephemeral mode)..."
    echo "  - Seed corpus: $FUZZ_DIR/corpus/"
    echo "  - Generated corpus: [temporary, will be discarded]"
fi
echo

# Run fuzzers in parallel
run_fuzzer() {
    local fuzzer=$1
    local seed_corpus=$2
    local output_corpus=$3
    local name=$(basename "$fuzzer")

    echo "Starting $name..."

    # Run fuzzer with both seed and output corpus
    # LibFuzzer will read from both directories and write new findings to the first one
    # Note: cd to logs directory so libFuzzer's fuzz-N.log files are written there
    (
        cd "$FUZZ_DIR/logs" || exit 1
        ASAN_OPTIONS=detect_leaks=1:symbolize=1 \
        UBSAN_OPTIONS=print_stacktrace=1:symbolize=1 \
            "$fuzzer" \
            -max_total_time="$DURATION" \
            -timeout=30 \
            -rss_limit_mb=4096 \
            -jobs="$JOBS" \
            -workers="$JOBS" \
            -dict="$FUZZ_DIR/dict/tls.dict" \
            -artifact_prefix="$FUZZ_DIR/crashes/" \
            -print_final_stats=1 \
            "$output_corpus" \
            "$seed_corpus" \
            > "$name.log" 2>&1
    )

    echo "$name completed (exit code: $?)"
}

# Function to display summary statistics
show_summary() {
    local interrupted=$1

    echo
    if [ "$interrupted" = "true" ]; then
        echo "========================================="
        echo "Fuzzing interrupted by user"
        echo "========================================="
    else
        echo "========================================="
        echo "All fuzzers completed!"
        echo "========================================="
    fi
    echo

    # Parse and display human-readable summary
    echo "SUMMARY"
    echo "-------"
    echo
    for fuzzer in fuzz_sni_parsing fuzz_pkcs12 fuzz_bio_operations fuzz_handshake; do
        log="$FUZZ_DIR/logs/$fuzzer.log"
        if [ -f "$log" ]; then
            # Format fuzzer name nicely
            display_name=$(echo "$fuzzer" | sed 's/fuzz_//' | sed 's/_/ /g' | awk '{for(i=1;i<=NF;i++)sub(/./,toupper(substr($i,1,1)),$i)}1')
            echo "[$display_name]"

            # Get final stats (last occurrence)
            total_execs=$(grep "stat::number_of_executed_units:" "$log" | tail -1 | awk '{print $2}')
            exec_per_sec=$(grep "stat::average_exec_per_sec:" "$log" | tail -1 | awk '{print $2}')
            new_units=$(grep "stat::new_units_added:" "$log" | tail -1 | awk '{print $2}')
            peak_rss=$(grep "stat::peak_rss_mb:" "$log" | tail -1 | awk '{print $2}')

            # Get coverage info from final stats line
            final_cov=$(grep "DONE" "$log" | tail -1 | grep -o "cov: [0-9]*" | awk '{print $2}')
            final_corp=$(grep "DONE" "$log" | tail -1 | grep -o "corp: [0-9]*/[0-9]*b" | awk '{print $2}')

            if [ -n "$total_execs" ]; then
                printf "  Total executions:     %'d\n" "$total_execs" 2>/dev/null || printf "  Total executions:     %s\n" "$total_execs"
                printf "  Execution rate:       %'d exec/sec\n" "$exec_per_sec" 2>/dev/null || printf "  Execution rate:       %s exec/sec\n" "$exec_per_sec"
                printf "  New corpus entries:   %s\n" "$new_units"
                [ -n "$final_cov" ] && printf "  Final coverage:       %s edges\n" "$final_cov"
                [ -n "$final_corp" ] && printf "  Final corpus size:    %s\n" "$final_corp"
                printf "  Peak memory usage:    %s MB\n" "$peak_rss"
            else
                echo "  No statistics available"
            fi
            echo
        fi
    done

    # Check for crashes
    echo "CRASHES"
    echo "-------"
    if [ -d "$FUZZ_DIR/crashes" ] && [ "$(ls -A "$FUZZ_DIR/crashes" 2>/dev/null)" ]; then
        echo "⚠️  CRASHES FOUND:"
        for crash in "$FUZZ_DIR/crashes"/*; do
            if [ -f "$crash" ]; then
                crash_size=$(stat -c%s "$crash" 2>/dev/null || stat -f%z "$crash" 2>/dev/null)
                echo "  - $(basename "$crash") (${crash_size} bytes)"
            fi
        done
    else
        echo "✓ No crashes found"
    fi
    echo

    # Show corpus growth
    echo "CORPUS GROWTH"
    echo "-------------"
    for corpus_name in sni pkcs12 bio handshake; do
        seed_dir="$FUZZ_DIR/corpus/$corpus_name"
        gen_dir="$CORPUS_OUTPUT_DIR/$corpus_name"

        seed_count=$(find "$seed_dir" -type f 2>/dev/null | wc -l)
        gen_count=$(find "$gen_dir" -type f 2>/dev/null | wc -l)
        gen_size=$(du -sh "$gen_dir" 2>/dev/null | awk '{print $1}')

        printf "  %-12s seed: %3d files  |  generated: %3d files (%s)\n" \
               "$corpus_name:" "$seed_count" "$gen_count" "$gen_size"
    done
    echo

    if [ "$SAVE_CORPUS" = true ]; then
        echo "Generated corpus saved to: $CORPUS_OUTPUT_DIR/"
        echo "To merge interesting findings into seed corpus: ./merge_corpus.sh"
    else
        echo "Generated corpus discarded (ephemeral mode)"
    fi
    echo "Logs saved in: $FUZZ_DIR/logs/"
}

# Signal handler for Ctrl-C
cleanup_and_exit() {
    echo
    echo "Stopping fuzzers..."

    # Kill all background fuzzer processes
    kill $PID_SNI $PID_PKCS12 $PID_BIO $PID_HANDSHAKE 2>/dev/null

    # Wait a moment for them to exit
    sleep 2

    # Show summary with interrupted flag
    show_summary true

    exit 130
}

# Set up signal trap
trap cleanup_and_exit SIGINT SIGTERM

# Create crashes directory
mkdir -p "$FUZZ_DIR/logs"
mkdir -p "$FUZZ_DIR/crashes"

# Launch all fuzzers in background
run_fuzzer "$SCRIPT_DIR/fuzz_sni_parsing" "$FUZZ_DIR/corpus/sni" "$CORPUS_OUTPUT_DIR/sni" &
PID_SNI=$!

run_fuzzer "$SCRIPT_DIR/fuzz_pkcs12" "$FUZZ_DIR/corpus/pkcs12" "$CORPUS_OUTPUT_DIR/pkcs12" &
PID_PKCS12=$!

run_fuzzer "$SCRIPT_DIR/fuzz_bio_operations" "$FUZZ_DIR/corpus/bio" "$CORPUS_OUTPUT_DIR/bio" &
PID_BIO=$!

run_fuzzer "$SCRIPT_DIR/fuzz_handshake" "$FUZZ_DIR/corpus/handshake" "$CORPUS_OUTPUT_DIR/handshake" &
PID_HANDSHAKE=$!

echo
echo "All fuzzers started. PIDs: $PID_SNI $PID_PKCS12 $PID_BIO $PID_HANDSHAKE"
echo "Logs: $FUZZ_DIR/logs/"
echo "Crashes: $FUZZ_DIR/crashes/"
echo
echo "To stop all fuzzers: pkill -P $$"
echo
echo "========================================="
echo "Fuzzing in progress..."
echo "========================================="
echo

# Wait for all fuzzers to complete
wait $PID_SNI $PID_PKCS12 $PID_BIO $PID_HANDSHAKE

# Show summary
show_summary false
