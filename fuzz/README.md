# Fuzzing Infrastructure

Comprehensive fuzzing setup for Apache Tomcat Native Library.

## Fuzz Targets

### 1. SNI Parsing (`fuzz_sni_parsing`)
Tests SNI (Server Name Indication) extension parsing in TLS handshakes.

**Target Functions:**
- `SSL_set_tlsext_servername()`
- SNI extension handling

### 2. PKCS#12 (`fuzz_pkcs12`)
Tests PKCS#12 certificate/key bundle parsing.

**Target Functions:**
- `d2i_PKCS12()`
- PKCS#12 processing

### 3. BIO Operations (`fuzz_bio_operations`)
Tests OpenSSL BIO (Basic I/O) memory operations.

**Target Functions:**
- `BIO_read()`, `BIO_write()`
- Memory BIO handling

### 4. TLS Handshake (`fuzz_handshake`)
Tests complete TLS handshake with dynamic certificate generation.

**Target Functions:**
- Full handshake flow
- Certificate creation and management

## Directory Structure

```
fuzz/
├── harnesses/              # Fuzzer source code
│   ├── fuzz_sni_parsing.c
│   ├── fuzz_pkcs12.c
│   ├── fuzz_bio_operations.c
│   └── fuzz_handshake.c
├── corpus/                 # Seed corpus (tracked in git)
│   ├── sni/
│   ├── pkcs12/
│   ├── bio/
│   └── handshake/
├── corpus-generated/       # Auto-discovered corpus (gitignored)
├── dict/                   # Fuzzing dictionaries
│   └── tls.dict
├── scripts/                # Build and execution scripts
├── oss-fuzz/              # OSS-Fuzz integration
├── logs/                   # Fuzzing logs (gitignored)
└── crashes/                # Crash artifacts (gitignored)
```

## Quick Start

```bash
# From repository root
./setup.sh

# Build fuzzers
cd fuzz/scripts
./build_fuzzers.sh

# Run short test
./run_fuzzers.sh 60 2

# Run full campaign
./run_fuzzers.sh 3600 4
```

## Corpus Management

### Seed Corpus vs Generated Corpus

- **`corpus/`** - Hand-crafted, minimal test cases (version controlled)
- **`corpus-generated/`** - Auto-discovered during fuzzing (not tracked)

### Merging Corpus

After a fuzzing run, merge interesting findings:

```bash
./merge_corpus.sh           # Merge all
./merge_corpus.sh sni       # Merge specific fuzzer
```

This uses libFuzzer's merge to eliminate redundant cases and keep only unique coverage.

### Cleaning Up

```bash
# Remove generated corpus (safe, can regenerate)
rm -rf ../corpus-generated/

# Full cleanup
rm -rf ../corpus-generated/ ../logs/ ../crashes/
```

## Running Individual Fuzzers

```bash
cd scripts

# Basic run
./fuzz_sni_parsing ../corpus/sni/

# With options
./fuzz_sni_parsing \
  -max_total_time=3600 \
  -dict=../dict/tls.dict \
  -artifact_prefix=../crashes/ \
  ../corpus-generated/sni/ \
  ../corpus/sni/
```

## Troubleshooting

### Fuzzer Exits Immediately

Check logs for errors:
```bash
cat ../logs/fuzz_*.log
```

Common issues:
- Dictionary format error (inline comments not supported)
- Missing corpus directory
- Native library not built with fuzzing

### Low Execution Rate

- Increase parallel jobs: `./run_fuzzers.sh 3600 8`
- Check memory limits with `top` or `htop`
- Reduce `-rss_limit_mb` if hitting memory constraints

### AddressSanitizer False Positives

Disable leak detection:
```bash
ASAN_OPTIONS=detect_leaks=0 ./run_fuzzers.sh
```

## OSS-Fuzz Integration

The `oss-fuzz/` directory contains:

- `project.yaml` - OSS-Fuzz project configuration
- `Dockerfile` - Build environment
- `build.sh` - Build script for OSS-Fuzz

To test locally:
```bash
# Clone OSS-Fuzz
git clone https://github.com/google/oss-fuzz.git
cd oss-fuzz

# Copy integration files
cp -r /path/to/fuzz/oss-fuzz projects/tomcat-native/

# Build
python infra/helper.py build_fuzzers tomcat-native

# Run
python infra/helper.py run_fuzzer tomcat-native fuzz_sni_parsing
```

## Verification

Run the verification script to check setup:

```bash
./verify_setup.sh
```

This performs:
- ✓ Prerequisite checks (clang, OpenSSL, APR)
- ✓ Build configuration verification
- ✓ Fuzzer binary validation
- ✓ AddressSanitizer test
- ✓ Short fuzzing runs
- ✓ OSS-Fuzz integration check

## Advanced Usage

### Custom Compiler Flags

```bash
export FUZZ_CFLAGS="-fsanitize=fuzzer,address,undefined -g -O2"
./build_fuzzers.sh
```

### Memory Limit

```bash
./run_fuzzers.sh 3600 4 --no-save  # Ephemeral, no corpus save
```

### Reproduce Crash

```bash
./fuzz_sni_parsing ../crashes/crash-abc123
```

## Resources

- [libFuzzer Tutorial](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)
- [Efficient Fuzzing Guide](https://chromium.googlesource.com/chromium/src/+/master/testing/libfuzzer/efficient_fuzzing.md)
- [Corpus Distillation](https://lcamtuf.blogspot.com/2014/11/pulling-jpegs-out-of-thin-air.html)
