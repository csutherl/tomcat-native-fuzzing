# Tomcat Native Fuzzing

Standalone fuzzing infrastructure for [Apache Tomcat Native Library](https://github.com/apache/tomcat-native) using libFuzzer, AddressSanitizer, and UndefinedBehaviorSanitizer.

## Quick Start

```bash
# 1. Clone this repository
git clone <your-repo-url> tomcat-native-fuzzing
cd tomcat-native-fuzzing

# 2. Run setup (initializes submodule and builds tomcat-native)
./setup.sh

# 3. Build fuzzers
cd fuzz/scripts
./build_fuzzers.sh

# 4. Run fuzzing campaign
./run_fuzzers.sh 3600    # Run for 1 hour
```

## Repository Structure

```
.
├── README.md                     # This file
├── setup.sh                      # Setup script
├── tomcat-native/                # Git submodule → apache/tomcat-native
│   ├── native/                   # Native library source
│   ├── java/                     # Java bindings
│   └── ...
└── fuzz/                         # Fuzzing infrastructure
    ├── harnesses/                # Fuzzer source code (*.c)
    ├── corpus/                   # Seed corpus (version controlled)
    │   ├── sni/                  # SNI parsing tests
    │   ├── pkcs12/               # PKCS#12 tests
    │   ├── bio/                  # BIO operations tests
    │   └── handshake/            # TLS handshake tests
    ├── corpus-generated/         # Auto-discovered inputs (gitignored)
    ├── dict/                     # Fuzzing dictionaries
    │   └── tls.dict              # TLS protocol tokens
    ├── scripts/                  # Build and run scripts
    │   ├── build_fuzzers.sh      # Build fuzzer binaries
    │   ├── run_fuzzers.sh        # Run fuzzing campaign
    │   ├── merge_corpus.sh       # Merge generated corpus
    │   ├── generate_corpus.sh    # Generate seed corpus
    │   └── verify_setup.sh       # Verify fuzzing setup
    ├── oss-fuzz/                 # OSS-Fuzz integration
    │   ├── project.yaml
    │   ├── Dockerfile
    │   └── build.sh
    ├── logs/                     # Fuzzing logs (gitignored)
    ├── crashes/                  # Crash artifacts (gitignored)
    └── README.md                 # Detailed fuzzing documentation
```

## Features

- **4 Fuzz Targets**: SNI parsing, PKCS#12, BIO operations, TLS handshake
- **Live Progress Monitoring**: Real-time coverage and corpus growth stats
- **Corpus Management**: Separate seed (tracked) and generated (untracked) corpora
- **Sanitizers**: AddressSanitizer, UndefinedBehaviorSanitizer, libFuzzer
- **OSS-Fuzz Ready**: Includes integration files for Google OSS-Fuzz
- **CI/CD Ready**: GitHub Actions workflow templates included

## Requirements

- **Compiler**: Clang 8+ (required for `-fsanitize=fuzzer`)
- **OpenSSL**: 3.0+
- **APR**: 1.7+
- **OS**: Linux (tested on Fedora/Ubuntu)

## Usage

### Running Fuzzers

```bash
cd fuzz/scripts

# Run for 1 hour with 4 parallel jobs (default)
./run_fuzzers.sh

# Run for 60 seconds with 2 parallel jobs
./run_fuzzers.sh 60 2

# Run without saving generated corpus (ephemeral mode)
./run_fuzzers.sh 60 2 --no-save
```

### Managing Corpus

The fuzzing infrastructure uses two corpus directories:

- **`corpus/`** - Manually curated seed corpus (version controlled)
- **`corpus-generated/`** - Auto-discovered test cases (gitignored)

After fuzzing, merge interesting findings into the seed corpus:

```bash
cd fuzz/scripts

# Merge all fuzzers
./merge_corpus.sh

# Merge specific fuzzer
./merge_corpus.sh sni
```

### Verifying Setup

```bash
cd fuzz/scripts
./verify_setup.sh
```

This checks prerequisites, build configuration, and runs short fuzzing tests.

## Fuzzing Support Patch

The fuzzing build requires a patch to tomcat-native's build system to add `--enable-fuzzing` support. This patch is not yet committed to the upstream Apache Tomcat Native project.

The patch (`fuzzing-support.patch`) is **automatically applied** by `setup.sh` and adds:
- **libFuzzer** instrumentation
- **AddressSanitizer** for memory error detection
- **UndefinedBehaviorSanitizer** for undefined behavior detection
- **Coverage instrumentation** for corpus minimization
- Gitignore entry for `autom4te.cache/` build artifacts

### Manual Patch Application

If you need to apply the patch manually (outside of setup.sh):

```bash
cd tomcat-native
patch -p1 < ../fuzzing-support.patch
```

### Reverting the Patch

To restore tomcat-native to a clean upstream state:

```bash
cd tomcat-native
git checkout .gitignore native/configure.ac
rm -rf native/autom4te.cache
```

## Syncing with Upstream

Update the tomcat-native submodule to the latest version:

```bash
cd tomcat-native
git pull origin master
cd ..
git add tomcat-native
git commit -m "Update tomcat-native submodule to latest"
```

Test against a specific tomcat-native branch:

```bash
cd tomcat-native
git checkout <branch-name>
cd ..
./setup.sh
cd fuzz/scripts
./build_fuzzers.sh
```

## Contributing Back to Upstream

When this fuzzing infrastructure is mature and proven:

1. Create a branch in the tomcat-native submodule
2. Copy `fuzz/` directory contents to `tomcat-native/native/fuzz/`
3. Update paths in scripts to work in-tree
4. Submit PR to apache/tomcat-native

## Development Workflow

1. **Make changes** to fuzzing infrastructure in `fuzz/`
2. **Test changes** with `./build_fuzzers.sh && ./run_fuzzers.sh 60 2`
3. **Commit changes** to this repository
4. **Run extended fuzzing** campaigns to validate
5. **Merge interesting corpus** findings
6. **Push to GitHub** for CI/CD and collaboration

## Continuous Fuzzing

For continuous fuzzing campaigns:

```bash
# Run for 24 hours
./run_fuzzers.sh 86400 8

# Monitor in another terminal
tail -f ../logs/*.log
```

## License

This fuzzing infrastructure is licensed under the Apache License 2.0, same as Apache Tomcat Native.

## Resources

- [Apache Tomcat Native](https://tomcat.apache.org/native-doc/)
- [libFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [OSS-Fuzz](https://github.com/google/oss-fuzz)
- [AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)

## Contact

For questions or issues with the fuzzing infrastructure, please open an issue on GitHub.
