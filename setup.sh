#!/bin/bash
#
# Setup script for Tomcat Native fuzzing environment
#
# This script initializes the fuzzing environment by:
# 1. Updating the tomcat-native submodule
# 2. Configuring tomcat-native with fuzzing enabled
# 3. Building the native library
#

set -e

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "========================================="
echo "Tomcat Native Fuzzing Setup"
echo "========================================="
echo

# Check for required tools
echo "Checking prerequisites..."
if ! command -v clang &> /dev/null; then
    echo "Error: clang not found. Install clang to build fuzzers." >&2
    exit 1
fi

if ! command -v git &> /dev/null; then
    echo "Error: git not found." >&2
    exit 1
fi

echo "✓ Prerequisites found"
echo

# Update submodule
echo "Updating tomcat-native submodule..."
cd "$REPO_ROOT"
git submodule update --init --recursive

if [ ! -d "tomcat-native" ]; then
    echo "Error: tomcat-native submodule not found" >&2
    exit 1
fi

echo "✓ Submodule updated"
echo

# Apply fuzzing support patch
echo "Applying fuzzing support patch..."
cd "$REPO_ROOT/tomcat-native"

# Check if patch is already applied
if ! grep -q "enable-fuzzing" native/configure.ac 2>/dev/null; then
    patch -p1 < "$REPO_ROOT/fuzzing-support.patch"
    echo "✓ Fuzzing support patch applied"
else
    echo "✓ Fuzzing support already enabled"
fi
echo

# Build tomcat-native (normal build, not fuzzing)
echo "Configuring tomcat-native..."
cd "$REPO_ROOT/tomcat-native/native"

# Check if we need to run buildconf
if [ ! -f "configure" ]; then
    echo "Running buildconf..."
    # Copy build files if needed
    if [ ! -f "build/tcnative.m4" ]; then
        mkdir -p build
        apr_build_dir=$(apr-1-config --installbuilddir 2>/dev/null || echo "/usr/lib64/apr-1/build")
        if [ -d "$apr_build_dir" ]; then
            cp "$apr_build_dir"/config.* build/ 2>/dev/null || true
            cp "$apr_build_dir"/install.sh build/ 2>/dev/null || true
        fi
    fi
    ./buildconf --with-apr=/usr 2>&1 | grep -v "^libtoolize:" || autoreconf --install --force
fi

# Configure normally (not with fuzzing - fuzzers will have fuzzing flags)
echo "Running configure..."
./configure \
    --with-apr=/usr \
    --with-ssl=/usr

if [ $? -ne 0 ]; then
    echo "Error: configure failed" >&2
    echo "You may need to adjust --with-apr and --with-ssl paths" >&2
    exit 1
fi

echo "✓ Configuration complete"
echo

# Build
echo "Building tomcat-native library..."
make

if [ $? -ne 0 ]; then
    echo "Error: build failed" >&2
    exit 1
fi

echo "✓ Build complete"
echo

echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo
echo "Next steps:"
echo "  1. Build fuzzers:       cd fuzz/scripts && ./build_fuzzers.sh"
echo "  2. Run quick test:      cd fuzz/scripts && ./run_fuzzers.sh 60 2"
echo "  3. Verify setup:        cd fuzz/scripts && ./verify_setup.sh"
echo
echo "For more information:"
echo "  See fuzz/README.md"
echo
