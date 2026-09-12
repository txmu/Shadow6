#!/bin/bash
set -euo pipefail

# Simplified build script for Core-Idris
# This script handles the complete build without relying on Idris package system

CROSED_LEVEL="${IDRIS_CROSED_LEVEL:-0}"
APP_TRANSPORT="${IDRIS_APP_TRANSPORT:-0}"
QUBES_ISOLATION="${IDRIS_QUBES_ISOLATION:-0}"

echo "========================================="
echo "Building Core-Idris (Simplified Build)"
echo "========================================="
echo "Crosed Level: $CROSED_LEVEL"
echo "App Transport: $APP_TRANSPORT"
echo "Qubes Isolation: $QUBES_ISOLATION"
echo ""

# Check dependencies
if ! command -v idris2 &> /dev/null; then
    echo "ERROR: idris2 not found"
    echo "Install from: https://www.idris-lang.org/pages/download.html"
    exit 1
fi

if ! pkg-config --exists libsodium; then
    echo "ERROR: libsodium not found"
    echo "Install: sudo apt-get install libsodium-dev"
    exit 1
fi

# Update build configuration
echo "Generating build configuration..."
cat > src/Shadow6/BuildConfig.idr << BUILDEOF
module Shadow6.BuildConfig

import Shadow6.Types

%default total

public export
BUILD_CROSED_LEVEL : CrosedLevel
BUILD_CROSED_LEVEL = $(case $CROSED_LEVEL in
  0) echo "L0" ;;
  1) echo "L1" ;;
  2) echo "L2" ;;
  3) echo "L3" ;;
  4) echo "L4" ;;
  5) echo "L5" ;;
  *) echo "L0" ;;
esac)

public export
BUILD_APP_TRANSPORT : Bool
BUILD_APP_TRANSPORT = $([ "$APP_TRANSPORT" = "1" ] && echo "True" || echo "False")

public export
BUILD_QUBES_ISOLATION : Bool
BUILD_QUBES_ISOLATION = $([ "$QUBES_ISOLATION" = "1" ] && echo "True" || echo "False")
BUILDEOF

# Build C FFI wrapper
echo "Compiling C FFI wrapper..."
mkdir -p ffi
gcc -c -fPIC -O2 -fstack-protector-strong \
    $(pkg-config --cflags libsodium) \
    ffi/sodium_ffi.c -o ffi/sodium_ffi.o

# Try package build first
echo "Building with Idris2..."
if idris2 --build shadow6-idris.ipkg 2>&1 | tee build.log; then
    if [ -f "build/exec/shadow6-idris" ]; then
        install -m 0755 build/exec/shadow6-idris shadow6-idris
        echo "✓ Build successful"
    else
        echo "Warning: Package build completed but binary not at expected location"
        echo "Attempting manual compilation..."
        
        # Fallback: manual compilation
        mkdir -p obj
        idris2 -o shadow6-idris \
            --codegen c \
            -p contrib \
            -p network \
            src/Main.idr
        
        if [ -f "build/exec/shadow6-idris" ]; then
            install -m 0755 build/exec/shadow6-idris shadow6-idris
            echo "✓ Manual build successful"
        fi
    fi
else
    echo "Build failed - see build.log for details"
    exit 1
fi

# Verify binary
if [ -x "./shadow6-idris" ]; then
    echo ""
    echo "========================================="
    echo "Build complete!"
    echo "========================================="
    echo "Binary: ./shadow6-idris"
    echo ""
    echo "Test with:"
    echo "  ./shadow6-idris --version"
    echo "  ./shadow6-idris --feature-report"
else
    echo "ERROR: Binary not created"
    exit 1
fi
