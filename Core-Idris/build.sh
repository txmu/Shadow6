#!/bin/bash
set -euo pipefail

# Build script for Core-Idris with security hardening

CROSED_LEVEL="${IDRIS_CROSED_LEVEL:-0}"
APP_TRANSPORT="${IDRIS_APP_TRANSPORT:-0}"
QUBES_ISOLATION="${IDRIS_QUBES_ISOLATION:-0}"

echo "Building Core-Idris with Crosed level $CROSED_LEVEL"

# Create build directory
mkdir -p obj

# Generate feature configuration based on build flags
cat > src/Shadow6/BuildConfig.idr << BUILDEOF
module Shadow6.BuildConfig

import Shadow6.Types

%default total

-- Generated at build time
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

# Update Features.idr to use BuildConfig
sed -i.bak \
  -e 's/^COMPILED_CROSED_LEVEL = L0/COMPILED_CROSED_LEVEL = BUILD_CROSED_LEVEL/' \
  -e 's/^COMPILED_APP_TRANSPORT = False/COMPILED_APP_TRANSPORT = BUILD_APP_TRANSPORT/' \
  -e 's/^COMPILED_QUBES_ISOLATION = False/COMPILED_QUBES_ISOLATION = BUILD_QUBES_ISOLATION/' \
  src/Shadow6/Features.idr || true

# Build with Idris 2
echo "Compiling with Idris 2..."
idris2 --build shadow6-idris.ipkg

# Apply security hardening to generated C code
if [ -f "build/exec/shadow6-idris" ]; then
  # Recompile with full security flags
  cd obj
  
  # Find all generated C files
  C_FILES=$(find . -name "*.c" 2>/dev/null || true)
  
  if [ -n "$C_FILES" ]; then
    echo "Applying security hardening to C backend..."
    
    # Recompile with hardening flags
    gcc -O2 -g \
      -fstack-protector-strong \
      -fPIE \
      -D_FORTIFY_SOURCE=2 \
      -Wl,-z,relro,-z,now \
      -Wl,-z,noexecstack \
      $C_FILES \
      -lsodium \
      -lpthread \
      -o ../shadow6-idris
  fi
  
  cd ..
fi

# Install binary
if [ -f "build/exec/shadow6-idris" ]; then
  install -m 0755 build/exec/shadow6-idris shadow6-idris
elif [ -f "shadow6-idris" ]; then
  chmod 0755 shadow6-idris
else
  echo "Warning: Binary not found after build"
fi

# Restore original Features.idr
if [ -f "src/Shadow6/Features.idr.bak" ]; then
  mv src/Shadow6/Features.idr.bak src/Shadow6/Features.idr
fi

echo "Build complete: shadow6-idris"
