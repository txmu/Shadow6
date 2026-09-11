#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
export CARP_DIR=${CARP_DIR:-"$PWD/../.tools/carp-v0.5.5-x86_64-linux"}
carp=${CARP:-"$CARP_DIR/bin/carp"}
test -x "$carp" || { echo 'Carp 0.5.5 toolchain required; set CARP and CARP_DIR' >&2; exit 1; }
mkdir -p build
"$carp" --no-profile --optimize --generate-only -b src/main.carp
test -s build/main.c && test -s build/schema.h
"${CC:-cc}" -std=c99 -D_DEFAULT_SOURCE -O2 -ffunction-sections -fdata-sections \
    -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function \
    -I"$CARP_DIR/core" -Isrc -Ibuild build/main.c -Wl,--gc-sections \
    -Wl,-z,relro,-z,now -lsodium -lm -o build/shadow6-carp
install -m 0755 build/shadow6-carp shadow6-carp
