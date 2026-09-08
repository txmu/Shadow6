#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
prefix="$root/.tools/gleam"
export PATH="$prefix/bin:$prefix/otp/bin:$PATH"
export ERL_FLAGS='+S 1:1 +SDcpu 1 +SDio 1'
work=$(mktemp -d "$root/.tmp/gleam-verify.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
erl -noshell -noinput -eval \
    'emu = erlang:system_info(emu_flavor), io:format("OTP ~s: JIT disabled~n", [erlang:system_info(otp_release)]), halt().'
rebar3 version
cp -R "$root/Core-Gleam/tools/smoke/." "$work/"
(cd "$work" && gleam run)
musl-gcc -O2 -Wall -Wextra -Werror -fPIE -pie -static-pie \
    -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
    -I"$prefix/musl/include" "$root/Core-Gleam/tools/smoke_crypto.c" \
    -L"$prefix/musl/lib" -lsodium -lcrypto -pthread -ldl \
    -o "$work/crypto-smoke"
readelf -Wh "$work/crypto-smoke" >"$work/header"
readelf -Wl "$work/crypto-smoke" >"$work/segments"
readelf -Wd "$work/crypto-smoke" >"$work/dynamic"
grep -Eq 'Type: +DYN' "$work/header"
grep -Eq 'GNU_STACK .* RW ' "$work/segments"
grep -q GNU_RELRO "$work/segments"
grep -q BIND_NOW "$work/dynamic"
if grep -q INTERP "$work/segments" || grep -q NEEDED "$work/dynamic"; then
    echo 'Unexpected dynamic dependency' >&2
    exit 1
fi
"$work/crypto-smoke"
echo 'Toolchain smoke tests passed (not a Core runtime audit).'
