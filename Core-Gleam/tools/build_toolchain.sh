#!/usr/bin/env bash
# Offline, single-job provisioning. This is a development toolchain, not the Core ELF.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
prefix="$root/.tools/gleam"
export ERL_FLAGS='+S 1:1 +SDcpu 1 +SDio 1'
mkdir -p "$prefix/logs" "$prefix/musl"
# Expose only kernel UAPI headers; never mix glibc headers into musl builds.
mkdir -p "$prefix/kernel-headers"
for headers in linux asm-generic; do
    if [[ ! -e "$prefix/kernel-headers/$headers" ]]; then
        ln -s "/usr/include/$headers" "$prefix/kernel-headers/$headers"
    fi
done
if [[ ! -e "$prefix/kernel-headers/asm" ]]; then
    ln -s "/usr/include/$(gcc -dumpmachine)/asm" "$prefix/kernel-headers/asm"
fi
reserve() {
    local available
    available=$(df -Pk "$prefix" | awk 'NR == 2 {print $4}')
    if (( available < 1048576 )); then
        echo 'Stopping: less than 1 GiB disk space remains' >&2
        exit 1
    fi
}
reserve
if [[ ! -f "$prefix/musl/lib/libsodium.a" ]]; then
    (
        cd "$prefix/src/sodium"
        CC=musl-gcc CFLAGS='-O2 -fPIE' ./configure \
            --prefix="$prefix/musl" --disable-shared --enable-static
        make -j1
        make check -j1
        make install
    ) >"$prefix/logs/sodium.log" 2>&1
fi
reserve
if [[ ! -f "$prefix/musl/lib/libcrypto.a" ]]; then
    (
        cd "$prefix/src/openssl"
        case $(uname -m) in
            x86_64) target=linux-x86_64 ;;
            aarch64) target=linux-aarch64 ;;
            *) exit 2 ;;
        esac
        CC=musl-gcc ./Configure "$target" no-shared no-tests no-module \
            --prefix="$prefix/musl" --libdir=lib -O2 -fPIE \
            "-I$prefix/kernel-headers"
        make -j1
        make install_sw
    ) >"$prefix/logs/openssl.log" 2>&1
fi
reserve
if [[ ! -x "$prefix/otp/bin/erl" ]]; then
    (
        cd "$prefix/src/otp"
        # Host compiler runtime. Final musl embedded ERTS is a separate build.
        ./configure --prefix="$prefix/otp" --disable-jit --without-javac \
            --without-wx --without-odbc --without-debugger --without-observer \
            --without-et --without-megaco --without-diameter --without-snmp
        make -j1
        make install
    ) >"$prefix/logs/otp.log" 2>&1
fi
"$prefix/otp/bin/erl" -noshell -noinput -eval \
    'io:format("OTP ~s; emulator ~p~n", [erlang:system_info(otp_release), erlang:system_info(emu_flavor)]), halt().'
"$prefix/bin/gleam" --version
reserve
