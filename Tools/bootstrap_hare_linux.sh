#!/usr/bin/env bash
# Explicit CI provisioning, never called by ordinary build/test targets.
set -euo pipefail
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
prefix=${1:?usage: bootstrap_hare_linux.sh ABSOLUTE_NEW_PREFIX}
case "$prefix" in /*) ;; *) echo 'prefix must be absolute' >&2; exit 1 ;; esac
if [[ -e "$prefix" || -L "$prefix" ]]; then
    echo 'prefix must not already exist' >&2
    exit 1
fi
work=$(mktemp -d /tmp/shadow6-hare-toolchain.XXXXXX)
trap 'rm -rf -- "$work"' EXIT

# Match the release validated by Core-Hare; never build a moving branch.
curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
    --connect-timeout 15 --max-time 120 \
    https://c9x.me/compile/release/qbe-1.2.tar.xz -o "$work/qbe.tar.xz"
printf '%s  %s\n' a6d50eb952525a234bf76ba151861f73b7a382ac952d985f2b9af1df5368225d \
    "$work/qbe.tar.xz" | sha256sum -c -
tar -xJf "$work/qbe.tar.xz" -C "$work"
git clone --depth 1 --branch 0.24.2 https://git.sr.ht/~sircmpwn/harec "$work/harec"
git clone --depth 1 --branch 0.24.2 https://git.sr.ht/~sircmpwn/hare "$work/hare"
test "$(git -C "$work/harec" rev-parse HEAD)" = aaf2f364c6d9fad452416c0385ccd296541d5661
test "$(git -C "$work/hare" rev-parse HEAD)" = 66ebb53ef4fa8aea329e883ea21787a74bdcedf9

mkdir -p "$prefix/bin"
export PATH="$prefix/bin:$PATH"
make -C "$work/qbe-1.2" -j2
install -m 0755 "$work/qbe-1.2/qbe" "$prefix/bin/qbe"
cp "$work/harec/configs/linux.mk" "$work/harec/config.mk"
make -C "$work/harec" -j2 PREFIX="$prefix" VERSION=0.24.2
make -C "$work/harec" install PREFIX="$prefix"
cp "$work/hare/configs/linux.mk" "$work/hare/config.mk"
make -C "$work/hare" -j2 .bin/hare PREFIX="$prefix" VERSION=0.24.2
make -C "$work/hare" install-mods PREFIX="$prefix"
install -m 0755 "$work/hare/.bin/hare" "$prefix/bin/hare"
hare version
