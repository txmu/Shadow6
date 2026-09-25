#!/usr/bin/env bash
# Explicit CI provisioning, never called by ordinary build/test targets.
set -euo pipefail
case "$(uname -s)" in
    Linux) platform=linux; build_make='make' ;;
    FreeBSD) platform=freebsd; build_make='gmake' ;;
    *) echo 'Hare CI bootstrap supports Linux and FreeBSD' >&2; exit 1 ;;
esac
arch=$(uname -m)
if [[ "$arch" == amd64 ]]; then arch=x86_64; fi
if [[ "$platform" == freebsd && "$arch" != x86_64 ]]; then
    echo 'pinned Hare FreeBSD backend currently requires x86_64' >&2; exit 1
fi
case "$arch" in x86_64|aarch64) ;; *) echo 'unsupported Hare build architecture' >&2; exit 1 ;; esac
prefix=${1:?usage: bootstrap_hare_linux.sh ABSOLUTE_NEW_PREFIX}
case "$prefix" in /*) ;; *) echo 'prefix must be absolute' >&2; exit 1 ;; esac
if [[ -e "$prefix" || -L "$prefix" ]]; then
    echo 'prefix must not already exist' >&2
    exit 1
fi
work=$(mktemp -d /tmp/shadow6-hare-toolchain.XXXXXX)
trap 'rm -rf -- "$work"' EXIT

# Match the release validated by Core-Hare; never build a moving branch.
# Networks may resolve both A and AAAA records while routing only one family.
# Neither curl nor git performs happy-eyeballs, so probe IPv4 then IPv6.
fetch() {
    local url=$1 output=$2 family
    for family in 4 6; do
        if timeout 180 curl -"$family" --fail --location --proto '=https' --tlsv1.2 --retry 2 \
            --connect-timeout 15 --max-time 120 "$url" -o "$output"; then
            return 0
        fi
        rm -f -- "$output"
    done
    echo "unable to download $url over IPv4 or IPv6" >&2
    return 1
}

clone_pinned() {
    local url=$1 directory=$2 family
    for family in 4 6; do
        if timeout 300 git clone -"$family" --depth 1 --branch 0.24.2 "$url" "$directory"; then
            return 0
        fi
        rm -rf -- "$directory"
    done
    echo "unable to clone $url over IPv4 or IPv6" >&2
    return 1
}

fetch https://c9x.me/compile/release/qbe-1.2.tar.xz "$work/qbe.tar.xz"
if [[ "$platform" == freebsd ]]; then
    test "$(sha256 -q "$work/qbe.tar.xz")" = a6d50eb952525a234bf76ba151861f73b7a382ac952d985f2b9af1df5368225d
else
    printf '%s  %s\n' a6d50eb952525a234bf76ba151861f73b7a382ac952d985f2b9af1df5368225d \
        "$work/qbe.tar.xz" | sha256sum -c -
fi
tar -xJf "$work/qbe.tar.xz" -C "$work"
clone_pinned https://git.sr.ht/~sircmpwn/harec "$work/harec"
clone_pinned https://git.sr.ht/~sircmpwn/hare "$work/hare"
test "$(git -C "$work/harec" rev-parse HEAD)" = aaf2f364c6d9fad452416c0385ccd296541d5661
test "$(git -C "$work/hare" rev-parse HEAD)" = 66ebb53ef4fa8aea329e883ea21787a74bdcedf9

mkdir -p "$prefix/bin"
export PATH="$prefix/bin:$PATH"
"$build_make" -C "$work/qbe-1.2" -j2
install -m 0755 "$work/qbe-1.2/qbe" "$prefix/bin/qbe"
cp "$work/harec/configs/$platform.mk" "$work/harec/config.mk"
"$build_make" -C "$work/harec" -j2 PREFIX="$prefix" VERSION=0.24.2 ARCH="$arch"
"$build_make" -C "$work/harec" install PREFIX="$prefix" ARCH="$arch"
cp "$work/hare/configs/$platform.mk" "$work/hare/config.mk"
"$build_make" -C "$work/hare" -j2 .bin/hare PREFIX="$prefix" VERSION=0.24.2 ARCH="$arch"
"$build_make" -C "$work/hare" install-mods PREFIX="$prefix" ARCH="$arch"
install -m 0755 "$work/hare/.bin/hare" "$prefix/bin/hare"
hare version
