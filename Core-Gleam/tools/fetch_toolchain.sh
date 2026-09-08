#!/usr/bin/env bash
# Explicit provisioning, never invoked by ordinary build/test targets.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
prefix="$root/.tools/gleam"
mkdir -p "$prefix/downloads" "$prefix/src" "$prefix/bin" "$root/.tmp"
work=$(mktemp -d "$root/.tmp/gleam-fetch.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

fetch() {
    local url=$1 digest=$2 name=$3
    if [[ ! -f "$prefix/downloads/$name" ]]; then
        curl --proto '=https' --proto-redir '=https' --fail --location \
            --connect-timeout 15 --max-time 600 --retry 2 "$url" -o "$work/$name"
        printf '%s  %s\n' "$digest" "$work/$name" | sha256sum -c -
        mv -- "$work/$name" "$prefix/downloads/$name"
    fi
    printf '%s  %s\n' "$digest" "$prefix/downloads/$name" | sha256sum -c -
}
case $(uname -m) in
    x86_64) arch=x86_64; gleam_sha=4955a38c2e8c99457458e2471472ccd5ee3c45bd7637a315ce33bccf0dd75d9e ;;
    aarch64) arch=aarch64; gleam_sha=ea08a64846677f36da7f2e9163c4393dd9a9dee814d13a8fb28fbe7dcbf32f6d ;;
    *) echo 'Core-Gleam supports only x86_64 and aarch64 Linux hosts' >&2; exit 2 ;;
esac
fetch "https://github.com/gleam-lang/gleam/releases/download/v1.18.1/gleam-v1.18.1-$arch-unknown-linux-musl.tar.gz" "$gleam_sha" gleam.tar.gz
fetch https://github.com/erlang/otp/releases/download/OTP-29.0.6/otp_src_29.0.6.tar.gz \
    36c89ffdac9d7531c19be0cee34355b167ea95188625d32bee61ebf49ac82afa otp.tar.gz
fetch https://github.com/openssl/openssl/releases/download/openssl-3.5.7/openssl-3.5.7.tar.gz \
    a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8 openssl.tar.gz
fetch https://github.com/jedisct1/libsodium/releases/download/1.0.22-RELEASE/libsodium-1.0.22.tar.gz \
    adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349 sodium.tar.gz
fetch https://github.com/erlang/rebar3/releases/download/3.27.0/rebar3 \
    af85aab41f9fd74bdd6341ebdf6fe9c88077aab9f8eac82371583fa02f2b0bdf rebar3
install -m 0755 "$prefix/downloads/rebar3" "$prefix/bin/rebar3"

tar -xzf "$prefix/downloads/gleam.tar.gz" -C "$work"
install -m 0755 "$work/gleam" "$prefix/bin/gleam"
for name in otp openssl sodium; do
    if [[ ! -d "$prefix/src/$name" ]]; then
        mkdir "$work/$name"
        tar -xzf "$prefix/downloads/$name.tar.gz" --strip-components=1 -C "$work/$name"
        mv -- "$work/$name" "$prefix/src/$name"
    fi
done
"$prefix/bin/gleam" --version
printf 'Verified sources: %s\n' "$prefix/src"
