#!/usr/bin/env bash
set -euo pipefail

# The host provisions the exact setup-go version and verifies its SHA-256.
test "$(uname -s)" = NetBSD
: "${PYTHON:=/usr/pkg/bin/python3.11}"
export PYTHON
"$PYTHON" --version
toolchain_dir=$(mktemp -d /tmp/shadow6-netbsd-go.XXXXXX)
trap 'rm -rf -- "$toolchain_dir"' EXIT
tar -xzf .tmp/netbsd-go/go.tar.gz -C "$toolchain_dir"
export PATH="$toolchain_dir/go/bin:$PATH"
export GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
go version

for component in Core-Go Guard Gate; do
    (cd "$component" && go test -buildvcs=false -count=1 -timeout=5m ./...)
done
(
    cd Core-Go
    CROSED_LEVEL=5 APP_TRANSPORT=1 QUBES_ISOLATION=1 bash ./compile.sh
    mv shadow6-go shadow6-go-crosed
    CROSED_LEVEL=0 APP_TRANSPORT=0 QUBES_ISOLATION=0 bash ./compile.sh
    ./shadow6-go --feature-report
    ./shadow6-go-crosed --feature-report
)

# Build every additional core whose native toolchain is provisioned by the
# NetBSD image; unsupported optional toolchains remain an explicit boundary.
if command -v c++ >/dev/null 2>&1 && test -f /usr/include/openssl/ssl.h; then
    (
        cd Core-Cpp
        bash ./compile.sh
        bash ./test.sh
    )
fi
if command -v zig >/dev/null 2>&1; then
    (cd Core-Zig && zig build -Doptimize=ReleaseSafe && zig build test -Doptimize=ReleaseSafe)
fi
if command -v nim >/dev/null 2>&1 && test -f /usr/include/openssl/evp.h; then
    (cd Core-Nim && nim c --mm:arc --threads:on -d:release -o:shadow6-nim src/shadow6_nim.nim)
fi
