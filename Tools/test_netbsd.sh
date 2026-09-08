#!/usr/bin/env bash
set -euo pipefail

# The host provisions the exact setup-go version and verifies its SHA-256.
test "$(uname -s)" = NetBSD
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
