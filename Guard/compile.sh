#!/usr/bin/env bash
set -euo pipefail

export CGO_ENABLED=0
if [[ "$(go env GOARCH)" == amd64 ]]; then
    export GOAMD64="${GOAMD64:-v1}"
fi
temporary="shadow6-guard.tmp.$$"
trap 'rm -f "$temporary"' EXIT
go build -buildvcs=false -o "$temporary" -trimpath -buildmode=pie -ldflags='-s -w -buildid=' .
mv -f "$temporary" shadow6-guard
chmod 0755 shadow6-guard
trap - EXIT
./shadow6-guard --install-ctl
chmod 0755 shadow6-guard-ctl.sh
printf '%s\n' '[+] Built Guard: shadow6-guard and shadow6-guard-ctl.sh'
