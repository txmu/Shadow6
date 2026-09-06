#!/usr/bin/env bash
set -euo pipefail

export CGO_ENABLED=0
if [[ "$(go env GOARCH)" == amd64 ]]; then
    export GOAMD64="${GOAMD64:-v1}"
fi
temporary="shadow6-go.tmp.$$"
trap 'rm -f "$temporary"' EXIT
tags=()
case "${CROSED_LEVEL:-0}" in
    0) ;;
    1) tags+=(crosed) ;;
    2|3|4|5) tags+=(crosed "crosed_l${CROSED_LEVEL}") ;;
    *) printf '%s\n' 'CROSED_LEVEL must be 0..5' >&2; exit 2 ;;
esac
[[ "${APP_TRANSPORT:-0}" == 1 ]] && tags+=(app_transport)
[[ "${QUBES_ISOLATION:-0}" == 1 ]] && tags+=(qubes_isolation)
build_args=(-buildvcs=false -o "$temporary" -trimpath -ldflags='-s -w -buildid=')
[[ "$(go env GOOS)" != "openbsd" && "$(go env GOOS)" != "netbsd" ]] && build_args+=(-buildmode=pie)
if ((${#tags[@]})); then
    joined_tags=$(IFS=,; printf '%s' "${tags[*]}")
    build_args+=(-tags "$joined_tags")
fi
go build "${build_args[@]}" .
mv -f "$temporary" shadow6-go
chmod 0755 shadow6-go
trap - EXIT
printf '%s\n' '[+] Built Core-Go: shadow6-go'
