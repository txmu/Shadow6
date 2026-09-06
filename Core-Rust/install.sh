#!/usr/bin/env bash
set -euo pipefail
prefix="${PREFIX:-/usr/local}"
destination="${DESTDIR:-}${prefix}/bin"
install -d "$destination"
install -m 0755 shadow6-rust "$destination/shadow6-rust"
printf 'Installed %s\n' "$destination/shadow6-rust"
