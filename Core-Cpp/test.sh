#!/usr/bin/env bash
set -euo pipefail

test -x ./shadow6-cpp
report=$(./shadow6-cpp --feature-report)
case "$report" in
  *'"core":"shadow6-cpp"'*'"crosed_max_level":0'*'"utf8":true'*) ;;
  *) echo "unexpected C++ feature report" >&2; exit 1 ;;
esac
config=$(mktemp)
trap 'rm -f "$config"' EXIT
printf '%s\n' '{"role":"agent","agent":{"transport":"sctp","target_port":22}}' > "$config"
./shadow6-cpp --check-config "$config" >/dev/null
printf '%s\n' '[+] Core-Cpp contract tests passed'
