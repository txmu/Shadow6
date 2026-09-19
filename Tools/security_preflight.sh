#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
python=${SHADOW6_PYTHON:-$root/.venv/bin/python}
[[ -x "$python" ]] || python=$(command -v python3)
[[ -x "$python" ]] || { echo "python3 is required" >&2; exit 2; }

failed=0
check_mode() {
    local path=$1 expected=$2 mode
    [[ -e "$path" ]] || return 0
    mode=$(stat -Lc '%a' -- "$path")
    if [[ "$mode" != "$(printf '%03o' "$expected")" ]]; then
        printf 'FAIL unsafe mode %s: %s (expected %s)\n' "$mode" "$path" "$expected" >&2
        failed=1
    fi
}

while IFS= read -r -d '' path; do
    check_mode "$path" 600
done < <(find "$root" -path "$root/.tools" -prune -o -path "$root/.venv" -prune -o -path "$root/work" -prune -o -type f -name '*.key' -print0)

while IFS= read -r -d '' path; do
    check_mode "$path" 0755
done < <(find "$root/configure" "$root/setup_test.sh" "$root"/Core-Go/*.sh \
    "$root"/Core-Rust/*.sh "$root"/C11Relay/*.sh "$root"/Guard/*.sh \
    "$root"/Tools/*.sh -maxdepth 0 -print0)

"$python" "$root/shadow6_audit.py" --source-only
shellcheck "$root/configure" "$root/setup_test.sh" "$root"/Core-Go/*.sh \
    "$root"/Core-Rust/*.sh "$root"/C11Relay/*.sh "$root"/Guard/*.sh \
    "$root"/Tools/*.sh
(( failed == 0 )) || exit 1
echo "PASS source security preflight"
