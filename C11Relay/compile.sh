#!/usr/bin/env bash
set -euo pipefail

temporary="bridge_relay.tmp.$$"
trap 'rm -f "$temporary"' EXIT
compiler=${CC:-cc}
flags=(-std=c11 -O3 -flto -Wall -Wextra -Wpedantic -Wformat=2
    -Werror=format-security -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
    -fPIE -pie -fstack-protector-strong -D_GNU_SOURCE
    "-Wl,-z,relro,-z,now" "-Wl,-z,noexecstack" "-Wl,-z,defs")
for optional in -Wtrampolines -fstack-clash-protection -fcf-protection=full -ftrivial-auto-var-init=zero; do
    if printf 'int shadow6_probe;\n' | "$compiler" -x c -c -o /dev/null "$optional" - 2>/dev/null; then
        flags+=("$optional")
    fi
done
"$compiler" "${flags[@]}" c11relay.c -o "$temporary"
mv -f "$temporary" bridge_relay
trap - EXIT
printf '%s\n' '[+] Built C11Relay: bridge_relay'
