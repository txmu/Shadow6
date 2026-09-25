#!/usr/bin/env bash
set -euo pipefail
temporary="shadow6-hare.tmp.$$"
trap 'rm -f -- "$temporary"' EXIT
case "$(uname -s)" in
    Linux)
        LDFLAGS='-static-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack' \
            hare build -l sodium -o "$temporary" src
        ;;
    FreeBSD)
        probe=$(mktemp -d /tmp/shadow6-hare-link.XXXXXX)
        trap 'rm -f -- "$temporary"; rm -rf -- "$probe"' EXIT
        hardening=('-Wl,-z,relro,-z,now' '-Wl,-z,noexecstack')
        # Probe only the native ABI/linker limitation. Keep every other
        # hardening flag mandatory, including PIE on the dynamic fallback.
        if printf 'int main(void) { return 0; }\n' | cc -Werror=unused-command-line-argument -x c - -static-pie \
            -L/usr/local/lib -lsodium "${hardening[@]}" -o "$probe/link" 2>"$probe/static-pie.log"; then
            pie=(-static-pie)
        else
            cat "$probe/static-pie.log" >&2
            echo 'FreeBSD static PIE unavailable; requiring dynamic PIE with the same RELRO/NX flags' >&2
            pie=(-fPIE -pie)
            printf 'int main(void) { return 0; }\n' | cc -x c - "${pie[@]}" \
                -L/usr/local/lib -lsodium "${hardening[@]}" -o "$probe/link"
        fi
        # libsodium depends on libc. Select Hare's libc startup explicitly so
        # FreeBSD initializes libc/TLS before config I/O and allocation.
        LDFLAGS="${pie[*]} ${hardening[*]}" \
            hare build -L /usr/local/lib -l c -l sodium -o "$temporary" src
        timeout 10 "./$temporary" --feature-report >/dev/null
        rm -rf -- "$probe"
        ;;
    *) echo 'Core-Hare supports Linux and FreeBSD' >&2; exit 1 ;;
esac
chmod 0755 "$temporary"
mv -f -- "$temporary" shadow6-hare
trap - EXIT
