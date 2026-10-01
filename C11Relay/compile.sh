#!/usr/bin/env bash
set -euo pipefail

compiler=${CC:-cc}
work=$(mktemp -d "${TMPDIR:-/tmp}/shadow6-relay-build.XXXXXX")
temporary="$work/bridge_relay"
trap 'rm -rf "$work"' EXIT

# Keep the portable warning baseline strict, then add hardening one feature at
# a time.  Several useful flags are compiler- or linker-specific (notably the
# GNU -z family), so probing the complete combination would make a Darwin or
# non-GNU build fail for an unrelated option.
compile_flags=(-std=c11 -O3 -Wall -Wextra -Wpedantic)
link_flags=()
probe_compile() {
    local name=$1; shift
    printf 'int shadow6_probe;\n' | "$compiler" "${compile_flags[@]}" "$@" -x c -c -o "$work/$name.o" - >/dev/null 2>&1
}
probe_link() {
    local name=$1; shift
    printf 'int main(void){return 0;}\n' | "$compiler" "${compile_flags[@]}" "$@" -x c -o "$work/$name" - >/dev/null 2>&1
}
add_compile_if_supported() {
    local name=$1; shift
    if probe_compile "$name" "$@"; then compile_flags+=("$@"); fi
}
add_link_if_supported() {
    local name=$1; shift
    if probe_link "$name" "${link_flags[@]}" "$@"; then link_flags+=("$@"); fi
}

if probe_compile fortify -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3; then
    compile_flags+=(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
fi
add_compile_if_supported format2 -Wformat=2
add_compile_if_supported format-security -Werror=format-security
add_compile_if_supported stack-protector -fstack-protector-strong
add_compile_if_supported trampolines -Wtrampolines
add_compile_if_supported stack-clash -fstack-clash-protection
add_compile_if_supported cf-protection -fcf-protection=full
add_compile_if_supported auto-init -ftrivial-auto-var-init=zero
add_compile_if_supported no-plt -fno-plt

# LTO and PIE need a link probe; keeping them separate lets a toolchain retain
# one when the other is unavailable.
if probe_link lto -flto; then compile_flags+=(-flto); fi
if probe_link pie -fPIE -pie; then compile_flags+=(-fPIE); link_flags+=(-pie); fi
add_link_if_supported relro '-Wl,-z,relro'
add_link_if_supported now '-Wl,-z,now'
add_link_if_supported noexecstack '-Wl,-z,noexecstack'
add_link_if_supported defs '-Wl,-z,defs'

echo "[+] C11Relay hardening: compile=${compile_flags[*]} link=${link_flags[*]}" >&2
"$compiler" "${compile_flags[@]}" c11relay.c "${link_flags[@]}" -o "$temporary"
chmod 0755 "$temporary"
mv -f "$temporary" bridge_relay
printf '%s\n' '[+] Built C11Relay: bridge_relay'
