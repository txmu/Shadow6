#!/usr/bin/env bash
set -euo pipefail

cpu_target=generic
if [[ "${SHADOW6_NATIVE:-0}" == 1 ]]; then
    cpu_target=native
fi
link_flags=""
case "$(uname -s)" in
    Darwin) cpu_flag="" ;;
    *) cpu_flag=" -C target-cpu=${cpu_target}"; link_flags=" -C link-arg=-Wl,-z,relro,-z,now -C link-arg=-Wl,-z,noexecstack" ;;
esac
export RUSTFLAGS="${RUSTFLAGS:-}${cpu_flag}${link_flags}"
features=()
case "${CROSED_LEVEL:-0}" in
    0) ;;
    1) features+=(crosed) ;;
    2|3|4|5) features+=("crosed-level-${CROSED_LEVEL}") ;;
    *) printf '%s\n' 'CROSED_LEVEL must be 0..5' >&2; exit 2 ;;
esac
[[ "${APP_TRANSPORT:-0}" == 1 ]] && features+=(app-transport)
[[ "${QUBES_ISOLATION:-0}" == 1 ]] && features+=(qubes-isolation)
build_args=(--release --locked)
if ((${#features[@]})); then
    joined_features=$(IFS=,; printf '%s' "${features[*]}")
    build_args+=(--features "$joined_features")
fi
cargo build "${build_args[@]}"
install -m 0755 target/release/shadow6-rust shadow6-rust
printf '[+] Built Core-Rust: shadow6-rust (target-cpu=%s)\n' "$cpu_target"
