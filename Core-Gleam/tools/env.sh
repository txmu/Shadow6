#!/usr/bin/env bash
# Source this file from bash to activate the repository-local toolchain.
shadow6_gleam_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
export PATH="$shadow6_gleam_root/.tools/gleam/bin:$shadow6_gleam_root/.tools/gleam/otp/bin:$PATH"
unset shadow6_gleam_root
