#!/usr/bin/env bash
set -euo pipefail
test -x ./shadow6-cpp
work=$(mktemp -d /tmp/shadow6-cpp-tests.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
: "${CXX:=c++}"
flags=(-std=c++20 -O1 -g -fno-exceptions -fno-rtti -Wall -Wextra -pthread)
read -r -a cppflags <<< "${CPPFLAGS:-}"
read -r -a ldflags <<< "${LDFLAGS:-}"
if [[ ${SHADOW6_CPP_SANITIZE:-0} == 1 ]]; then
    flags+=('-fsanitize=address,undefined' -fno-omit-frame-pointer)
    "$CXX" "${flags[@]}" "${cppflags[@]}" src/main.cpp "${ldflags[@]}" -lssl -lcrypto -o "$work/shadow6-cpp"
    export SHADOW6_CPP_BINARY="$work/shadow6-cpp"
fi
"$CXX" "${flags[@]}" "${cppflags[@]}" tests.cpp "${ldflags[@]}" -lssl -lcrypto -o "$work/probe"
"$work/probe"
export SHADOW6_CPP_PROBE="$work/probe"
python=python3
[[ ! -x ../.venv/bin/python ]] || python=../.venv/bin/python
"$python" test_core.py
