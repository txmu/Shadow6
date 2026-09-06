#!/usr/bin/env bash
set -euo pipefail

trap 'rm -f c11relay_test' EXIT

"${CC:-cc}" -std=c11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
    -Wall -Wextra -Wpedantic c11relay.c -o c11relay_test
./c11relay_test --run-tests
python3 test_relay.py ./c11relay_test
