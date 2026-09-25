#!/usr/bin/env bash
set -euo pipefail

test_dir=$(mktemp -d /tmp/shadow6-relay-tests.XXXXXX)
trap 'rm -f c11relay_test; rm -rf "$test_dir"' EXIT

"${CC:-cc}" -std=c11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
    -Wall -Wextra -Wpedantic c11relay.c -o c11relay_test
./c11relay_test --run-tests
"${CC:-cc}" -std=c11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
    -Wall -Wextra -Wpedantic test_batch.c -o "$test_dir/test_batch"
"$test_dir/test_batch"
python3 test_relay.py ./c11relay_test
