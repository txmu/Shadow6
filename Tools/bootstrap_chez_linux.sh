#!/usr/bin/env bash
# CI-only native Chez runtime, shared by the Idris producer and consumer jobs.
set -euo pipefail
chez_source=$(mktemp -d "${RUNNER_TEMP:-/tmp}/shadow6-chez.XXXXXX")
trap 'rm -rf -- "$chez_source"' EXIT
git clone --depth 1 --branch v10.0.0 https://github.com/cisco/ChezScheme.git "$chez_source"
test "$(git -C "$chez_source" rev-parse HEAD)" = 253230f7dfbb4fe777277d6bbf93f39f9567f086
git -C "$chez_source" submodule update --init --recursive --depth 1
cd "$chez_source"
./configure --threads --disable-x11 --disable-curses --installprefix=/usr/local
make -j2
sudo make install
# Idris launchers resolve chezscheme, while upstream installs scheme.
printf '#!/bin/sh\nexec /usr/local/bin/scheme "$@"\n' | sudo tee /usr/local/bin/chezscheme > /dev/null
sudo chmod 0755 /usr/local/bin/chezscheme
/usr/local/bin/chezscheme --version
