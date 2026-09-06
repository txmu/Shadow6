#!/usr/bin/env bash
set -euo pipefail

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$project_dir"

printf '%s\n' '[1/4] Building all configured components'
make build
printf '%s\n' '[2/4] Running unit and integration tests'
make test
printf '%s\n' '[3/4] Running static checks'
make check
printf '%s\n' '[4/4] Running offline binary/source audit'
make audit
printf '%s\n' 'Shadow6 verification completed successfully.'
