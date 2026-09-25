#!/usr/bin/env bash
# Explicit CI cross-build and execution; QEMU rates are not native throughput.
set -euo pipefail
case "${1:-}" in
    riscv64) goarch=riscv64; emulator=qemu-riscv64-static; triple=riscv64-linux-gnu ;;
    loongarch64) goarch=loong64; emulator=qemu-loongarch64-static; triple=loongarch64-linux-gnu ;;
    mips64) goarch=mips64le; emulator=qemu-mips64el-static; triple=mips64el-linux-gnuabi64 ;;
    s390x64) goarch=s390x; emulator=qemu-s390x-static; triple=s390x-linux-gnu ;;
    *) echo 'expected riscv64, loongarch64, mips64, or s390x64' >&2; exit 2 ;;
esac
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
output=${2:?absolute output directory required}
case "$output" in /*) ;; *) exit 2 ;; esac
mkdir -p "$output"
command -v "$emulator"
export GOOS=linux GOARCH="$goarch" CGO_ENABLED=0
export QEMU_LD_PREFIX="/usr/$triple"
build_flags=(-buildvcs=false -trimpath -ldflags='-s -w -buildid=')
# Go does not implement PIE for MIPS64; the other Linux targets retain it.
if [[ "$goarch" != mips64le ]]; then build_flags+=(-buildmode=pie); fi
for component in Core-Go Gate Guard; do
    case "$component" in Core-Go) name=go ;; Gate) name=gate ;; Guard) name=guard ;; esac
    (
        cd "$root/$component"
        go build "${build_flags[@]}" -o "$output/shadow6-$name" .
        # binfmt is enabled by the CI setup so tests' child processes also
        # execute as the target architecture, including FIFO-open regressions.
        go test -buildvcs=false -count=1 -timeout=10m -exec "$emulator" ./...
    )
done
"$emulator" "$output/shadow6-go" --feature-report > "$output/go-l0.json"
"$emulator" "$output/shadow6-gate" --feature-report > "$output/gate.json"
"$emulator" "$output/shadow6-guard" --help > "$output/guard-help.txt" 2>&1
(
    cd "$root/Core-Go"
    go build "${build_flags[@]}" \
        -tags 'crosed,crosed_l5,app_transport' -o "$output/shadow6-go-crosed" .
)
"$emulator" "$output/shadow6-go-crosed" --feature-report > "$output/go-l5.json"
python3 - "$output" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
for level in (0, 5):
    report = json.loads((root / f"go-l{level}.json").read_text())
    assert report["crosed_max_level"] == level, report
assert json.loads((root / "gate.json").read_text())["enabled_by_default"] is False
PY
if [[ -n "$triple" ]]; then
    cc="$triple-gcc"
    if [[ "$goarch" == loong64 ]]; then cc="$triple-gcc-14"; fi
    (cd "$root/C11Relay" && CC="$cc" bash ./compile.sh)
    mv "$root/C11Relay/bridge_relay" "$output/bridge_relay"
    "$emulator" -L "/usr/$triple" "$output/bridge_relay" --run-tests
    "$cc" -std=c11 -O2 -pthread "$root/C11Relay/test_batch.c" -o "$output/relay-batch-test"
    "$emulator" -L "/usr/$triple" "$output/relay-batch-test"
    # Python's test fixture starts the target executable repeatedly. Use an
    # explicit sysroot runner, retaining the production linker's hardening.
    printf '#!/usr/bin/env bash\nexec %q -L %q %q "$@"\n' \
        "$emulator" "/usr/$triple" "$output/bridge_relay" > "$output/relay-runner"
    chmod 0755 "$output/relay-runner"
    python3 "$root/C11Relay/test_relay.py" "$output/relay-runner"
fi
{
    printf 'platform=linux-%s\ngoarch=%s\nemulator=%s\n' "$1" "$goarch" "$emulator"
    echo 'compiled-and-tested=go,gate,guard'
    echo 'relay=compiled-and-tested'
    echo 'performance=not measured; QEMU correctness does not establish native Gbps'
    if [[ "$goarch" == mips64le ]]; then echo 'go-pie=unavailable: Go MIPS64 backend does not implement PIE'; fi
    echo 'other-cores=not yet covered by this cross-toolchain matrix'
} > "$output/support.txt"
