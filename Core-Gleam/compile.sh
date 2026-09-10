#!/usr/bin/env bash
set -euo pipefail

core_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
root=$(dirname -- "$core_dir")
tool_root="$root/.tools/gleam"
export PATH="$tool_root/bin:$tool_root/otp/bin:$PATH"
export ERL_FLAGS='+S 2:2 +SDcpu 1 +SDio 1'
export ERL_COMPILER_OPTIONS=deterministic

command -v gleam musl-gcc ar perl make >/dev/null
test -f "$tool_root/downloads/otp.tar.gz"
test -f "$tool_root/musl/lib/libsodium.a"

level=${CROSED_LEVEL:-0}
app=${APP_TRANSPORT:-0}
qubes=${QUBES_ISOLATION:-0}
case "$level:$app:$qubes" in
    0:0:0|5:1:1) ;;
    *) echo 'Core-Gleam supports only default L0 or complete L5 builds' >&2; exit 2 ;;
esac

cd "$core_dir"
gleam build --target erlang
build_module="$core_dir/build/generated/shadow6_build.erl"
mkdir -p "$(dirname -- "$build_module")"
python3 "$core_dir/tools/write_build_module.py" "$build_module" "$level" "$app" "$qubes"
"$tool_root/otp/bin/erlc" +deterministic -Werror \
  -o "$core_dir/build/dev/erlang/shadow6_gleam/ebin" "$build_module"
make nif ERL="$tool_root/otp/bin/erl"
ar d "$core_dir/obj/libshadow6_sodium.a" shadow6_rom.o 2>/dev/null || true

static_source="$tool_root/otp-static-src"
static_prefix="$tool_root/otp-static"
if [[ ! -f "$static_source/.shadow6-extracted" ]]; then
    rm -rf -- "$static_source"
    mkdir -p "$static_source"
    tar -xzf "$tool_root/downloads/otp.tar.gz" --strip-components=1 -C "$static_source"
    : >"$static_source/.shadow6-extracted"
fi

target_make=$(find "$static_source/erts/emulator" -path '*-linux-*/Makefile' -print -quit 2>/dev/null || true)
config_stamp="$static_source/.shadow6-static-config-v2"
if [[ ! -f "$config_stamp" || ! -f "$static_source/erts/config.status" || -z "$target_make" ]] || \
   ! grep -q 'libshadow6_rom' "$target_make" || ! grep -q 'libcrypto.a' "$target_make"; then
    cd "$static_source"
    CC=musl-gcc CFLAGS='-O2 -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2' \
      LDFLAGS='-pie -static-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack' \
      LIBS="$tool_root/musl/lib/libsodium.a $tool_root/musl/lib/libcrypto.a -pthread -ldl" \
      ./configure --prefix="$static_prefix" --disable-jit --without-javac --without-wx \
        --without-termcap \
        --without-odbc --without-debugger --without-observer --without-et \
        --without-megaco --without-diameter --without-snmp --without-ssl \
        --enable-static-nifs="$core_dir/obj/libshadow6_sodium.a:shadow6_sodium,$core_dir/obj/libshadow6_rom.a:shadow6_rom"
    : >"$config_stamp"
fi

python3 "$core_dir/tools/prepare_embedded_otp.py" \
  --otp-source "$static_source" --otp-root "$tool_root/otp" \
  --core-ebin "$core_dir/build/dev/erlang/shadow6_gleam/ebin"
musl-gcc -O2 -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
  -I"$tool_root/otp/lib/erlang/usr/include" -c "$core_dir/obj/shadow6_rom.c" \
  -o "$core_dir/obj/shadow6_rom.o"
ar rcs "$core_dir/obj/libshadow6_rom.a" "$core_dir/obj/shadow6_rom.o"

target_make=$(find "$static_source/erts/emulator" -path '*-linux-*/Makefile' -print -quit)
test -n "$target_make"
erts_target=$(basename -- "$(dirname -- "$target_make")")
ERL_TOP="$static_source" make -C "$static_source/erts/emulator" TARGET="$erts_target" -j1 opt
beam=$(find "$static_source/bin" -name beam.smp -type f -print -quit)
test -n "$beam" -a -x "$beam"
install -m 0755 "$beam" "$core_dir/shadow6-gleam"
strip --strip-debug "$core_dir/shadow6-gleam"
python3 - "$core_dir/shadow6-gleam" "$root" <<'PY'
import pathlib, sys
path, prefix = pathlib.Path(sys.argv[1]), sys.argv[2].encode()
data = path.read_bytes()
replacement = b"/usr/src/shadow6".ljust(len(prefix), b"_")
if len(replacement) != len(prefix):
    raise SystemExit("source prefix replacement is longer than source path")
path.write_bytes(data.replace(prefix, replacement))
PY
