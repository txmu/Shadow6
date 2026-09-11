#!/usr/bin/env bash
set -euo pipefail

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
parent_dir=$(dirname -- "$project_dir")
project_name=$(basename -- "$project_dir")
package_tmp_root=${SHADOW6_PACKAGE_TMPDIR:-$parent_dir}
package_tmp=$(mktemp -d "$package_tmp_root/.${project_name}.package.XXXXXX")
package_output_dir=${SHADOW6_PACKAGE_OUTPUT_DIR:-$parent_dir}
tar_tmp="$package_tmp/$project_name.tar.gz"
zip_tmp="$package_tmp/$project_name.zip"
zip_stage="$package_tmp/zip-stage"
apk_source="$project_name/Android/app/build/outputs/apk/debug/app-debug.apk"
apk_archive_path="$project_name/Android/dist/shadow6-android-debug.apk"
apk_included=0
cleanup() {
    rm -rf -- "$package_tmp"
}
trap cleanup EXIT

cd "$parent_dir"
if [[ -f "$apk_source" ]]; then
    mkdir -p "$project_name/Android/dist"
    install -m 0644 "$apk_source" "$apk_archive_path"
    apk_included=1
fi
tar --exclude="$project_name/.venv" \
	--exclude="$project_name/.git" \
    --exclude="$project_name/.tools" \
    --exclude='*/.android-toolchain' \
    --exclude='*/.tmp' \
    --exclude="$project_name/.runtime" \
    --exclude="$project_name/Shadow6.tar.gz" \
    --exclude="$project_name/Shadow6.zip" \
    --exclude="$project_name/Core-Rust/target" \
    --exclude="$project_name/Core-Gleam/build" \
    --exclude="$project_name/Core-Gleam/obj" \
    --exclude="$project_name/Core-Zig/.zig-cache" \
    --exclude="$project_name/Core-Zig/zig-out" \
    --exclude="$project_name/Core-Ada/obj" \
    --exclude="$project_name/Core-Nim/obj" \
    --exclude="$project_name/Core-Ada/test_cells" \
    --exclude="$project_name/.zig-cache" \
    --exclude="$project_name/Android/.gradle" \
    --exclude="$project_name/Android/build" \
    --exclude="$project_name/Android/app/build" \
    --exclude='*/__pycache__' \
    --exclude='*/erl_crash.dump' \
    --exclude="$project_name/Auto-Orchestrator/generated" \
    --exclude="$project_name/Auto-Orchestrator/generated-rust" \
    -czpf "$tar_tmp" "$project_name"
if [[ "$apk_included" == 1 ]]; then
    tar -tzf "$tar_tmp" "$apk_archive_path" >/dev/null || {
        echo "APK output is missing from the temporary tar archive: $apk_archive_path" >&2
        exit 1
    }
fi

mkdir -p "$zip_stage"
cd "$parent_dir"
tar --exclude="$project_name/.venv" \
	--exclude="$project_name/.git" \
    --exclude="$project_name/.tools" \
    --exclude='*/.android-toolchain' \
    --exclude='*/.tmp' \
    --exclude="$project_name/.runtime" \
    --exclude="$project_name/Shadow6.tar.gz" \
    --exclude="$project_name/Shadow6.zip" \
    --exclude="$project_name/Core-Rust/target" \
    --exclude="$project_name/Core-Gleam/build" \
    --exclude="$project_name/Core-Gleam/obj" \
    --exclude="$project_name/Core-Zig/.zig-cache" \
    --exclude="$project_name/Core-Zig/zig-out" \
    --exclude="$project_name/Core-Zig/shadow6-zig" \
    --exclude="$project_name/Core-Ada/obj" \
    --exclude="$project_name/Core-Nim/obj" \
    --exclude="$project_name/Core-Hare/shadow6-hare" \
    --exclude="$project_name/Core-Carp/shadow6-carp" \
    --exclude="$project_name/Core-Carp/build" \
    --exclude="$project_name/Core-Ada/test_cells" \
    --exclude="$project_name/Core-Ada/shadow6-ada" \
    --exclude="$project_name/Core-Ada/shadow6-ada-crosed" \
    --exclude="$project_name/.zig-cache" \
    --exclude="$project_name/Android/.gradle" \
    --exclude="$project_name/Android/build" \
    --exclude="$project_name/Android/app/build" \
    --exclude="$project_name/Android/app/src/main/jniLibs" \
    --exclude="$project_name/Android/dist" \
    --exclude='*/__pycache__' \
    --exclude='*/erl_crash.dump' \
    --exclude="$project_name/Auto-Orchestrator/generated" \
    --exclude="$project_name/Auto-Orchestrator/generated-rust" \
    --exclude="$project_name/Core-Go/shadow6-go" \
    --exclude="$project_name/Core-Go/shadow6-go-crosed" \
    --exclude="$project_name/Core-Go/shadow6-go-public6" \
    --exclude="$project_name/Core-Rust/shadow6-rust" \
    --exclude="$project_name/Core-Rust/shadow6-rust-crosed" \
    --exclude="$project_name/Core-Rust/shadow6-rust-public6" \
    --exclude="$project_name/Core-Gleam/shadow6-gleam" \
    --exclude="$project_name/Core-Gleam/shadow6-gleam-crosed" \
    --exclude="$project_name/Core-Cpp/shadow6-cpp" \
    --exclude="$project_name/Guard/shadow6-guard" \
    --exclude="$project_name/Gate/shadow6-gate" \
    --exclude="$project_name/C11Relay/bridge_relay" \
    --exclude="$project_name/C11Relay/c11relay_test" \
    --exclude="$project_name/config.mk" \
    -cf - "$project_name" | tar -xf - -C "$zip_stage"

# ZIP is a text-only source exchange artifact. Strict UTF-8 text files receive
# the .txt suffix; PNG/APK/ELF/archive/font and every other binary are removed
# from the staging tree. The source tree and tar archive are never renamed.
"$project_dir/.venv/bin/python" "$project_dir/Tools/prepare_text_zip.py" "$zip_stage/$project_name"
cd "$zip_stage"
zip -rq -X "$zip_tmp" "$project_name"

mv -f -- "$tar_tmp" "$package_output_dir/$project_name.tar.gz"
mv -f -- "$zip_tmp" "$package_output_dir/$project_name.zip"
rm -rf -- "$package_tmp"
trap - EXIT
printf 'Created %s and %s\n' "$package_output_dir/$project_name.tar.gz" "$package_output_dir/$project_name.zip"
