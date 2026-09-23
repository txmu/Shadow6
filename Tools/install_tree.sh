#!/usr/bin/env bash
# Install the Shadow6 tree that installed entry points inspect and drive.
#
# "make install" places executables in <prefix>/bin and their shared modules in
# <prefix>/share/shadow6/{modules,assistants}. Those entry points resolve the
# Shadow6 tree through <prefix>/share/shadow6/tree, so the tree has to exist for
# the deployment doctor, the infrastructure observation, the Control Center and
# the component catalogs to report anything but "missing". This copies the
# repository tree, including built Core binaries, excluding dependency
# environments, caches and vcs metadata.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: install_tree.sh DESTINATION" >&2
    exit 2
fi

destination=$1
if [[ -z "$destination" || "$destination" != /* ]]; then
    echo "install_tree.sh requires an absolute destination path" >&2
    exit 2
fi

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
project_name=$(basename -- "$project_dir")
destination=${destination%/}

case "$destination" in
    "$project_dir"|"$project_dir"/*)
        echo "refusing to install the tree into itself: $destination" >&2
        exit 2
        ;;
esac

# Never copy dependency environments, caches or generated Android/Gradle output
# into an installation prefix. Build products that the doctor verifies, such as
# the Core binaries and the Idris runtime directory, are intentionally kept.
excludes=(
    "$project_name/.git"
    "$project_name/.venv"
    "$project_name/.venv-ft"
    "$project_name/.tools"
    "$project_name/.tmp"
    "$project_name/.runtime"
    "$project_name/.android-toolchain"
    "$project_name/work"
    "$project_name/Shadow6.tar.gz"
    "$project_name/Shadow6.zip"
    "$project_name/config.mk"
    "$project_name/Core-Rust/target"
    "$project_name/Core-Gleam/build"
    "$project_name/Core-Gleam/obj"
    "$project_name/Core-Zig/.zig-cache"
    "$project_name/Core-Zig/zig-out"
    "$project_name/Core-Ada/obj"
    "$project_name/Core-Nim/obj"
    "$project_name/Core-Pony/obj"
    "$project_name/Core-Carp/build"
    "$project_name/Android/.gradle"
    "$project_name/Android/build"
    "$project_name/Android/app/build"
    "$project_name/Android/app/src/main/jniLibs"
)

tar_arguments=()
for pattern in "${excludes[@]}"; do
    tar_arguments+=(--exclude="$pattern")
done
tar_arguments+=(--exclude='*/.tmp' --exclude='*/__pycache__' --exclude='*/erl_crash.dump' --exclude='*/.zig-cache')

# Replacing the tree deletes the destination's previous contents, so refuse a
# directory that is neither empty nor recognisably a Shadow6 tree. Without this
# guard a mistyped prefix such as /home or /usr/local would be cleared.
marker="$destination/.shadow6-tree"
if [[ -d "$destination" ]] && [[ -n "$(ls -A "$destination" 2>/dev/null)" ]]; then
    if [[ ! -f "$destination/Makefile" && ! -f "$destination/.shadow6-tree" ]]; then
        echo "refusing to replace $destination: it is not an installed Shadow6 tree" >&2
        echo "remove it explicitly if that is really intended" >&2
        exit 2
    fi
fi

mkdir -p "$destination"
cd "$(dirname -- "$project_dir")"
# Copy through a tar pipeline so hard links, symbolic links and Unix modes are
# preserved exactly; the tree is replaced wholesale to avoid stale components.
find "$destination" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
printf 'shadow6-installed-tree\n' > "$marker"
# Normalize modes on extraction so a permissive checkout umask (for example
# group-writable build outputs) can never install binaries the deployment
# doctor would reject (it refuses any Core binary with mode & 0o022 set).
u_mask=$(umask)
umask "$u_mask"
tar "${tar_arguments[@]}" -cf - "$project_name" | tar --mode=go-w -xf - -C "$destination" --strip-components=1
# Enforce non-writable Core binaries explicitly; extraction has already
# preserved their execute bits while clearing group/other write.
find "$destination" \
    \( -name "shadow6-*" -o -name "bridge_relay" -o -name "c11relay_test" \) \
    -type f -exec chmod a-w {} +

staged_makefile="$destination/Makefile"
if [[ ! -f "$staged_makefile" ]]; then
    echo "installed tree is incomplete: $staged_makefile is missing" >&2
    exit 1
fi
printf 'Installed Shadow6 tree at %s\n' "$destination"
