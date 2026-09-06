#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export TZ=Etc/UTC

# Shadow6 Debian 13 headless Android build bootstrap.
PROJECT_DIR=${SHADOW6_PROJECT_DIR:-"$HOME/Shadow6"}
TOOLCHAIN="$PROJECT_DIR/.android-toolchain"
SDK_ROOT="$TOOLCHAIN/sdk"
NDK_ROOT="$TOOLCHAIN/ndk/android-ndk-r28b"
GRADLE_ROOT="$TOOLCHAIN/gradle/gradle-9.4.1"
JDK_ROOT=${JAVA_HOME:-}

if [[ ! -d "$PROJECT_DIR/Android" || ! -f "$PROJECT_DIR/Makefile" ]]; then
  echo "Shadow6 source tree not found at $PROJECT_DIR" >&2
  echo "Set SHADOW6_PROJECT_DIR to the extracted repository path." >&2
  exit 1
fi

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  apt_cmd=()
else
  sudo -n true 2>/dev/null || {
    echo 'Unattended mode requires root or passwordless sudo (sudo -n).' >&2
    exit 1
  }
  apt_cmd=(sudo -n)
fi
"${apt_cmd[@]}" apt-get update
"${apt_cmd[@]}" apt-get install -y ca-certificates curl unzip tar zip util-linux build-essential python3 python3-venv default-jdk golang

if [[ -z "$JDK_ROOT" ]]; then
  mapfile -t bundled_jdks < <(find "$TOOLCHAIN/jdk" -mindepth 2 -maxdepth 2 -type f -path '*/bin/java' -print 2>/dev/null)
  if [[ ${#bundled_jdks[@]} -eq 1 ]]; then
    JDK_ROOT=$(dirname "$(dirname "${bundled_jdks[0]}")")
  else
    javac_path=$(command -v javac || true)
    [[ -n "$javac_path" ]] && JDK_ROOT=$(dirname "$(dirname "$(readlink -f "$javac_path")")")
  fi
fi
if [[ ! -x "$JDK_ROOT/bin/java" ]]; then
  echo 'A complete JDK 17 is required; set JAVA_HOME to its absolute path.' >&2
  exit 1
fi
java_major=$("$JDK_ROOT/bin/java" -XshowSettings:properties -version 2>&1 | awk -F'= ' '/java.specification.version/ { print $2; exit }')
if [[ "$java_major" != 17 ]]; then
  printf 'JDK 17 is required, but JAVA_HOME resolves to Java %s at %s\n' "$java_major" "$JDK_ROOT" >&2
  exit 1
fi

mkdir -p "$TOOLCHAIN" "$SDK_ROOT/cmdline-tools" "$TOOLCHAIN/ndk" "$TOOLCHAIN/gradle"

# A fresh Android toolchain and dependency cache need several GiB.  Refuse
# before downloads when the host cannot hold them; filling the root filesystem
# can make sshd and the whole machine unreliable.
if [[ ! -x "$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" || ! -d "$NDK_ROOT" || ! -x "$GRADLE_ROOT/bin/gradle" ]]; then
  free_kib=$(df -Pk "$PROJECT_DIR" | awk 'NR == 2 { print $4 }')
  if [[ ! "$free_kib" =~ ^[0-9]+$ || "$free_kib" -lt 8388608 ]]; then
    echo 'A fresh Android setup requires at least 8 GiB free on the project filesystem.' >&2
    echo 'Free disk space or place SHADOW6_PROJECT_DIR on a larger filesystem.' >&2
    exit 1
  fi
fi

if [[ ! -x "$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" ]]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  curl -fL --retry 3 -o "$tmp/cmdline-tools.zip" \
    https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip
  rm -rf "$SDK_ROOT/cmdline-tools/latest" "$tmp/cmdline-tools"
  unzip -q "$tmp/cmdline-tools.zip" -d "$tmp"
  mv "$tmp/cmdline-tools" "$SDK_ROOT/cmdline-tools/latest"
fi

SDKMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
yes | "$SDKMANAGER" --sdk_root="$SDK_ROOT" --licenses >/dev/null || true
"$SDKMANAGER" --sdk_root="$SDK_ROOT" \
  "platform-tools" "platforms;android-36" "build-tools;36.0.0" "ndk;28.2.13676358"

if [[ ! -x "$GRADLE_ROOT/bin/gradle" ]]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  curl -fL --retry 3 -o "$tmp/gradle.zip" \
    https://services.gradle.org/distributions/gradle-9.4.1-bin.zip
  unzip -q "$tmp/gradle.zip" -d "$TOOLCHAIN/gradle"
fi

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
export PATH="$HOME/.cargo/bin:$PATH"
rustup toolchain install stable
rustup component add clippy
rustup target add aarch64-linux-android x86_64-linux-android

# The Android cross-build helper uses only Python's standard library.  Do not
# install the server/ML environment (including PyTorch) just to produce an APK.

export ANDROID_SDK_ROOT="$SDK_ROOT"
export ANDROID_NDK="$NDK_ROOT"
export ANDROID_GRADLE="$GRADLE_ROOT/bin/gradle"
export JAVA_HOME="$JDK_ROOT"
export GRADLE_USER_HOME="$TOOLCHAIN/gradle-home"
export TMPDIR="$PROJECT_DIR/.tmp/android-gradle-tmp"
export GOCACHE="$PROJECT_DIR/.tmp/go-build"
export SHADOW6_ANDROID_BUILD_JOBS=${SHADOW6_ANDROID_BUILD_JOBS:-1}
mkdir -p "$TMPDIR" "$GOCACHE"

cd "$PROJECT_DIR"
make android-apk
apk="$PROJECT_DIR/Android/app/build/outputs/apk/debug/app-debug.apk"
test -f "$apk"
printf 'APK created: %s\n' "$apk"
