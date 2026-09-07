#!/usr/bin/env python3
"""Cross-build Core executables for Android ABIs using an existing SDK/NDK."""
import argparse
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {"arm64-v8a": ("arm64", "aarch64-linux-android"), "x86_64": ("amd64", "x86_64-linux-android")}

def build_jobs() -> int:
    raw = os.environ.get("SHADOW6_ANDROID_BUILD_JOBS", "1")
    try:
        jobs = int(raw)
    except ValueError as exc:
        raise SystemExit("SHADOW6_ANDROID_BUILD_JOBS must be an integer") from exc
    if not 1 <= jobs <= 16:
        raise SystemExit("SHADOW6_ANDROID_BUILD_JOBS must be between 1 and 16")
    return jobs

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--abi", choices=TARGETS, action="append")
    args = parser.parse_args()
    jobs = build_jobs()
    ndk = args.ndk.resolve(strict=True)
    prebuilt_root = ndk / "toolchains" / "llvm" / "prebuilt"
    candidates = [path for path in prebuilt_root.iterdir() if path.is_dir() and not path.is_symlink()]
    if len(candidates) != 1:
        raise SystemExit("NDK must contain exactly one non-symlink LLVM toolchain")
    prebuilt = candidates[0]
    abis = args.abi or list(TARGETS)
    for abi in abis:
        goarch, rust_target = TARGETS[abi]
        destination = ROOT / "Android/app/src/main/jniLibs" / abi
        destination.mkdir(parents=True, exist_ok=True)
        api = "28"
        clang = prebuilt / "bin" / f"{rust_target}{api}-clang"
        if not clang.is_file() or clang.is_symlink():
            raise SystemExit(f"NDK compiler is unavailable: {clang}")
        ldc = shutil.which("ldc2")
        if ldc:
            d_sources = [str(p) for p in (ROOT / "Core-D/src").glob("*.d")]
            d_cmd = [ldc, "-betterC", "-O2", "-release", "-I", str(ROOT / "Core-D/src"), "-mtriple=" + ("aarch64-linux-android" if abi == "arm64-v8a" else "x86_64-linux-android"), "-of=" + str(destination / "libshadow6_d.so")] + d_sources + [str(ROOT / "Core-D/src/platform.c"), "-L-lcrypto", "-L-lssl", "-L-lsodium"]
            subprocess.run(d_cmd, cwd=ROOT, env=dict(os.environ, CC=str(clang)), check=True)
        nim = shutil.which("nim")
        if nim:
            # Nim's C backend uses the selected NDK clang and emits the same
            # JNI shared-library contract as the other bundled cores.
            nim_cpu = "arm64" if abi == "arm64-v8a" else "amd64"
            nim_cmd = [nim, "c", "--os:android", f"--cpu:{nim_cpu}", "--mm:arc",
                       "--threads:on", "-d:release", "--checks:on", "--assertions:on",
                       "--stackTrace:on", "--lineTrace:on", "--passC:-fPIC",
                       f"--passC:--target={rust_target}{api}", f"--cc:clang",
                       "--passL:-fPIC", "--passL:-shared", "--passL:-lcrypto",
                       "--passL:-landroid", "--passL:-llog",
                       f"--nimcache:{ROOT / '.tmp/nim-android-cache' / abi}",
                       f"-o:{destination / 'libshadow6_nim.so'}",
                       str(ROOT / "Core-Nim/src/shadow6_nim.nim")]
            subprocess.run(nim_cmd, cwd=ROOT, env=dict(os.environ, PATH=str(prebuilt / "bin") + os.pathsep + os.environ.get("PATH", "")), check=True)
        # Android's Go runtime uses the NDK linker even with no application
        # C bindings; keep the compiler fixed to the selected API/ABI.
        env = dict(
            os.environ, GOOS="android", GOARCH=goarch, CGO_ENABLED="1",
            CC=str(clang), CXX=str(clang),
            GOMAXPROCS=str(jobs),
            GOCACHE=str(ROOT / ".tmp/go-build-android"),
        )
        subprocess.run(["go", "build", "-buildvcs=false", "-trimpath", "-buildmode=pie", "-o", str(destination / "libshadow6_go.so"), "."], cwd=ROOT / "Core-Go", env=env, check=True)
        subprocess.run(["go", "build", "-buildvcs=false", "-trimpath", "-buildmode=pie", "-o", str(destination / "libshadow6_gate.so"), "."], cwd=ROOT / "Gate", env=env, check=True)
        archiver = prebuilt / "bin" / f"llvm-ar"
        if not clang.is_file() or clang.is_symlink() or not archiver.is_file():
            raise SystemExit(f"NDK compiler is unavailable: {clang}")
        cargo_env = dict(
            os.environ,
            CARGO_TARGET_DIR=str(ROOT / ".tmp/android-rust-target"),
            CC=str(clang),
            AR=str(archiver),
            **{f"CC_{rust_target.replace('-', '_')}": str(clang)},
            **{f"AR_{rust_target.replace('-', '_')}": str(archiver)},
            **{f"CARGO_TARGET_{rust_target.replace('-', '_').upper()}_LINKER": str(clang)},
        )
        subprocess.run(["cargo", "build", "--jobs", str(jobs), "--release", "--locked", "--target", rust_target], cwd=ROOT / "Core-Rust", env=cargo_env, check=True)
        shutil.copy2(ROOT / ".tmp/android-rust-target" / rust_target / "release/shadow6-rust", destination / "libshadow6_rust.so")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
