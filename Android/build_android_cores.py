#!/usr/bin/env python3
"""Cross-build Core executables for Android ABIs using an existing SDK/NDK."""
import argparse
import os
import shutil
import shlex
import subprocess
import tempfile
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


def build_nim(abi, target, prebuilt, crypto, rtc, destination, jobs):
    nim = shutil.which("nim")
    if not nim:
        raise SystemExit("nim is required for Android Core-Nim")
    for prefix, names in (
        (crypto, ("include/openssl/evp.h", "lib/libssl.a", "lib/libcrypto.a")),
        (rtc, ("include/rtc/rtc.h", "lib/libdatachannel.a", "lib/libjuice.a", "lib/libusrsctp.a")),
    ):
        for name in names:
            if not (prefix / name).is_file():
                raise SystemExit(f"Missing Android {abi} dependency: {prefix / name}; run crypto/RTC builders first")
    clang = prebuilt / "bin" / (target + "28-clang")
    linker = prebuilt / "bin" / (target + "28-clang++")
    if not clang.is_file() or not linker.is_file():
        raise SystemExit(f"NDK C/C++ toolchain is unavailable for {abi}")
    # Nim generates C, but libdatachannel needs the NDK C++ runtime at link time.
    # CoreRuntime starts this as a process: it must be a PIE, not a JNI DSO.
    command = [nim, "c", "--app:console", "--os:android",
               "--cpu:" + ("arm64" if abi == "arm64-v8a" else "amd64"),
               "--mm:arc", "--threads:on", "-d:release", "--checks:on", "--assertions:on",
               "--stackTrace:on", "--lineTrace:on", "--parallelBuild:" + str(jobs),
               "--cc:clang", "--clang.exe:" + str(clang), "--clang.linkerexe:" + str(linker),
               "--passC:-fPIE", "--passC:-DRTC_STATIC", "--passC:-DRTC_ENABLE_MEDIA=0",
               "--passC:-DRTC_ENABLE_WEBSOCKET=1"]
    for prefix in (crypto, rtc):
        command += ["--passC:-I" + shlex.quote(str(prefix / "include")),
                    "--passL:-L" + shlex.quote(str(prefix / "lib"))]
    # Android exposes pthreads through libc and intentionally has no separate
    # libpthread. Nim's --threads:on target configuration still appends
    # -lpthread, so provide a temporary empty archive to satisfy that legacy
    # name; the actual pthread symbols continue to resolve from libc.
    pthread_compat = tempfile.TemporaryDirectory(prefix="shadow6-android-pthread-")
    (Path(pthread_compat.name) / "libpthread.a").write_bytes(b"!<arch>\n")
    command += ["--passL:-L" + shlex.quote(pthread_compat.name),
                "--passL:-pie", "--passL:-static-libstdc++",
                "--passL:-Wl,-z,relro,-z,now,-z,max-page-size=16384",
                "--passL:-Wl,--start-group", "--passL:-ldatachannel", "--passL:-lusrsctp",
                "--passL:-ljuice", "--passL:-lssl", "--passL:-lcrypto", "--passL:-Wl,--end-group",
                "--passL:-pthread", "--passL:-ldl", "--passL:-lm", "--passL:-llog",
                "--nimcache:" + str(ROOT / '.tmp/nim-android-cache' / abi),
                "-o:" + str(destination / 'libshadow6_nim.so'),
                str(ROOT / 'Core-Nim/src/shadow6_nim.nim')]
    try:
        subprocess.run(command, cwd=ROOT, check=True)
    finally:
        pthread_compat.cleanup()

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--abi", choices=TARGETS, action="append")
    parser.add_argument("--crypto-prefix", type=Path,
                        default=ROOT / ".tmp/android-crypto")
    parser.add_argument("--rtc-prefix", type=Path, default=ROOT / ".tmp/android-rtc")
    parser.add_argument("--core-d-only", action="store_true",
                        help="Build only Core-D for targeted verification")
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
        crypto = args.crypto_prefix.resolve() / abi
        ldc = shutil.which("ldc2")
        if not ldc:
            raise SystemExit("ldc2 is required for Android Core-D")
        for required in ("include/openssl/ssl.h", "lib/libssl.a", "lib/libcrypto.a", "lib/libsodium.a"):
            if not (crypto / required).is_file():
                raise SystemExit(f"Missing Android {abi} dependency: {crypto / required}; run Android/build_android_crypto.py first")
        # Android launches these .so-named files as executables, not JNI libraries.
        # Compile C with NDK clang; LDC only emits the BetterC object.
        with tempfile.TemporaryDirectory(prefix="shadow6-d-android-") as temporary:
            work = Path(temporary)
            objects = []
            for name in ("platform", "launcher"):
                obj = work / (name + ".o")
                subprocess.run([str(clang), "-O2", "-fPIE", "-I" + str(crypto / "include"),
                                "-c", str(ROOT / "Core-D/src" / (name + ".c")),
                                "-o", str(obj)], check=True)
                objects.append(str(obj))
            dobj = work / "core.o"
            subprocess.run([ldc, "-betterC", "-O2", "-release", "-c", "-singleobj",
                            "-relocation-model=pic", "-mtriple=" + rust_target,
                            "-I=" + str(ROOT / "Core-D/src"), "-of=" + str(dobj)] +
                           [str(p) for p in sorted((ROOT / "Core-D/src").glob("*.d"))], check=True)
            subprocess.run([str(clang), "-pie", "-Wl,-z,max-page-size=16384",
                            "-o", str(destination / "libshadow6_d.so"), str(dobj)] + objects +
                           [str(crypto / "lib" / name) for name in ("libssl.a", "libcrypto.a", "libsodium.a")] +
                           ["-ldl", "-pthread"], check=True)
        if args.core_d_only:
            continue
        build_nim(abi, rust_target, prebuilt, crypto, args.rtc_prefix.resolve() / abi,
                  destination, jobs)
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
