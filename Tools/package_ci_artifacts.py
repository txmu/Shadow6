#!/usr/bin/env python3
"""Group same-run GitHub artifacts by target platform/architecture and bundle them."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile

MAX_FILES = 50_000
MAX_FILE_BYTES = 2 * 1024**3
MAX_TOTAL_BYTES = 8 * 1024**3
ARTIFACT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def target_for(name: str) -> tuple[str, str]:
    if not ARTIFACT_NAME.fullmatch(name):
        raise ValueError(f"unsafe artifact name: {name!r}")
    exact = {
        "shadow6-android-debug": ("android", "multi-abi"),
        "shadow6-linux-release": ("linux", "x86_64"),
        "shadow6-linux-arm64-components": ("linux", "arm64"),
        "shadow6-linux-arm64-network-benchmark": ("linux", "arm64"),
        "shadow6-linux-arm64-named-profile-lifecycle": ("linux", "arm64"),
        "shadow6-linux-iperf-chain": ("linux", "x86_64"),
        "shadow6-linux-network-benchmark": ("linux", "x86_64"),
        "shadow6-linux-native-wan-pcap": ("linux", "x86_64"),
        "shadow6-s6epe-linux-runtime": ("linux", "x86_64"),
        "shadow6-deployment-acceptance": ("reports", "workflow"),
        "shadow6-gleam-x86_64": ("linux", "x86_64"),
        "shadow6-platform-results": ("reports", "workflow"),
        "shadow6-performance-all": ("reports", "workflow"),
        "shadow6-carp-generated": ("build-support", "linux_x86_64"),
        "shadow6-omnios-x86-64-components": ("omnios", "x86_64"),
        "shadow6-dragonflybsd-x86-64-components": ("dragonflybsd", "x86_64"),
        "shadow6-iperf3-omnios-x86-64": ("omnios", "x86_64"),
    }
    if name in exact:
        return exact[name]
    match = re.fullmatch(r"shadow6-linux-musl-(x86_64|aarch64)-components", name)
    if match:
        return "linux-musl", "x86_64" if match.group(1) == "x86_64" else "arm64"
    match = re.fullmatch(r"shadow6-linux-qemu-([A-Za-z0-9_-]{1,32})-components", name)
    if match:
        return "linux-qemu", match.group(1)
    match = re.fullmatch(r"shadow6-gleam-(x86_64|aarch64)", name)
    if match:
        return "linux", "x86_64" if match.group(1) == "x86_64" else "arm64"
    for os_name in ("macos", "windows", "freebsd", "openbsd", "netbsd", "alpine", "dragonflybsd", "omnios"):
        match = re.fullmatch(rf"shadow6-{os_name}-(.+?)-(?:components|release|network-benchmark|iperf3-.+)", name)
        if not match:
            match = re.fullmatch(rf"shadow6-{os_name}-network-benchmark-(.+)", name)
        if match:
            raw = match.group(1)
            arch = {"x86-64": "x86_64", "amd64": "x86_64", "aarch64": "arm64"}.get(raw, raw)
            return os_name, arch
    if name.startswith("shadow6-idris-network-benchmark-"):
        return "reports", "cross-platform"
    idris_target = re.fullmatch(
        r"shadow6-idris-(ubuntu-latest|ubuntu-24\.04-arm|macos-latest)-(X64|ARM64)", name)
    if idris_target:
        runner, runner_arch = idris_target.groups()
        target_platform = "macos" if runner.startswith("macos-") else "linux"
        return target_platform, "x86_64" if runner_arch == "X64" else "arm64"
    legacy_idris = {
        "shadow6-idris-ubuntu-latest": ("linux", "x86_64"),
        "shadow6-idris-ubuntu-24.04-arm": ("linux", "arm64"),
    }
    if name in legacy_idris:
        return legacy_idris[name]
    if name == "shadow6-idris-macos-latest":
        raise ValueError("legacy macOS Idris artifact lacks runner architecture metadata")
    if name.startswith("shadow6-idris-"):
        raise ValueError(f"Idris artifact has no explicit platform/architecture mapping: {name}")
    if name.startswith("shadow6-iperf3-"):
        match = re.fullmatch(r"shadow6-iperf3-(linux|alpine|freebsd|openbsd|netbsd|macos|windows)-(.+)", name)
        if match:
            os_name, arch = match.groups()
            return os_name, {"x86-64": "x86_64", "amd64": "x86_64", "aarch64": "arm64"}.get(arch, arch)
    raise ValueError(f"artifact name has no platform/architecture mapping: {name}")


def _hash_file(path: Path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
        raise ValueError(f"artifact entry is not a bounded regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return info.st_size, digest.hexdigest(), stat.S_IMODE(info.st_mode)


def discover(root: Path):
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("artifact input must be a real directory")
    result = {}
    for entry in sorted(root.iterdir()):
        if not entry.is_dir() or entry.is_symlink():
            continue
        if not ARTIFACT_NAME.fullmatch(entry.name):
            raise ValueError("downloaded artifact directory has an unsafe name")
        result[entry.name] = entry
    if not result:
        raise ValueError("no downloaded GitHub artifacts were found")
    return result


def _add_tree(archive: tarfile.TarFile, root: Path, artifact_name: str, manifest_files: list,
              total_state: list):
    paths = sorted(root.rglob("*"))
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if ".." in PurePosixPath(relative).parts:
            raise ValueError("artifact path traversal")
        if path.is_symlink():
            raise ValueError(f"symbolic link in downloaded artifact is rejected: {artifact_name}/{relative}")
        if path.is_dir():
            continue
        size, digest, mode = _hash_file(path)
        total_state[0] += size
        total_state[1] += 1
        if total_state[0] > MAX_TOTAL_BYTES or total_state[1] > MAX_FILES:
            raise ValueError("combined artifact payload exceeds the bounded package budget")
        arcname = f"{artifact_name}/{relative}"
        info = archive.gettarinfo(str(path), arcname=arcname)
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mode = mode & 0o755
        info.mtime = 0
        if not info.isfile():
            raise ValueError(f"non-regular artifact entry is rejected: {arcname}")
        with path.open("rb") as stream:
            archive.addfile(info, stream)
        manifest_files.append({"artifact": artifact_name, "path": relative,
                               "size": size, "mode": mode, "sha256": digest})


def _platform_readme(platform_name, arch, names, *, full_linux_release):
    files = "\n".join(f"- `{name}`" for name in names)
    install = ("This bundle contains the full Linux release tree and its verified prebuilt installer. "
               "The default script installs to the current user's prefix and does not compile Cores." if full_linux_release else
               "This target bundle stages the platform artifacts under the current user's local Shadow6 artifact directory. "
               "It does not enable services, request administrator rights, or install unrelated system packages.")
    if platform_name == "android":
        install = "This folder contains an Android APK. On a connected, authorized device, install.sh runs `adb install -r`; it does not need device root."
    return (f"# Shadow6 {platform_name}/{arch} artifacts\n\n{install}\n\n"
            "## Included same-run artifacts\n\n" + (files or "- none") +
            "\n\nThe bundle-root manifest binds every included file to the workflow run and source commit. "
            "Only this platform/architecture group is covered by its installer.\n")


def _install_shell(platform_name, arch, commit):
    return f'''#!/bin/sh
set -eu
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$base/install_platform_payload.py" --bundle "$base/artifacts.tar.gz" \\
  --platform {platform_name} --arch {arch} --commit {commit}
'''


def _install_powershell(platform_name, arch, commit):
    return f'''$ErrorActionPreference = 'Stop'
$Base = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Get-Command py -ErrorAction SilentlyContinue
if ($Python) {{ & $Python.Source -3 (Join-Path $Base 'install_platform_payload.py') --bundle (Join-Path $Base 'artifacts.tar.gz') --platform {platform_name} --arch {arch} --commit {commit} }}
else {{ & python (Join-Path $Base 'install_platform_payload.py') --bundle (Join-Path $Base 'artifacts.tar.gz') --platform {platform_name} --arch {arch} --commit {commit} }}
if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}
'''


def package(input_dir: Path, output: Path, *, run_id: str, commit: str):
    if not COMMIT.fullmatch(commit):
        raise ValueError("source commit must be a full 40-character SHA")
    if not run_id or len(run_id) > 32 or not run_id.isascii() or not run_id.isdigit():
        raise ValueError("workflow run ID must be a bounded decimal ID")
    artifacts = discover(input_dir)
    groups = {}
    for name, path in artifacts.items():
        groups.setdefault(target_for(name), []).append((name, path))
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="shadow6-ci-bundle-", dir=output.parent) as temp:
        root = Path(temp) / "Shadow6-artifact-bundle"
        (root / "platforms").mkdir(parents=True)
        manifest = {"schema": "shadow6.ci-artifact-bundle.v1", "runId": run_id,
                    "commit": commit, "hostPackager": {"system": platform.system(), "machine": platform.machine()},
                    "bounds": {"maxFiles": MAX_FILES, "maxFileBytes": MAX_FILE_BYTES,
                               "maxCombinedPayloadBytes": MAX_TOTAL_BYTES}, "groups": [], "files": []}
        installer_source = Path(__file__).with_name("install_platform_payload.py")
        for (platform_name, arch), entries in sorted(groups.items()):
            group_dir = root / "platforms" / platform_name / arch
            group_dir.mkdir(parents=True)
            files = []
            total_state = [0, 0]
            payload = group_dir / "artifacts.tar.gz"
            with tarfile.open(payload, "w:gz", compresslevel=6, format=tarfile.PAX_FORMAT) as archive:
                for artifact_name, artifact_root in sorted(entries):
                    _add_tree(archive, artifact_root, artifact_name, files, total_state)
            full_linux_release = (platform_name, arch) == ("linux", "x86_64") and any(name == "shadow6-linux-release" for name, _ in entries)
            payload_size, payload_sha256, _ = _hash_file(payload)
            (group_dir / "README.md").write_text(_platform_readme(platform_name, arch,
                [name for name, _ in entries], full_linux_release=full_linux_release), encoding="utf-8")
            shutil.copyfile(installer_source, group_dir / "install_platform_payload.py")
            shell = group_dir / "install.sh"
            shell.write_text(_install_shell(platform_name, arch, commit), encoding="utf-8")
            shell.chmod(0o755)
            (group_dir / "install.ps1").write_text(_install_powershell(platform_name, arch, commit), encoding="utf-8")
            group_manifest = {"schema": "shadow6.ci-artifact-group.v1", "runId": run_id,
                "commit": commit, "platform": platform_name, "architecture": arch,
                "artifacts": [name for name, _ in sorted(entries)], "files": len(files),
                "payloadBytes": total_state[0], "payloadArchiveBytes": payload_size,
                "payloadSha256": payload_sha256, "fileManifest": files,
                "installer": "install.sh / install.ps1",
                "installerMode": "prebuilt-release-install" if full_linux_release else
                    "adb-install" if platform_name == "android" else "user-local-artifact-stage"}
            (group_dir / "manifest.json").write_text(json.dumps(group_manifest, sort_keys=True,
                indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")
            manifest["groups"].append({key: value for key, value in group_manifest.items()
                if key != "fileManifest"})
            manifest["files"].extend({"group": f"{platform_name}/{arch}", **item} for item in files)
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=True,
            allow_nan=False) + "\n", encoding="utf-8")
        readme = ["# Shadow6 same-run artifact bundle", "",
            f"Workflow run: `{run_id}`  ", f"Source commit: `{commit}`", "",
            "Choose a folder under `platforms/<platform>/<architecture>/`. Each folder includes a bounded artifact archive and a local installer. Linux x86_64 installs the prebuilt complete release when present; Android uses adb; component-only targets are staged in the current user's local artifact directory.", "",
            "No installer starts a service, adds a Core, changes a firewall, or installs system packages.", "",
            "## Platform groups", ""]
        readme.extend(f"- `{item['platform']}/{item['architecture']}` — {len(item['artifacts'])} artifact(s), {item['installerMode']}" for item in manifest["groups"])
        (root / "README.md").write_text("\n".join(readme) + "\n", encoding="utf-8")
        (root / "install.sh").write_text('''#!/bin/sh
set -eu
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
system=$(uname -s | tr '[:upper:]' '[:lower:]')
machine=$(uname -m)
case "$machine" in x86_64|amd64) arch=x86_64;; aarch64|arm64) arch=arm64;; *) arch=$machine;; esac
case "$system" in linux) target=linux;; darwin) target=macos;; freebsd|openbsd|netbsd) target=$system;; *) target=$system;; esac
exec "$base/platforms/$target/$arch/install.sh"
''', encoding="utf-8")
        (root / "install.sh").chmod(0o755)
        (root / "install.ps1").write_text('''$ErrorActionPreference = 'Stop'
$Base = Split-Path -Parent $MyInvocation.MyCommand.Path
$Arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } else { 'x86_64' }
& (Join-Path $Base "platforms/windows/$Arch/install.ps1")
exit $LASTEXITCODE
''', encoding="utf-8")
        output_temp = Path(temp) / output.name
        with zipfile.ZipFile(output_temp, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as bundle:
            for path in sorted(root.rglob("*")):
                if path.is_symlink():
                    raise ValueError("generated package unexpectedly contains a symbolic link")
                if path.is_file():
                    relative = path.relative_to(root.parent).as_posix()
                    info = zipfile.ZipInfo(relative)
                    info.compress_type = zipfile.ZIP_STORED
                    info.external_attr = (stat.S_IMODE(path.stat().st_mode) & 0o777) << 16
                    with path.open("rb") as source, bundle.open(info, "w") as destination:
                        shutil.copyfileobj(source, destination, 1024 * 1024)
        os.replace(output_temp, output)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        manifest = package(args.input, args.output, run_id=args.run_id, commit=args.commit)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(2, f"artifact bundle failed: {type(error).__name__}: {error}\n")
    print(json.dumps({"schema": manifest["schema"], "runId": manifest["runId"],
        "commit": manifest["commit"], "groups": len(manifest["groups"]),
        "files": len(manifest["files"]), "output": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
