#!/usr/bin/env python3
"""Install or stage one platform folder from a verified CI artifact bundle."""
from __future__ import annotations

try:
    from Deployment.service_storage import strict_json as portable_json
except ImportError:
    import sys
    from pathlib import Path
    for _json_parent in Path(__file__).resolve().parents:
        for _json_path in (_json_parent / 'Deployment', _json_parent / 'deployment',
                           _json_parent / 'share/shadow6/deployment'):
            if (_json_path / 'service_storage.py').is_file():
                sys.path.insert(0,str(_json_path)); break
        else: continue
        break
    from service_storage import strict_json as portable_json


import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

MAX_MEMBERS = 50_000
MAX_FILE_BYTES = 2 * 1024**3
MAX_TOTAL_BYTES = 8 * 1024**3


def _safe_name(name):
    if not isinstance(name, str) or "\\" in name or ":" in name or "\x00" in name:
        raise ValueError("unsafe archive member path")
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("unsafe archive member path")
    return path


def _members(archive):
    result = []
    total = 0
    seen_files = set()
    for member in archive.getmembers():
        normalized = _safe_name(member.name).as_posix().rstrip("/")
        if member.isdir():
            result.append(member)
        elif member.isfile():
            if normalized in seen_files:
                raise ValueError("archive repeats a regular-file path")
            seen_files.add(normalized)
            if member.size < 0 or member.size > MAX_FILE_BYTES:
                raise ValueError("archive contains an oversized file")
            total += member.size
            result.append(member)
        else:
            raise ValueError("archive links and special files are rejected")
        if len(result) > MAX_MEMBERS or total > MAX_TOTAL_BYTES:
            raise ValueError("archive exceeds extraction bounds")
    return result


def _extract_regular(archive, members, destination):
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    for member in members:
        relative = _safe_name(member.name)
        target = destination.joinpath(*relative.parts)
        if member.isdir():
            target.mkdir(mode=0o755, parents=True, exist_ok=True)
            continue
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        info = target.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or target.parent.is_symlink():
            raise ValueError("archive path traversed a non-directory")
        source = archive.extractfile(member)
        if source is None:
            raise ValueError("archive member could not be read")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags, 0o600)
        with os.fdopen(descriptor, "wb") as output, source:
            shutil.copyfileobj(source, output, 1024 * 1024)
        target.chmod(0o755 if member.mode & 0o111 else 0o644)


def _verify_payload(base, payload, platform_name, arch, commit):
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", platform_name) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", arch):
        raise ValueError("platform and architecture must be bounded identifiers")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("source commit must be a full lowercase SHA-1 identifier")
    manifest_path = Path(base) / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > 16 * 1024**2:
        raise ValueError("platform folder manifest is missing or exceeds its bound")

    value = portable_json(manifest_path.read_bytes(), limit=16*1024**2)
    if (not isinstance(value, dict) or value.get("schema") != "shadow6.ci-artifact-group.v1" or
            value.get("commit") != commit or value.get("platform") != platform_name or
            value.get("architecture") != arch):
        raise ValueError("platform folder manifest does not match the selected commit and target")
    if payload.is_symlink() or not payload.is_file() or payload.stat().st_size > MAX_TOTAL_BYTES:
        raise ValueError("platform payload is not a bounded regular file")
    if payload.stat().st_size != value.get("payloadArchiveBytes"):
        raise ValueError("platform payload is not present in the bundle manifest")
    digest = hashlib.sha256()
    with payload.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != value.get("payloadSha256"):
        raise ValueError("platform payload SHA-256 verification failed")
    file_manifest = value.get("fileManifest")
    if not isinstance(file_manifest, list) or len(file_manifest) != value.get("files") or len(file_manifest) > MAX_MEMBERS:
        raise ValueError("platform folder file manifest is malformed")
    expected = {}
    for item in file_manifest:
        if (not isinstance(item, dict) or not isinstance(item.get("artifact"), str) or
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", item["artifact"])):
            raise ValueError("platform folder file manifest has a malformed entry")
        relative = _safe_name(item.get("path"))
        name = PurePosixPath(item["artifact"], *relative.parts).as_posix()
        if (name in expected or not isinstance(item.get("size"), int) or isinstance(item["size"], bool) or item["size"] < 0 or
                not isinstance(item.get("sha256"), str) or
                not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
            raise ValueError("platform folder file manifest has a duplicate or invalid digest entry")
        expected[name] = (item["size"], item["sha256"])
    actual = {}
    with tarfile.open(payload, "r:gz") as archive:
        for member in _members(archive):
            if not member.isfile():
                continue
            name = _safe_name(member.name).as_posix()
            if name in actual:
                raise ValueError("platform payload repeats a file path")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("platform payload file could not be read")
            file_digest = hashlib.sha256()
            size = 0
            with source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    size += len(chunk)
                    file_digest.update(chunk)
            actual[name] = (size, file_digest.hexdigest())
    if actual != expected:
        raise ValueError("platform payload file hashes do not match the folder manifest")


def _release_install(archive, members, prefix):
    releases = [item for item in members if item.isfile() and PurePosixPath(item.name).name == "Shadow6.tar.gz"]
    if len(releases) != 1:
        raise ValueError("a unique complete Shadow6.tar.gz release archive was not found")
    release_file = archive.extractfile(releases[0])
    if release_file is None:
        raise ValueError("release archive cannot be read")
    with tempfile.TemporaryDirectory(prefix="shadow6-prebuilt-install-") as temporary:
        stage = Path(temporary)
        archive_path = stage / "Shadow6.tar.gz"
        with archive_path.open("xb") as stream:
            shutil.copyfileobj(release_file, stream, 1024 * 1024)
        with tarfile.open(archive_path, "r:gz") as release:
            release_members = _members(release)
            extraction = stage / "source"
            _extract_regular(release, release_members, extraction)
        source = extraction / "Shadow6"
        if not (source / "Tools" / "install_prebuilt.py").is_file():
            raise ValueError("complete release layout is missing the prebuilt installer")
        command = [sys.executable, str(source / "Tools" / "install_prebuilt.py"),
                   "--source", str(source), "--prefix", str(prefix)]
        result = subprocess.run(command, cwd=source, capture_output=True, timeout=300, check=False)
        sys.stdout.buffer.write(result.stdout[-16_000:])
        sys.stderr.buffer.write(result.stderr[-16_000:])
        if result.returncode:
            raise RuntimeError(f"prebuilt installer exited with status {result.returncode}")


def _install_apk(archive, members):
    apks = [item for item in members if item.isfile() and item.name.lower().endswith(".apk")]
    if len(apks) != 1:
        raise ValueError("Android artifact folder must contain exactly one APK")
    adb = shutil.which("adb")
    if not adb:
        raise RuntimeError("adb is unavailable; install Android platform-tools and reconnect an authorized device")
    with tempfile.NamedTemporaryFile(prefix="shadow6-android-", suffix=".apk", delete=False) as temporary:
        apk_path = Path(temporary.name)
        source = archive.extractfile(apks[0])
        if source is None:
            raise ValueError("APK cannot be read")
        with source:
            shutil.copyfileobj(source, temporary, 1024 * 1024)
    try:
        result = subprocess.run([adb, "install", "-r", str(apk_path)], capture_output=True,
                                timeout=120, check=False)
        sys.stdout.buffer.write(result.stdout[-8000:])
        sys.stderr.buffer.write(result.stderr[-8000:])
        if result.returncode:
            raise RuntimeError(f"adb install exited with status {result.returncode}")
    finally:
        apk_path.unlink(missing_ok=True)


def _safe_destination(path):
    path = Path(path)
    if os.name == "nt":
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"destination already exists; refusing to overwrite: {path}")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        return
    home = Path.home()
    try:
        path.relative_to(home)
    except ValueError as error:
        raise ValueError("artifact destination must remain under the current user's home directory") from error
    current = Path(path.anchor)
    for component in path.parts[1:-1]:
        current = current / component
        if current.exists() or current.is_symlink():
            info = current.lstat()
            under_home = current == home or home in current.parents
            if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022 or
                    (under_home and info.st_uid != os.getuid())):
                raise ValueError("artifact destination parent must be a private, non-symlink directory")
        else:
            current.mkdir(mode=0o700)
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"destination already exists; refusing to overwrite: {path}")


def install(bundle: Path, *, platform_name: str, arch: str, commit: str):
    bundle = Path(bundle)
    if bundle.is_symlink() or not bundle.is_file() or bundle.stat().st_size > MAX_TOTAL_BYTES:
        raise ValueError("platform archive is not a bounded regular file")
    base = Path(__file__).resolve().parent
    _verify_payload(base, bundle, platform_name, arch, commit)
    with tarfile.open(bundle, "r:gz") as archive:
        members = _members(archive)
        if platform_name == "android":
            return _install_apk(archive, members)
        if platform_name == "linux" and arch == "x86_64" and any(
                item.name.startswith("shadow6-linux-release/") and
                item.isfile() and PurePosixPath(item.name).name == "Shadow6.tar.gz" for item in members):
            prefix = Path(os.environ.get("SHADOW6_PREFIX", str(Path.home() / ".local"))).expanduser()
            return _release_install(archive, members, prefix)
        if os.name == "nt":
            local = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "Shadow6" / "Artifacts"
        else:
            local = Path.home() / ".local" / "lib" / "shadow6" / "artifacts"
        destination = local / platform_name / arch / commit
        _safe_destination(destination)
        _extract_regular(archive, members, destination)
        print(f"Platform payload staged at {destination}; no service or system package was installed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        install(args.bundle, platform_name=args.platform, arch=args.arch, commit=args.commit)
    except (OSError, ValueError, RuntimeError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(2, f"Shadow6 artifact installation failed: {type(error).__name__}: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
