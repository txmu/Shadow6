"""Artifact provenance and Native Profile inventory for the WAN/PCAP lab."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Crosed"))
sys.path.insert(0, str(ROOT / "Deployment"))
from native_profiles import CORE_IDS, profile_digest, profiles
from service_storage import strict_json

MANIFEST = "shadow6-test-lab-artifact-manifest.json"
IDRIS_LINUX_ARTIFACTS = ("shadow6-idris-ubuntu-latest-X64", "shadow6-idris-ubuntu-latest")
MANIFEST_SCHEMA = "shadow6.test-lab-artifacts.v1"
MAX_ARTIFACT_BYTES = 2 * 1024**3
MAX_MEMBER_BYTES = 512 * 1024**2
MAX_MEMBERS = 20000
SHA = re.compile(r"[0-9a-f]{40}\Z")


def _strict_json(data: bytes):
    return strict_json(data, limit=8 * 1024 * 1024)


def _safe_relative(value: str) -> Path:
    if (not isinstance(value, str) or not value or value.startswith('/') or
            any(part in ("", ".", "..") for part in value.split('/')) or
            "\\" in value or '\0' in value):
        raise ValueError("unsafe artifact path")
    return Path(value)


def _checked_file(path: Path, *, maximum=MAX_MEMBER_BYTES) -> os.stat_result:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_size > maximum or info.st_nlink != 1 or
            info.st_mode & 0o022 or info.st_uid not in (0, os.geteuid())):
        raise ValueError(f"artifact file is not regular, bounded, and owner-controlled: {path}")
    return info


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_file(path: Path, *, maximum=MAX_MEMBER_BYTES, digest_only=False):
    path = Path(path).absolute()
    # Open every directory component without following a symlink. Retain the
    # final directory descriptor through the post-read pathname recheck.
    parent_fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        before = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_size > maximum or
                before.st_nlink != 1 or before.st_mode & 0o022 or before.st_uid not in (0, os.geteuid())):
            raise ValueError('artifact file is not regular, bounded, and owner-controlled')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent_fd)
        try:
            opened = os.fstat(fd)
            if _identity(opened) != _identity(before):
                raise ValueError('artifact changed while opening')
            digest = hashlib.sha256()
            data = bytearray()
            remaining = opened.st_size
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    raise ValueError('artifact truncated while reading')
                remaining -= len(chunk)
                digest.update(chunk)
                if not digest_only:
                    data.extend(chunk)
            if (os.read(fd, 1) or _identity(os.fstat(fd)) != _identity(opened) or
                    _identity(os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)) != _identity(opened) or
                    _identity(path.lstat()) != _identity(opened)):
                raise ValueError('artifact changed while reading')
            return digest.hexdigest() if digest_only else bytes(data)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def sha256_file(path: Path) -> str:
    return _read_file(path, digest_only=True)


def expected_files():
    """Return unique primary binaries directly from the existing Profile registry."""
    result = {}
    for profile in profiles():
        if profile["primary"]:
            result[profile["artifact"]] = profile
    if len(result) != len(CORE_IDS):
        raise ValueError("Native Profile registry primary Core coverage is inconsistent")
    return result


def create_manifest(root: Path, *, run_id=None, run_attempt=None, commit=None,
                    workflow="multiplatform", platform="linux", architecture=None):
    root = Path(root).absolute()
    files = []
    for relative, profile in expected_files().items():
        path = root / _safe_relative(relative)
        info = _checked_file(path)
        files.append({"path": relative, "size": info.st_size,
                      "mode": stat.S_IMODE(info.st_mode), "sha256": sha256_file(path),
                      "core": profile["core"], "profile": profile["id"],
                      "profileDigest": profile_digest(profile),
                      "nativeTransport": profile["nativeTransport"],
                      "applicationBoundary": profile["applicationBoundary"]})
    if commit is None:
        try:
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                                    capture_output=True, text=True, timeout=3).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            commit = None
    if commit is not None and (not isinstance(commit, str) or not SHA.fullmatch(commit)):
        raise ValueError("commit must be a full 40-character Git SHA")
    if architecture is None:
        import platform as _platform
        architecture = _platform.machine()
    return {"schema": MANIFEST_SCHEMA, "workflow": workflow,
            "runId": str(run_id) if run_id is not None else None,
            "runAttempt": str(run_attempt) if run_attempt is not None else None,
            "commit": commit, "platform": platform, "architecture": architecture,
            "createdAt": int(time.time()), "files": files}


def write_manifest(root: Path, output: Path, **metadata):
    value = create_manifest(root, **metadata)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    data = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o644)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return value


def find_manifest(root: Path):
    root = Path(root)
    direct = root / MANIFEST
    if direct.is_file() and not direct.is_symlink():
        return direct
    matches = []
    for path in root.rglob(MANIFEST):
        if path.is_symlink() or not path.is_file():
            continue
        matches.append(path)
        if len(matches) > 1:
            raise ValueError("multiple artifact manifests found")
    return matches[0] if matches else None


def load_manifest(path: Path):
    path = Path(path)
    info = _checked_file(path, maximum=1024 * 1024)
    if info.st_nlink != 1:
        raise ValueError("artifact manifest must have one link")
    value = _strict_json(_read_file(path, maximum=1024 * 1024))
    required = {"schema", "workflow", "runId", "runAttempt", "commit", "platform",
                "architecture", "createdAt", "files"}
    if not isinstance(value, dict) or set(value) != required or value["schema"] != MANIFEST_SCHEMA:
        raise ValueError("invalid test-lab artifact manifest")
    if (not isinstance(value['workflow'], str) or not re.fullmatch(r'[A-Za-z0-9 ._-]{1,128}', value['workflow']) or
            not isinstance(value['platform'], str) or not re.fullmatch(r'[a-z][a-z0-9_-]{1,31}', value['platform']) or
            not isinstance(value['architecture'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', value['architecture'])):
        raise ValueError('invalid artifact workflow/platform/architecture identity')
    for field in ('runId', 'runAttempt'):
        if value[field] is not None and (not isinstance(value[field], str) or
                not re.fullmatch(r'[1-9][0-9]{0,19}', value[field])):
            raise ValueError('invalid artifact Actions run identity')
    if value["commit"] is not None and (not isinstance(value["commit"], str) or not SHA.fullmatch(value["commit"])):
        raise ValueError("invalid artifact source commit")
    if type(value["createdAt"]) is not int or not isinstance(value["files"], list) or len(value["files"]) != len(expected_files()):
        raise ValueError("invalid artifact manifest inventory")
    wanted = expected_files()
    seen = set()
    for item in value["files"]:
        fields = {"path", "size", "mode", "sha256", "core", "profile", "profileDigest",
                  "nativeTransport", "applicationBoundary"}
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("invalid artifact manifest entry")
        relative = item["path"]
        profile = wanted.get(relative)
        if profile is None or relative in seen:
            raise ValueError("artifact manifest path is unknown or duplicated")
        seen.add(relative)
        if (item["core"] != profile["core"] or item["profile"] != profile["id"] or
                item["profileDigest"] != profile_digest(profile) or
                item["nativeTransport"] != profile["nativeTransport"] or
                item["applicationBoundary"] != profile["applicationBoundary"] or
                type(item["size"]) is not int or not 0 < item["size"] <= MAX_MEMBER_BYTES or
                type(item["mode"]) is not int or item["mode"] & ~0o777 or item['mode'] & 0o022 or item['mode'] & 0o500 != 0o500 or
                not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
            raise ValueError("artifact manifest entry conflicts with the current Profile contract")
    if seen != set(wanted):
        raise ValueError("artifact manifest omits registered Native Cores")
    return value


def locate_binary(root: Path, profile: dict) -> Path | None:
    root = Path(root).absolute()
    relative = _safe_relative(profile["artifact"])
    path = root / relative
    if path.is_file() and not path.is_symlink():
        return path
    candidates = [item for item in root.rglob(relative.name)
                  if item.is_file() and not item.is_symlink() and item.parent.name == relative.parent.name]
    if len(candidates) == 1:
        return candidates[0]
    return None


def verify_inventory(root: Path, *, manifest_path: Path | None = None, expected_commit=None,
                     expected_workflow=None, expected_run_id=None, expected_run_attempt=None,
                     expected_platform=None, expected_architecture=None):
    root = Path(root).absolute()
    manifest_path = manifest_path or find_manifest(root)
    manifest = load_manifest(manifest_path) if manifest_path else None
    if expected_commit and not SHA.fullmatch(expected_commit):
        raise ValueError("expected commit must be a full Git SHA")
    if manifest and expected_commit and manifest["commit"] != expected_commit:
        raise ValueError("artifact manifest commit does not match requested commit")
    if manifest:
        for field, expected in (('workflow', expected_workflow), ('runId', expected_run_id),
                ('runAttempt', expected_run_attempt), ('platform', expected_platform),
                ('architecture', expected_architecture)):
            actual = manifest[field]
            if field == 'architecture':
                aliases = {'amd64': 'x86_64', 'AMD64': 'x86_64', 'arm64': 'aarch64', 'ARM64': 'aarch64'}
                actual = aliases.get(actual, actual)
                expected = aliases.get(expected, expected)
            if expected is not None and actual != str(expected):
                raise ValueError('artifact manifest ' + field + ' does not match requested identity')
    digest_by_path = {item["path"]: item for item in (manifest or {}).get("files", [])}
    rows = []
    for profile in profiles():
        if not profile["primary"]:
            continue
        path = locate_binary(root, profile)
        row = {"core": profile["core"], "profile": profile["id"],
               "nativeTransport": profile["nativeTransport"],
               "applicationBoundary": profile["applicationBoundary"],
               "artifact": profile["artifact"], "profileDigest": profile_digest(profile),
               "available": False, "sha256": None, "integrity": "unavailable", "reason": None}
        if path is None:
            row["reason"] = "registered binary artifact is missing from supplied artifact directory"
        else:
            try:
                info = _checked_file(path)
                actual = sha256_file(path)
                expected = digest_by_path.get(profile["artifact"])
                if expected and (info.st_size != expected["size"] or actual != expected["sha256"]):
                    raise ValueError("binary size or SHA-256 differs from artifact manifest")
                mode_restored = False
                if expected and stat.S_IMODE(info.st_mode) != expected['mode']:
                    # Actions download-artifact normalizes files to 0644. Only
                    # this documented transformation may restore executable bits.
                    if stat.S_IMODE(info.st_mode) != 0o644 or expected['mode'] != 0o755:
                        raise ValueError('binary mode differs from artifact manifest')
                    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    try:
                        if _identity(os.fstat(descriptor)) != _identity(info):
                            raise ValueError('artifact changed before mode restoration')
                        os.fchmod(descriptor, expected['mode'])
                    finally:
                        os.close(descriptor)
                    if sha256_file(path) != actual:
                        raise ValueError('artifact changed during mode restoration')
                    mode_restored = True
                row.update(available=True, sha256="sha256:" + actual,
                           integrity="manifest-verified" if expected else "computed-no-manifest",
                           path=str(path), size=info.st_size,
                           mode=stat.S_IMODE(path.lstat().st_mode),
                           actionsModeRestored=mode_restored,
                           executable=os.access(path, os.X_OK))
            except (OSError, ValueError) as error:
                row["reason"] = str(error)
                row["integrity"] = "failed"
        rows.append(row)
    return {"manifest": manifest, "manifestPath": str(manifest_path) if manifest_path else None,
            "expectedCommit": expected_commit, "cores": rows,
            "available": sum(row["available"] for row in rows), "denominator": len(CORE_IDS)}


def _gh_json(endpoint: str):
    result = subprocess.run(["gh", "api", endpoint], capture_output=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError("GitHub API request failed; check gh authentication and repository access")
    if len(result.stdout) > 8 * 1024 * 1024:
        raise ValueError("GitHub API response exceeds size limit")
    return _strict_json(result.stdout)


def _repo_slug():
    remote = subprocess.run(["git", "remote", "get-url", "origin"], cwd=ROOT,
                            capture_output=True, text=True, timeout=3, check=True).stdout.strip()
    match = re.search(r"github\.com[:/]([^/]+/[^/.]+?)(?:\.git)?$", remote)
    if not match:
        raise ValueError("origin is not a GitHub repository")
    return match.group(1)


def _artifact_token():
    result = subprocess.run(["gh", "auth", "token"], capture_output=True, timeout=5, check=False)
    if result.returncode or not result.stdout.strip():
        raise RuntimeError("GitHub CLI authentication is unavailable")
    return result.stdout.decode("utf-8").strip()


class _StripCrossOriginAuth(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            redirected.remove_header("Authorization")
        return redirected


def _download_zip(url: str, token: str, target: Path, digest: str | None):
    opener = urllib.request.build_opener(_StripCrossOriginAuth())
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    hasher = hashlib.sha256()
    total = 0
    with opener.open(request, timeout=60) as response, target.open("xb") as output:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > MAX_ARTIFACT_BYTES:
                raise ValueError("GitHub artifact exceeds 2 GiB bound")
            hasher.update(block)
            output.write(block)
    actual = hasher.hexdigest()
    if digest:
        normalized = digest.removeprefix("sha256:")
        if not re.fullmatch(r"[0-9a-f]{64}", normalized) or normalized != actual:
            raise ValueError("GitHub artifact archive digest mismatch")
    return actual, total


def _safe_extract(archive: Path, destination: Path):
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if len(members) > MAX_MEMBERS:
            raise ValueError("artifact member count exceeds bound")
        total = 0
        for item in members:
            relative = _safe_relative(item.filename.rstrip("/")) if item.filename.rstrip("/") else None
            mode = item.external_attr >> 16
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError("artifact contains a link or special file")
            if mode & 0o022:
                raise ValueError('artifact member permits group/world writes')
            if item.file_size > MAX_MEMBER_BYTES:
                raise ValueError("artifact member exceeds size bound")
            total += item.file_size
            if total > MAX_ARTIFACT_BYTES:
                raise ValueError("expanded artifact exceeds size bound")
            if relative is None:
                continue
            target = destination / relative
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                raise ValueError("duplicate artifact member")
            with source.open(item) as input_stream, target.open("xb") as output:
                remaining = item.file_size
                while remaining:
                    block = input_stream.read(min(65536, remaining))
                    if not block:
                        raise ValueError("truncated artifact member")
                    output.write(block)
                    remaining -= len(block)
            executable = bool(mode & 0o111)
            target.chmod(0o755 if executable else 0o644)


def _safe_extract_runtime_tar(archive_path: Path, destination: Path):
    """Extract the Idris runtime archive without trusting member names or links."""
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) > MAX_MEMBERS:
            raise ValueError("nested runtime archive member count exceeds bound")
        normalized = []
        total = 0
        link_names = set()
        for member in members:
            raw = member.name
            if "\\" in raw or raw.startswith("/"):
                raise ValueError("nested runtime archive contains an absolute or non-portable path")
            while raw.startswith("./"):
                raw = raw[2:]
            if raw in ("", "."):
                if member.isdir():
                    continue
                raise ValueError("nested runtime archive has an invalid root member")
            relative = PurePosixPath(raw)
            if any(part in ("", ".", "..") for part in relative.parts):
                raise ValueError("nested runtime archive path traversal")
            if member.isdir() or member.isfile():
                if member.isfile():
                    if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                        raise ValueError("nested runtime archive contains an oversized file")
                    total += member.size
                normalized.append((member, relative))
            else:
                raise ValueError("nested runtime archive contains a link or special file")
            if member.mode & 0o022:
                raise ValueError('nested runtime archive member permits group/world writes')
            if total > MAX_ARTIFACT_BYTES:
                raise ValueError("nested runtime archive exceeds expanded size bound")
        for _, relative in normalized:
            for parent in relative.parents:
                if parent.as_posix() in link_names:
                    raise ValueError("nested runtime archive traverses a symbolic link")
        for member, relative in normalized:
            if member.issym():
                continue
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("nested runtime archive member cannot be read")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(target, flags, 0o600)
            with os.fdopen(descriptor, "wb") as output, source:
                remaining = member.size
                while remaining:
                    block = source.read(min(65536, remaining))
                    if not block:
                        raise ValueError("nested runtime archive member is truncated")
                    output.write(block)
                    remaining -= len(block)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
        for member, relative in normalized:
            if not member.issym():
                continue
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            os.symlink(member.linkname, target)


def _verify_idris_checksums(root: Path):
    checksum_path = root / "SHA256SUMS"
    if not checksum_path.is_file() or checksum_path.is_symlink():
        raise ValueError("Idris runtime artifact is missing its embedded SHA256SUMS")
    lines = checksum_path.read_text(encoding="ascii").splitlines()
    if not lines or len(lines) > MAX_MEMBERS:
        raise ValueError("Idris runtime checksum inventory is empty or oversized")
    seen = set()
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise ValueError("Idris runtime checksum entry is malformed")
        expected, name = line[:64], line[66:]
        while name.startswith("./"):
            name = name[2:]
        relative = _safe_relative(name)
        if name in seen or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("Idris runtime checksum entry is duplicated or invalid")
        seen.add(name)
        if name == "SHA256SUMS":
            # The producer hashes the initially truncated checksum file itself.
            if expected != hashlib.sha256(b"").hexdigest():
                raise ValueError("Idris runtime self-checksum has an unexpected value")
            continue
        path = root / relative
        if sha256_file(path) != expected:
            raise ValueError(f"Idris runtime file digest mismatch: {name}")


def _extract_tar_member(archive_path: Path, member_name: str, destination: Path):
    """Extract one exact regular file from the already verified release tar."""
    archive_path = Path(archive_path)
    info = _checked_file(archive_path, maximum=MAX_ARTIFACT_BYTES)
    matches = 0
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) > MAX_MEMBERS:
            raise ValueError("release archive member count exceeds bound")
        selected = None
        for member in members:
            raw = member.name
            while raw.startswith("./"):
                raw = raw[2:]
            if raw == member_name:
                matches += 1
                selected = member
        if matches != 1 or selected is None or not selected.isfile():
            raise ValueError(f"release archive does not contain one regular {member_name}")
        if selected.size < 1 or selected.size > MAX_MEMBER_BYTES:
            raise ValueError("release archive runtime member exceeds its bound")
        source = archive.extractfile(selected)
        if source is None:
            raise ValueError("release archive runtime member cannot be read")
        destination = Path(destination)
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        descriptor = os.open(destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as output, source:
            remaining = selected.size
            while remaining:
                block = source.read(min(65536, remaining))
                if not block:
                    raise ValueError("release archive runtime member is truncated")
                output.write(block)
                remaining -= len(block)
        destination.chmod(0o755 if selected.mode & 0o111 else 0o644)
    if info.st_size > MAX_ARTIFACT_BYTES:
        raise ValueError("release artifact archive exceeds its bound")


def _copy_safe_tree(source: Path, destination: Path):
    source = Path(source)
    if not source.is_dir() or source.is_symlink():
        raise ValueError("runtime companion must be a real directory")
    destination.mkdir(mode=0o755, parents=True, exist_ok=False)
    total = count = 0
    for entry in sorted(source.rglob("*")):
        relative = entry.relative_to(source)
        _safe_relative(relative.as_posix())
        if entry.is_symlink():
            raise ValueError("symbolic link in runtime companion is rejected")
        target = destination.joinpath(*relative.parts)
        if entry.is_dir():
            target.mkdir(mode=0o755, parents=True, exist_ok=True)
            continue
        file_info = _checked_file(entry)
        total += file_info.st_size
        count += 1
        if total > MAX_ARTIFACT_BYTES or count > MAX_MEMBERS:
            raise ValueError("runtime companion exceeds its copy bound")
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        source_fd = os.open(entry, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(source_fd, "rb") as input_stream, os.fdopen(target_fd, "wb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream, 1024 * 1024)
        target.chmod(0o755 if file_info.st_mode & 0o111 else 0o644)


def merge_runtime_companions(root: Path, *, idris_artifact: Path | None,
                             s6epe_artifact: Path | None):
    """Merge same-run runtime artifacts omitted by older Linux release bundles."""
    root = Path(root)
    missing = []
    if idris_artifact is not None:
        idris_artifact = Path(idris_artifact)
        nested = idris_artifact / "core-idris-runtime.tar.gz"
        if not nested.is_file() or nested.is_symlink():
            missing.append(f"Idris runtime tarball missing from {idris_artifact.name}")
        elif not (root / "Core-Idris" / "shadow6-idris").is_file():
            idris_root = root / "Core-Idris"
            if idris_root.exists():
                raise ValueError("refusing to merge Idris runtime over existing Core-Idris files")
            _safe_extract_runtime_tar(nested, idris_root)
            _verify_idris_checksums(idris_root)
    nim_binary = root / "Core-Nim" / "shadow6-nim"
    nim_provider = root / "Core-Nim" / "libdatachannel.so.0.23"
    release_archive = root / "ci-artifacts" / "linux" / "Shadow6.tar.gz"
    if nim_binary.is_file() and not nim_provider.is_file() and release_archive.is_file():
        temporary_package = root / ".test-lab-nim-runtime"
        if temporary_package.exists():
            raise ValueError("refusing to overwrite temporary Native WebRTC runtime stage")
        temporary_package.mkdir(mode=0o700)
        try:
            packaged_binary = temporary_package / "shadow6-nim"
            packaged_library = temporary_package / "libdatachannel.so.0.23"
            _extract_tar_member(release_archive, "Shadow6/Core-Nim/shadow6-nim", packaged_binary)
            _extract_tar_member(release_archive, "Shadow6/Core-Nim/libdatachannel.so.0.23", packaged_library)
            if sha256_file(packaged_binary) != sha256_file(nim_binary):
                raise ValueError("packaged Nim Core binary differs from the registered Linux artifact")
            nim_provider.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            os.replace(packaged_library, nim_provider)
        finally:
            shutil.rmtree(temporary_package, ignore_errors=True)
    if s6epe_artifact is not None:
        s6epe_artifact = Path(s6epe_artifact)
        runtime_root = root / "runtime-artifacts" / "shadow6-s6epe-linux-runtime"
        if runtime_root.is_symlink():
            raise ValueError("S6EPE runtime destination is a symbolic link")
        if not runtime_root.exists():
            runtime_root.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            _copy_safe_tree(s6epe_artifact, runtime_root)
        provider = runtime_root / "lib" / "libdatachannel.so.0.23"
        if not runtime_root.is_dir() or not provider.is_file() or provider.is_symlink():
            missing.append("S6EPE runtime artifact lacks its recorded libdatachannel provider")
    if nim_binary.is_file() and not nim_provider.is_file():
        missing.append("Native Nim libdatachannel ABI is absent from its Core/release artifacts; S6EPE provider is not ABI-compatible")
    return missing


def locate_linux_idris_artifact(directory: Path) -> Path:
    """Locate the x86_64 Idris runtime companion, including legacy artifact names."""
    root = Path(directory)
    matches = [root / name for name in IDRIS_LINUX_ARTIFACTS
               if (root / name).is_dir() and not (root / name).is_symlink()]
    if len(matches) > 1:
        raise ValueError("multiple Linux Idris runtime companion artifacts were provided")
    return matches[0] if matches else root / IDRIS_LINUX_ARTIFACTS[0]


def load_fetch_provenance(root: Path):
    """Recheck the downloaded artifact archive digests and binary file index."""
    path = Path(root) / "shadow6-test-lab-fetch-provenance.json"
    info = _checked_file(path, maximum=1024 * 1024)
    value = _strict_json(_read_file(path, maximum=1024 * 1024))
    fields = {"schema", "repository", "runId", "commit", "artifacts",
              "missingArtifacts", "binaries", "runtimeFiles"}
    if not isinstance(value, dict) or set(value) != fields or value["schema"] != "shadow6.test-lab-fetch-provenance.v1":
        raise ValueError("invalid GitHub artifact fetch provenance")
    if not isinstance(value["repository"], str) or not isinstance(value["runId"], int) or value["runId"] < 1:
        raise ValueError("invalid GitHub artifact run identity")
    if not isinstance(value["commit"], str) or not SHA.fullmatch(value["commit"]):
        raise ValueError("invalid GitHub artifact source commit")
    if not isinstance(value["artifacts"], list) or not value["artifacts"]:
        raise ValueError("GitHub artifact provenance has no downloaded artifacts")
    for artifact in value["artifacts"]:
        required = {"name", "artifactId", "artifactDigest", "downloadedZipSha256",
                    "archiveBytes", "sourceCommit", "sourceShaVerifiedAgainstRun"}
        if not isinstance(artifact, dict) or set(artifact) != required:
            raise ValueError("invalid downloaded artifact provenance entry")
        if (artifact["sourceCommit"] != value["commit"] or
                type(artifact["sourceShaVerifiedAgainstRun"]) is not bool or
                type(artifact["archiveBytes"]) is not int or not 0 < artifact["archiveBytes"] <= MAX_ARTIFACT_BYTES):
            raise ValueError("artifact run/commit provenance is inconsistent")
        digest = artifact["artifactDigest"]
        actual = artifact["downloadedZipSha256"]
        if not isinstance(digest, str) or not isinstance(actual, str):
            raise ValueError("artifact digest metadata is malformed")
        if digest.removeprefix("sha256:") != actual.removeprefix("sha256:") or not re.fullmatch(
                r"[0-9a-f]{64}", digest.removeprefix("sha256:")):
            raise ValueError("downloaded artifact ZIP digest does not match GitHub digest")
    for group_name in ("binaries", "runtimeFiles"):
        rows = value[group_name]
        if not isinstance(rows, list) or len(rows) > MAX_MEMBERS:
            raise ValueError("artifact file digest inventory exceeds bound")
        seen = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"path", "size", "sha256"}:
                raise ValueError("invalid artifact file digest entry")
            relative = _safe_relative(row["path"])
            if relative.as_posix() in seen or type(row["size"]) is not int or row["size"] < 1:
                raise ValueError("duplicate or invalid artifact file digest entry")
            seen.add(relative.as_posix())
            if not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
                raise ValueError("invalid artifact file SHA-256")
            file_path = Path(root) / relative
            file_info = _checked_file(file_path)
            if file_info.st_size != row["size"] or sha256_file(file_path) != row["sha256"]:
                raise ValueError(f"downloaded artifact file digest mismatch: {relative.as_posix()}")
    if info.st_nlink != 1:
        raise ValueError("artifact fetch provenance must have one link")
    return value


def fetch_artifacts(destination: Path, *, run_id=None, commit=None, tag=None):
    """Fetch the same-run Linux Core bundle and registered runtime companions."""
    if sum(value is not None for value in (run_id, commit, tag)) > 1:
        raise ValueError("choose at most one of run-id, commit, or tag")
    repo = _repo_slug()
    if run_id is None:
        if tag is not None:
            branch = tag
        elif commit is not None:
            branch = commit
        else:
            info = _gh_json(f"repos/{repo}")
            branch = info.get("default_branch")
            if not isinstance(branch, str) or not branch:
                raise ValueError("repository default branch is unavailable")
        query = urllib.parse.urlencode({"branch": branch, "status": "success", "per_page": 30})
        runs = _gh_json(f"repos/{repo}/actions/workflows/multiplatform.yml/runs?{query}")
        candidates = runs.get("workflow_runs", [])
        selected = next((item for item in candidates if item.get("conclusion") == "success" and
                         (commit is None or item.get("head_sha") == commit) and
                         (tag is None or item.get("head_branch") == tag)), None)
        if not selected:
            raise RuntimeError("no successful multiplatform workflow run matches the requested branch/commit/tag")
        run_id = selected.get("id")
    if type(run_id) is not int and not (isinstance(run_id, str) and run_id.isdigit()):
        raise ValueError("run-id must be a decimal GitHub Actions run ID")
    run_id = int(run_id)
    run = _gh_json(f"repos/{repo}/actions/runs/{run_id}")
    source_sha = run.get("head_sha")
    if (not isinstance(source_sha, str) or not SHA.fullmatch(source_sha) or
            run.get('path') != '.github/workflows/multiplatform.yml'):
        raise ValueError('selected Actions run has an invalid workflow/commit identity')
    if run.get("conclusion") != "success" or run.get("status") != "completed":
        raise ValueError("selected Actions run is not completed successfully")
    if commit and source_sha != commit:
        raise ValueError("selected Actions run does not match requested commit")
    if tag and run.get("head_branch") != tag:
        raise ValueError("selected Actions run does not match requested tag")
    by_name = {}
    for page in range(1, 21):
        artifact_response = _gh_json(f"repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100&page={page}")
        entries = artifact_response.get('artifacts', [])
        for item in entries:
            if item.get("name") in {"shadow6-linux-release", *IDRIS_LINUX_ARTIFACTS,
                                    "shadow6-s6epe-linux-runtime"} and not item.get("expired"):
                by_name.setdefault(item["name"], []).append(item)
        if len(entries) < 100:
            break
    else:
        raise ValueError('Actions artifact inventory exceeds bounded pagination')
    primary = by_name.get("shadow6-linux-release", [])
    if len(primary) != 1:
        raise ValueError("successful run must contain exactly one unexpired shadow6-linux-release artifact")
    selected = [primary[0]]
    missing = []
    idris_candidates = [item for name in IDRIS_LINUX_ARTIFACTS for item in by_name.get(name, [])]
    if len(idris_candidates) > 1:
        raise ValueError("successful run contains duplicate Linux Idris runtime artifacts")
    if idris_candidates:
        selected.append(idris_candidates[0])
    else:
        missing.append(IDRIS_LINUX_ARTIFACTS[0])
    for name in ("shadow6-s6epe-linux-runtime",):
        matches = by_name.get(name, [])
        if len(matches) > 1:
            raise ValueError(f"successful run contains duplicate {name} artifacts")
        if matches:
            selected.append(matches[0])
        else:
            missing.append(name)
    for artifact in selected:
        if not isinstance(artifact.get('digest'), str) or not re.fullmatch(
                r'sha256:[0-9a-f]{64}', artifact['digest']):
            raise ValueError('selected Actions artifact has no SHA-256 provenance')
        expected_sha = artifact.get("workflow_run", {}).get("head_sha")
        if expected_sha and expected_sha != source_sha:
            raise ValueError("artifact provenance SHA differs from workflow run")
    token = _artifact_token()
    destination = Path(destination).absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="shadow6-artifact-", dir=destination.parent))
    try:
        parts = stage / "parts"
        parts.mkdir()
        provenance = []
        extracted = None
        for artifact in selected:
            archive = stage / (artifact["name"] + ".zip")
            digest, size = _download_zip(artifact["archive_download_url"], token, archive,
                                         artifact.get("digest"))
            part = parts / artifact["name"]
            _safe_extract(archive, part)
            provenance.append({"name": artifact["name"], "artifactId": artifact.get("id"),
                "artifactDigest": artifact.get("digest"), "downloadedZipSha256": "sha256:" + digest,
                "archiveBytes": size, "sourceCommit": source_sha,
                "sourceShaVerifiedAgainstRun": bool(artifact.get("workflow_run", {}).get("head_sha"))})
            if artifact["name"] == "shadow6-linux-release":
                extracted = part
        if extracted is None:
            raise ValueError("Linux release extraction was not produced")
        idris_part = next((parts / item["name"] for item in selected
                           if item["name"] in IDRIS_LINUX_ARTIFACTS), None)
        s6epe_part = next((parts / item["name"] for item in selected
                           if item["name"] == "shadow6-s6epe-linux-runtime"), None)
        missing.extend(merge_runtime_companions(extracted, idris_artifact=idris_part,
                                                s6epe_artifact=s6epe_part))
        expected = expected_files()
        binaries = []
        runtime_files = []
        for relative in expected:
            binary = extracted / _safe_relative(relative)
            if binary.is_file() and not binary.is_symlink():
                file_info = _checked_file(binary)
                binaries.append({"path": relative, "size": file_info.st_size,
                                 "sha256": sha256_file(binary)})
        for relative in ("Core-Nim/libdatachannel.so.0.23", "Core-Idris/libsodium_ffi.so",
                         "runtime-artifacts/shadow6-s6epe-linux-runtime/lib/libdatachannel.so.0.23",
                         "runtime-artifacts/shadow6-s6epe-linux-runtime/shadow6-privacy-envelope"):
            runtime = extracted / relative
            if runtime.is_file() and not runtime.is_symlink():
                file_info = _checked_file(runtime)
                runtime_files.append({"path": relative, "size": file_info.st_size,
                                      "sha256": sha256_file(runtime)})
        provenance_path = extracted / "shadow6-test-lab-fetch-provenance.json"
        provenance_data = (json.dumps({"schema": "shadow6.test-lab-fetch-provenance.v1",
            "repository": repo, "runId": run_id, "commit": source_sha,
            "artifacts": provenance, "missingArtifacts": missing,
            "binaries": binaries, "runtimeFiles": runtime_files}, sort_keys=True,
            indent=2, allow_nan=False) + "\n").encode("utf-8")
        provenance_fd = os.open(provenance_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        with os.fdopen(provenance_fd, "wb") as stream:
            stream.write(provenance_data)
            stream.flush()
            os.fsync(stream.fileno())
        manifest_path = find_manifest(extracted)
        manifest = load_manifest(manifest_path) if manifest_path else None
        if manifest and manifest.get("commit") != source_sha:
            raise ValueError("artifact manifest source commit differs from Actions run")
        if destination.exists():
            raise FileExistsError("artifact destination already exists; choose a new empty path")
        extracted.rename(destination)
        primary_provenance = next(item for item in provenance if item["name"] == "shadow6-linux-release")
        return {"source": "github-actions", "repository": repo, "runId": run_id,
                "commit": source_sha, "artifact": "shadow6-linux-release",
                "artifactId": primary_provenance["artifactId"],
                "artifactDigest": primary_provenance["artifactDigest"],
                "downloadedZipSha256": primary_provenance["downloadedZipSha256"],
                "archiveBytes": primary_provenance["archiveBytes"], "artifacts": provenance,
                "missingArtifacts": missing,
                "manifest": str(destination / manifest_path.relative_to(extracted)) if manifest_path else None,
                "destination": str(destination)}
    finally:
        import shutil
        shutil.rmtree(stage, ignore_errors=True)
