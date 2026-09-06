#!/usr/bin/env python3
"""Signed, bounded package and version manager for Shadow6 extensions."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KINDS = {"crosed-mod", "plugin", "app"}
IDENTITY = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?")
MAX_FILES = 4096
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
MANIFEST_KEYS = {"schema_version", "kind", "id", "version", "files", "signer", "signature"}
FILE_KEYS = {"path", "sha256", "size", "executable"}


class PackageError(ValueError):
    pass


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PackageError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def strict_json(data: bytes, limit: int = 1024 * 1024) -> dict[str, Any]:
    if len(data) > limit:
        raise PackageError("JSON document exceeds size limit")
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        reject_number = lambda _: (_ for _ in ()).throw(PackageError("floats/nonfinite numbers are forbidden"))
        value = json.loads(text, object_pairs_hook=_reject_duplicate, parse_float=reject_number, parse_constant=reject_number)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise PackageError("invalid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise PackageError("JSON document must be an object")
    canonical(value)
    return value


def canonical(value: Any) -> bytes:
    budget = 0
    def check(item: Any, depth: int = 0) -> None:
        nonlocal budget
        budget += 1
        if budget > 1_048_576:
            raise PackageError("JSON document exceeds size limit")
        if depth > 32 or isinstance(item, float):
            raise PackageError("manifest nesting is excessive or contains a float")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 256:
                    raise PackageError("invalid manifest key")
                check(key, depth + 1)
                check(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                check(child, depth + 1)
        elif isinstance(item, str):
            try:
                size = len(item.encode("utf-8"))
            except UnicodeError as exc:
                raise PackageError("invalid Unicode scalar") from exc
            if size > 65_536 or "\x00" in item:
                raise PackageError("unsafe or oversized JSON string")
            budget += size
        elif type(item) is int and abs(item) > 9_007_199_254_740_991:
            raise PackageError("integer is not exactly portable")
        elif not isinstance(item, (int, bool, type(None))):
            raise PackageError("unsupported manifest value")
    check(value)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    if len(encoded) > 1_048_576:
        raise PackageError("JSON document exceeds size limit")
    return encoded


def secure_read(path: Path, limit: int, *, secret: bool = False, dir_fd: int | None = None) -> bytes:
    """Validate the opened inode, not merely the pathname checked earlier."""
    def check(info: os.stat_result) -> None:
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise PackageError("file must be bounded and regular")
        if secret:
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise PackageError("private key must be owner-controlled with mode 0600")
    before = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    check(before)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags, dir_fd=dir_fd)
    try:
        opened = os.fstat(descriptor)
        check(opened)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise PackageError("file changed while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(descriptor)
        check(after)
        if len(data) > limit or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise PackageError("file grew or changed during read")
        return data
    finally:
        os.close(descriptor)


@contextmanager
def directory_fd(root: Path, parts: tuple[str, ...] = (), *, create: bool = False):
    """Walk below a caller-selected root using no-follow directory descriptors."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    if root.is_symlink():
        raise PackageError("directory must not be a symlink")
    descriptor = os.open(root, flags)
    try:
        for part in (None, *parts):
            if part is not None:
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise PackageError("directory must be owner-controlled and not group/other writable")
        yield descriptor
    finally:
        os.close(descriptor)


def _safe_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise PackageError("package path must be a string")
    path = PurePosixPath(value)
    if not value or len(value) > 1024 or path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise PackageError(f"unsafe package path: {value!r}")
    if any(len(part.encode("utf-8")) > 255 or any(c in part for c in '\\:*?"<>|') or any(ord(c) < 32 for c in part)
           or part.endswith((".", " ")) or re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part) for part in path.parts):
        raise PackageError(f"invalid package path: {value!r}")
    return path


def validate_manifest(document: dict[str, Any]) -> None:
    canonical(document)
    if set(document) != MANIFEST_KEYS or type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise PackageError("unknown/missing manifest fields or schema version")
    if not isinstance(document["kind"], str) or document["kind"] not in KINDS or not isinstance(document["id"], str) or not IDENTITY.fullmatch(document["id"]):
        raise PackageError("invalid package kind or id")
    if not isinstance(document["version"], str) or not VERSION.fullmatch(document["version"]):
        raise PackageError("version must be strict SemVer major.minor.patch")
    if not isinstance(document["signer"], str) or not IDENTITY.fullmatch(document["signer"]):
        raise PackageError("invalid signer id")
    if not isinstance(document["signature"], str) or not re.fullmatch(r"[0-9a-f]{128}", document["signature"]):
        raise PackageError("invalid Ed25519 signature encoding")
    files = document["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise PackageError("package file count is out of range")
    seen: set[str] = set()
    total = 0
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != FILE_KEYS:
            raise PackageError("unknown or missing package-file fields")
        path = str(_safe_relative(entry.get("path")))
        if path == "package.json" or path.casefold() in seen or any(path.casefold().startswith(p + "/") or p.startswith(path.casefold() + "/") for p in seen):
            raise PackageError("duplicate package file path")
        seen.add(path.casefold())
        size = entry.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= MAX_FILE_BYTES:
            raise PackageError("package file size is out of range")
        total += size
        if total > MAX_PACKAGE_BYTES or not isinstance(entry.get("executable"), bool):
            raise PackageError("package total size or executable flag is invalid")
        if not isinstance(entry.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise PackageError("invalid package file digest")


def _signed_payload(document: dict[str, Any]) -> bytes:
    unsigned = dict(document)
    unsigned.pop("signature", None)
    return canonical(unsigned)


def _secure_private_key(path: Path) -> Ed25519PrivateKey:
    data = secure_read(path, 16_384, secret=True)
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise PackageError("private key is not Ed25519")
    return key


def load_trust(path: Path) -> dict[str, Ed25519PublicKey]:
    document = strict_json(secure_read(path, 1_048_576))
    if set(document) != {"schema_version", "signers"} or type(document["schema_version"]) is not int or document["schema_version"] != 1 or not isinstance(document["signers"], dict):
        raise PackageError("invalid trust-store schema")
    result = {}
    for signer, encoded in document["signers"].items():
        if not IDENTITY.fullmatch(signer) or not isinstance(encoded, str) or not re.fullmatch(r"[0-9a-f]{64}", encoded):
            raise PackageError("invalid trust-store signer")
        result[signer] = Ed25519PublicKey.from_public_bytes(bytes.fromhex(encoded))
    return result


class PackageSource:
    def __init__(self, source: Path):
        self.source = source
        self.archive: zipfile.ZipFile | None = None
        if source.is_symlink():
            raise PackageError("package source must not be a symlink")
        if source.is_file():
            self.archive = zipfile.ZipFile(io.BytesIO(secure_read(source, MAX_PACKAGE_BYTES + 16 * 1024 * 1024)))
            names = [item.filename for item in self.archive.infolist()]
            if len(names) != len(set(names)) or len(names) > MAX_FILES + 1:
                raise PackageError("archive has duplicate or excessive entries")
            for item in self.archive.infolist():
                _safe_relative(item.filename)
                mode = item.external_attr >> 16
                if stat.S_IFMT(mode) not in {0, stat.S_IFREG} or item.is_dir() or item.file_size > MAX_FILE_BYTES:
                    raise PackageError("archive contains a symlink or oversized entry")
        elif not source.is_dir():
            raise PackageError("package source must be a directory or ZIP")

    def read(self, relative: str) -> bytes:
        safe = str(_safe_relative(relative))
        if self.archive is not None:
            try:
                with self.archive.open(safe) as stream:
                    return stream.read(MAX_FILE_BYTES + 1)
            except KeyError as exc:
                raise PackageError(f"missing package file: {safe}") from exc
        parts = PurePosixPath(safe).parts
        with directory_fd(self.source, parts[:-1]) as parent:
            return secure_read(Path(parts[-1]), MAX_FILE_BYTES, dir_fd=parent)

    def close(self) -> None:
        if self.archive is not None:
            self.archive.close()


def verify_package(source: Path, trust_path: Path) -> tuple[dict[str, Any], PackageSource]:
    package = PackageSource(source)
    try:
        manifest = strict_json(package.read("package.json"))
        validate_manifest(manifest)
        if package.archive is not None and set(package.archive.namelist()) != {"package.json", *(entry["path"] for entry in manifest["files"])}:
            raise PackageError("archive contains files outside its signed manifest")
        key = load_trust(trust_path).get(manifest["signer"])
        if key is None:
            raise PackageError("package signer is not trusted")
        try:
            key.verify(bytes.fromhex(manifest["signature"]), _signed_payload(manifest))
        except InvalidSignature as exc:
            raise PackageError("package manifest signature verification failed") from exc
        for entry in manifest["files"]:
            data = package.read(entry["path"])
            if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise PackageError(f"package file verification failed: {entry['path']}")
        return manifest, package
    except Exception:
        package.close()
        raise


def atomic_json(path: Path, document: dict[str, Any], mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(document, output, sort_keys=True, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def install_package(source: Path, trust: Path, root: Path, activate: bool) -> dict[str, Any]:
    manifest, package = verify_package(source, trust)
    try:
        base = root / manifest["kind"] / manifest["id"]
        versions = base / "versions"
        versions.mkdir(parents=True, exist_ok=True)
        destination = versions / manifest["version"]
        if destination.exists() or destination.is_symlink():
            raise PackageError("this package version is already installed")
        temporary = Path(tempfile.mkdtemp(prefix=".install-", dir=versions))
        try:
            for entry in manifest["files"]:
                data = package.read(entry["path"])
                if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                    raise PackageError("package changed after signature verification")
                target = temporary.joinpath(*PurePosixPath(entry["path"]).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                target.chmod(0o755 if entry["executable"] else 0o644)
            atomic_json(temporary / "package.json", manifest)
            os.rename(temporary, destination)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        if activate:
            atomic_json(base / "active.json", {"schema_version": 1, "version": manifest["version"]})
        return manifest
    finally:
        package.close()


def activate(root: Path, kind: str, package_id: str, version: str) -> None:
    if kind not in KINDS or not IDENTITY.fullmatch(package_id) or not VERSION.fullmatch(version):
        raise PackageError("invalid package selector")
    base = root / kind / package_id
    if not (base / "versions" / version / "package.json").is_file():
        raise PackageError("requested installed version does not exist")
    atomic_json(base / "active.json", {"schema_version": 1, "version": version})


def list_packages(root: Path) -> list[dict[str, str | bool]]:
    rows = []
    for kind in sorted(KINDS):
        kind_dir = root / kind
        if not kind_dir.is_dir():
            continue
        for package_dir in sorted(kind_dir.iterdir()):
            if not package_dir.is_dir() or not IDENTITY.fullmatch(package_dir.name):
                continue
            active = ""
            active_file = package_dir / "active.json"
            if active_file.is_file() and not active_file.is_symlink():
                document = strict_json(active_file.read_bytes(), 4096)
                if set(document) == {"schema_version", "version"} and document["schema_version"] == 1:
                    active = document["version"]
            versions = package_dir / "versions"
            if versions.is_dir():
                for version_dir in sorted(versions.iterdir()):
                    if version_dir.is_dir() and VERSION.fullmatch(version_dir.name):
                        rows.append({"kind": kind, "id": package_dir.name, "version": version_dir.name, "active": version_dir.name == active})
    return rows


def keygen(private_path: Path, trust_path: Path, signer: str) -> None:
    if not IDENTITY.fullmatch(signer) or private_path.exists() or trust_path.exists():
        raise PackageError("invalid signer or output already exists")
    key = Ed25519PrivateKey.generate()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    atomic_json(trust_path, {"schema_version": 1, "signers": {signer: public}})


def build_package(payload: Path, output: Path, private_key: Path, signer: str, kind: str, package_id: str, version: str) -> None:
    if kind not in KINDS or not IDENTITY.fullmatch(package_id) or not VERSION.fullmatch(version) or not IDENTITY.fullmatch(signer):
        raise PackageError("invalid package metadata")
    if payload.is_symlink() or not payload.is_dir() or output.exists():
        raise PackageError("payload must be a directory and output must not exist")
    entries = []
    paths = sorted(path for path in payload.rglob("*") if path.is_file())
    if not paths or len(paths) > MAX_FILES:
        raise PackageError("payload file count is out of range")
    total = 0
    for path in paths:
        if path.is_symlink():
            raise PackageError("payload symlinks are forbidden")
        relative = path.relative_to(payload).as_posix()
        _safe_relative(relative)
        data = path.read_bytes()
        total += len(data)
        if len(data) > MAX_FILE_BYTES or total > MAX_PACKAGE_BYTES:
            raise PackageError("payload is too large")
        entries.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "executable": bool(path.stat().st_mode & stat.S_IXUSR)})
    manifest = {"schema_version": 1, "kind": kind, "id": package_id, "version": version, "files": entries, "signer": signer, "signature": ""}
    manifest["signature"] = _secure_private_key(private_key).sign(_signed_payload(manifest)).hex()
    validate_manifest(manifest)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr("package.json", json.dumps(manifest, sort_keys=True, ensure_ascii=False, indent=2) + "\n")
        for entry in entries:
            archive.write(payload / entry["path"], entry["path"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Shadow6 signed package/version manager")
    commands = parser.add_subparsers(dest="command", required=True)
    key = commands.add_parser("keygen"); key.add_argument("--private-key", type=Path, required=True); key.add_argument("--trust", type=Path, required=True); key.add_argument("--signer", required=True)
    build = commands.add_parser("build"); build.add_argument("payload", type=Path); build.add_argument("--output", type=Path, required=True); build.add_argument("--private-key", type=Path, required=True); build.add_argument("--signer", required=True); build.add_argument("--kind", choices=sorted(KINDS), required=True); build.add_argument("--id", required=True); build.add_argument("--version", required=True)
    verify = commands.add_parser("verify"); verify.add_argument("package", type=Path); verify.add_argument("--trust", type=Path, required=True)
    install = commands.add_parser("install"); install.add_argument("package", type=Path); install.add_argument("--trust", type=Path, required=True); install.add_argument("--root", type=Path, required=True); install.add_argument("--no-activate", action="store_true")
    listing = commands.add_parser("list"); listing.add_argument("--root", type=Path, required=True); listing.add_argument("--json", action="store_true")
    switch = commands.add_parser("activate"); switch.add_argument("kind", choices=sorted(KINDS)); switch.add_argument("id"); switch.add_argument("version"); switch.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "keygen": keygen(args.private_key, args.trust, args.signer)
    elif args.command == "build": build_package(args.payload, args.output, args.private_key, args.signer, args.kind, args.id, args.version)
    elif args.command == "verify":
        manifest, source = verify_package(args.package, args.trust); source.close(); print(f"verified {manifest['kind']}/{manifest['id']} {manifest['version']}")
    elif args.command == "install":
        manifest = install_package(args.package, args.trust, args.root, not args.no_activate); print(f"installed {manifest['kind']}/{manifest['id']} {manifest['version']}")
    elif args.command == "activate": activate(args.root, args.kind, args.id, args.version)
    else:
        rows = list_packages(args.root)
        if args.json: print(json.dumps(rows, ensure_ascii=False, indent=2))
        else:
            for row in rows: print(f"{row['kind']}\t{row['id']}\t{row['version']}\t{'active' if row['active'] else 'inactive'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, PackageError, zipfile.BadZipFile) as exc:
        print(f"shadow6-pkg: {exc}", file=__import__("sys").stderr)
        raise SystemExit(2)
