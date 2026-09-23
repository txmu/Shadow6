#!/usr/bin/env python3
"""Fail closed when a release archive violates Shadow6's package contract."""

from __future__ import annotations

import argparse
import sys
import tarfile
import zipfile
from pathlib import PurePosixPath


FORBIDDEN_ZIP_DIRS = {
    ".venv", ".venv-ft", ".tools", ".nim_runtime", ".android-toolchain", "__pycache__", "target",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".hypothesis", ".tox", ".nox", ".cache",
    ".gradle", "build", "dist", ".zig-cache", "zig-out",
}
FORBIDDEN_ZIP_FILES = {"config.mk"}
FORBIDDEN_ZIP_NAMES = (".apk", ".der", ".pem", ".p12")
REQUIRED_TAR_FILES = {
    "Core-Go/shadow6-go",
    "Core-Go/shadow6-go-crosed",
    "Core-Rust/shadow6-rust",
    "Core-Rust/shadow6-rust-crosed",
}
MAX_MEMBERS = 250_000
MAX_MEMBER_NAME = 4096


def safe_member_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name.rstrip("/"))
    if not path.is_absolute() and ".." not in path.parts:
        return path
    raise ValueError(f"unsafe archive member path: {name}")


def check_tar(path: str, project_root: str = "Shadow6") -> None:
    found = set()
    prefix = f"{project_root}/"
    with tarfile.open(path, "r:gz") as archive:
        for index, member in enumerate(archive):
            if index >= MAX_MEMBERS:
                raise ValueError("tar archive has too many members")
            if len(member.name) > MAX_MEMBER_NAME:
                raise ValueError("tar member name is too long")
            member_path = safe_member_name(member.name[len(prefix):] if member.name.startswith(prefix) else member.name)
            if member.isfile():
                found.add(str(member_path))
            if member.issym() or member.islnk():
                target = PurePosixPath(member.linkname.rstrip("/"))
                if target.is_absolute() or ".." in target.parts:
                    raise ValueError(f"unsafe archive link: {member.name}")
    missing = REQUIRED_TAR_FILES - found
    if missing:
        raise ValueError(f"tar is missing required binaries: {', '.join(sorted(missing))}")


def check_zip(path: str) -> None:
    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
        if len(infos) > MAX_MEMBERS:
            raise ValueError("zip archive has too many members")
        for info in infos:
            if len(info.filename) > MAX_MEMBER_NAME:
                raise ValueError("zip member name is too long")
            member_path = safe_member_name(info.filename)
            if info.is_dir():
                continue
            if member_path.suffix != ".txt":
                raise ValueError(f"non-text zip member: {info.filename}")
            if "config.mk" in member_path.parts or "config.mk.txt" in member_path.parts:
                raise ValueError(f"forbidden zip member: {info.filename}")
            if any(part in FORBIDDEN_ZIP_DIRS for part in member_path.parts):
                raise ValueError(f"forbidden zip directory: {info.filename}")
            if any(part.endswith(FORBIDDEN_ZIP_NAMES) for part in member_path.parts):
                raise ValueError(f"binary or secret-like zip member: {info.filename}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tar", help="Shadow6.tar.gz")
    parser.add_argument("--zip", help="Shadow6.zip")
    args = parser.parse_args()
    if not (args.tar or args.zip):
        parser.error("provide at least one archive")
    try:
        if args.tar:
            check_tar(args.tar)
            print(f"PASS {args.tar}: bounded paths and required Core binaries")
        if args.zip:
            check_zip(args.zip)
            print(f"PASS {args.zip}: text-only source exchange contract")
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
