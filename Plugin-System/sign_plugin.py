#!/usr/bin/env python3
"""Sign a Shadow6 plugin manifest with an external Ed25519 private key."""

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def read_private_key(path: Path) -> bytes:
    if path.is_symlink():
        raise ValueError("private key must not be a symlink")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise PermissionError("private key must be owner-controlled with mode 0600")
        if metadata.st_size > 16_384:
            raise ValueError("private key file is too large")
        return os.read(descriptor, 16_385)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--private-key", type=Path, required=True, help="PEM Ed25519 private key")
    parser.add_argument("--signer", required=True)
    args = parser.parse_args()
    if args.manifest.is_symlink():
        raise ValueError("manifest must not be a symlink")
    manifest_path = args.manifest.resolve(strict=True)
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    unresolved_entrypoint = manifest_path.parent / document["entrypoint"]
    if unresolved_entrypoint.is_symlink():
        raise ValueError("entrypoint must not be a symlink")
    entrypoint = unresolved_entrypoint.resolve(strict=True)
    if entrypoint.parent != manifest_path.parent.resolve():
        raise ValueError("entrypoint escapes the plugin directory")
    private_key = serialization.load_pem_private_key(read_private_key(args.private_key), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("private key must be Ed25519")
    document["sha256"] = hashlib.sha256(entrypoint.read_bytes()).hexdigest()
    document["signer"] = args.signer
    document.pop("signature", None)
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    document["signature"] = private_key.sign(payload).hex()
    rendered = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".plugin.", suffix=".json", dir=manifest_path.parent)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, manifest_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    print(f"signed {manifest_path}; trust-store public key: {public.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
