#!/usr/bin/env python3
"""Crosed signed request builder and local Core negotiation client."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


CAPABILITY_LEVELS = {
    "observe.version": 1, "observe.health": 1,
    "policy.request": 2, "policy.config": 2,
    "transport.metadata": 3, "transport.application": 3,
    "identity.assert": 4, "identity.resolve": 4,
    "core.lifecycle": 5, "core.hook": 5,
}
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
DOMAIN_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")


class CrosedError(RuntimeError):
    pass


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CrosedError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def strict_json(data: bytes, limit: int = 1024 * 1024) -> dict[str, Any]:
    if len(data) > limit:
        raise CrosedError("JSON document exceeds size limit")
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        reject_number = lambda _: (_ for _ in ()).throw(CrosedError("floats/nonfinite numbers are forbidden"))
        value = json.loads(text, object_pairs_hook=_reject_duplicate, parse_float=reject_number, parse_constant=reject_number)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise CrosedError("invalid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CrosedError("JSON document must be an object")
    canonical(value)
    return value


def canonical(value: Any) -> bytes:
    budget = 0
    def check(item: Any, depth: int = 0) -> None:
        nonlocal budget
        budget += 1
        if budget > 1_048_576:
            raise CrosedError("JSON document exceeds size limit")
        if depth > 32 or isinstance(item, float):
            raise CrosedError("manifest nesting is excessive or contains a float")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 256:
                    raise CrosedError("invalid manifest key")
                check(key, depth + 1)
                check(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                check(child, depth + 1)
        elif isinstance(item, str):
            try:
                size = len(item.encode("utf-8"))
            except UnicodeError as exc:
                raise CrosedError("invalid Unicode scalar") from exc
            if size > 65_536 or "\x00" in item:
                raise CrosedError("unsafe or oversized JSON string")
            budget += size
        elif type(item) is int and abs(item) > 9_007_199_254_740_991:
            raise CrosedError("integer is not exactly portable")
        elif not isinstance(item, (int, bool, type(None))):
            raise CrosedError("unsupported manifest value")
    check(value)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    if len(encoded) > 1_048_576:
        raise CrosedError("JSON document exceeds size limit")
    return encoded


def secure_read(path: Path, limit: int, *, secret: bool = False, dir_fd: int | None = None) -> bytes:
    """Validate the opened inode, not merely the pathname checked earlier."""
    def check(info: os.stat_result) -> None:
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise CrosedError("file must be bounded and regular")
        if info.st_uid not in ({os.geteuid()} if secret else {0, os.geteuid()}) or info.st_mode & 0o022:
            raise CrosedError("file must be owner-controlled and not group/other writable")
        if secret and stat.S_IMODE(info.st_mode) != 0o600:
            raise CrosedError("private key must have mode 0600")
    before = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    check(before)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags, dir_fd=dir_fd)
    try:
        opened = os.fstat(descriptor)
        check(opened)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise CrosedError("file changed while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(descriptor)
        check(after)
        if len(data) > limit or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise CrosedError("file grew or changed during read")
        return data
    finally:
        os.close(descriptor)



def read_owner_only(path: Path, limit: int = 65_536) -> bytes:
    return secure_read(path, limit, secret=True)


def atomic_owner_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".crosed-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def signed_payload(request: dict[str, Any]) -> bytes:
    validate_payload(request["payload"])
    capabilities = sorted(request["capabilities"])
    payload = json.dumps(request["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "\n".join(
        [
            str(request["version"]), request["mod_id"], request["nonce"], str(request["issued_at"]),
            str(request["requested_level"]), ",".join(capabilities), hashlib.sha256(payload).hexdigest(),
            request.get("source_domain", ""), request.get("target_domain", ""),
        ]
    ).encode()


def validate_payload(value: Any, depth: int = 0) -> None:
    if depth > 16:
        raise CrosedError("Crosed payload nesting is too deep")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 9_007_199_254_740_991:
            raise CrosedError("Crosed integers must be exactly portable across Core languages")
        return
    if isinstance(value, str):
        try:
            size = len(value.encode("utf-8"))
        except UnicodeError as exc:
            raise CrosedError("invalid Unicode scalar") from exc
        if "\x00" in value or size > 16_384:
            raise CrosedError("Crosed UTF-8 string is unsafe or oversized")
        return
    if isinstance(value, list):
        for item in value:
            validate_payload(item, depth + 1)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for key, item in value.items():
            validate_payload(key, depth + 1)
            validate_payload(item, depth + 1)
        return
    raise CrosedError("Crosed payload supports only portable JSON types (floats are forbidden)")


def build_request(
    mod_id: str, level: int, capabilities: list[str], payload: dict[str, Any],
    private_key: Ed25519PrivateKey, source_domain: str = "", target_domain: str = "",
) -> dict[str, Any]:
    if not isinstance(mod_id, str) or not ID_RE.fullmatch(mod_id) or type(level) is not int or not 1 <= level <= 5:
        raise CrosedError("invalid Mod id or requested level")
    if not isinstance(payload, dict) or not isinstance(capabilities, list) or len(capabilities) > len(CAPABILITY_LEVELS) or any(not isinstance(c, str) for c in capabilities):
        raise CrosedError("payload must be an object and capabilities a bounded string list")
    if not isinstance(source_domain, str) or not isinstance(target_domain, str):
        raise CrosedError("domains must be strings")
    if len(capabilities) != len(set(capabilities)):
        raise CrosedError("duplicate capability")
    for capability in capabilities:
        required = CAPABILITY_LEVELS.get(capability)
        if required is None or required > level:
            raise CrosedError(f"capability {capability} is unavailable at level {level}")
    if source_domain and not DOMAIN_RE.fullmatch(source_domain):
        raise CrosedError("invalid source domain")
    if target_domain and not DOMAIN_RE.fullmatch(target_domain):
        raise CrosedError("invalid target domain")
    validate_payload(payload)
    if len(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")) > 32_768:
        raise CrosedError("Crosed payload is too large")
    validate_payload(payload)
    request = {
        "version": 1, "mod_id": mod_id, "nonce": os.urandom(16).hex(),
        "issued_at": int(time.time()), "requested_level": level,
        "capabilities": sorted(capabilities), "source_domain": source_domain,
        "target_domain": target_domain, "payload": payload,
    }
    request["signature"] = private_key.sign(signed_payload(request)).hex()
    return request


def inspect_binary(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise CrosedError("Core binary must be owner-controlled and not group/other writable")
    completed = subprocess.run([str(resolved), "--feature-report"], capture_output=True, text=True, timeout=5, check=False)
    if completed.returncode != 0:
        raise CrosedError(f"Core feature query failed: {completed.stderr.strip()}")
    report = json.loads(completed.stdout)
    required = {"core", "version", "crosed_compiled", "crosed_max_level", "app_transport", "qubes_isolation", "gate_compiled", "gate_enabled_by_default", "utf8", "crosed_capabilities"}
    if set(report) != required:
        raise CrosedError("Core returned an invalid feature report")
    return report


def negotiate(core: Path, request: Path, trust: Path) -> dict[str, Any]:
    report = inspect_binary(core)
    completed = subprocess.run(
        [str(core.resolve()), "--crosed-request", str(request.resolve()), "--crosed-trust", str(trust.resolve())],
        capture_output=True, text=True, timeout=5, check=False,
    )
    if completed.returncode != 0:
        raise CrosedError(f"Core rejected Crosed input: {completed.stderr.strip()}")
    response = json.loads(completed.stdout)
    if response.get("core") != report["core"] or response.get("version") != report["version"]:
        raise CrosedError("Core response does not match its feature report")
    return response


def main() -> int:
    parser = argparse.ArgumentParser(description="Shadow6 Crosed control utility")
    commands = parser.add_subparsers(dest="command", required=True)
    features = commands.add_parser("features")
    features.add_argument("cores", nargs="+", type=Path)
    request = commands.add_parser("request")
    request.add_argument("--mod-id", required=True)
    request.add_argument("--level", type=int, required=True)
    request.add_argument("--capability", action="append", default=[])
    request.add_argument("--payload", default="{}")
    request.add_argument("--source-domain", default="")
    request.add_argument("--target-domain", default="")
    request.add_argument("--private-key", required=True, type=Path)
    request.add_argument("--output", required=True, type=Path)
    negotiation = commands.add_parser("negotiate")
    negotiation.add_argument("--core", required=True, type=Path)
    negotiation.add_argument("--request", required=True, type=Path)
    negotiation.add_argument("--trust", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "features":
        print(json.dumps([inspect_binary(path) for path in args.cores], ensure_ascii=False, indent=2))
    elif args.command == "request":
        key = serialization.load_pem_private_key(read_owner_only(args.private_key, 16_384), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise CrosedError("Mod private key must be Ed25519")
        payload = strict_json(args.payload, 32_768)
        if not isinstance(payload, dict):
            raise CrosedError("payload must be a JSON object")
        document = build_request(args.mod_id, args.level, args.capability, payload, key, args.source_domain, args.target_domain)
        atomic_owner_write(args.output, json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
        print(f"wrote signed Crosed request to {args.output}")
    else:
        print(json.dumps(negotiate(args.core, args.request, args.trust), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CrosedError, json.JSONDecodeError, ValueError) as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(2)
