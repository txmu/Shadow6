#!/usr/bin/env python3
"""Composable defensive infrastructure assistants for Shadow6."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import unicodedata
import uuid
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


VERSION = "1.0.0"
MAX_JSON = 1_048_576
MAX_LEDGER = 16 * 1024 * 1024
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ASSISTANTS = {
    "doctor": "read-only deployment, permission, feature-contract and integrity checks",
    "sbom": "offline CycloneDX software and binary inventory",
    "policy": "deny-by-default deployment policy evaluator",
    "ledger": "Ed25519-signed hash-chain audit ledger with a signed checkpoint",
}
COMPONENTS = {
    "core-go": {"source": "Core-Go/main.go", "binaries": ["Core-Go/shadow6-go", "Core-Go/shadow6-go-crosed"]},
    "core-rust": {"source": "Core-Rust/src/main.rs", "binaries": ["Core-Rust/shadow6-rust", "Core-Rust/shadow6-rust-crosed"]},
    "guard": {"source": "Guard/main.go", "binaries": ["Guard/shadow6-guard"]},
    "relay": {"source": "C11Relay/c11relay.c", "binaries": ["C11Relay/bridge_relay"]},
    "gate": {"source": "Gate/main.go", "binaries": ["Gate/shadow6-gate"]},
    "orchestrator": {"source": "Auto-Orchestrator/shadow6_auto.py", "binaries": []},
    "detector": {"source": "Detector/detector_core.py", "binaries": []},
    "plugins": {"source": "Plugin-System/shadow6_plugins.py", "binaries": []},
    "crosed": {"source": "Crosed/crosedctl.py", "binaries": []},
    "application": {"source": "Application-Layer/shadow_protocols.py", "binaries": []},
    "security-assistants": {"source": "Security-Assistants/shadow6_security.py", "binaries": []},
    "infrastructure-assistants": {"source": "Infrastructure-Assistants/shadow6_infra.py", "binaries": []},
    "control-center": {"source": "Control-Center/shadow6_control.py", "binaries": []},
    "slots": {"source": "Slot-System/shadow6_slots.py", "binaries": []},
    "service-init": {"source": "Service-Init/shadow6_init.py", "binaries": []},
    "migration": {"source": "Migration/shadow6_migrate.py", "binaries": []},
    "online-repository": {"source": "Online-Repository/shadow6_repo.py", "binaries": []},
    "android": {"source": "Android/app/src/main/java/org/shadow6/android/MainActivity.kt",
                "binaries": ["Android/dist/shadow6-android-debug.apk", "Android/app/build/outputs/apk/debug/app-debug.apk"]},
}


class SecurityError(RuntimeError):
    pass


def canonical(document: Any) -> bytes:
    validate_portable(document)
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def strict_json_loads(raw: bytes | str, limit: int = MAX_JSON) -> Any:
    """Parse bounded UTF-8 portable JSON, rejecting ambiguous signed inputs."""
    if type(limit) is not int or limit < 1:
        raise SecurityError("JSON limit must be a positive integer")
    if not isinstance(raw, (bytes, str)) or len(raw) > limit:
        raise SecurityError("JSON input is invalid or oversized")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise SecurityError("JSON contains a duplicate key")
            result[key] = value
        return result

    def reject_number(value: str) -> Any:
        raise SecurityError("JSON floats and non-finite numbers are forbidden")

    try:
        text = raw.decode("utf-8", errors="strict") if isinstance(raw, bytes) else raw
        if len(text.encode("utf-8")) > limit:
            raise SecurityError("JSON input is oversized")
        # Bound nesting before the decoder allocates deeply nested containers.
        depth, quoted, escaped = 0, False, False
        for character in text:
            if quoted:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    quoted = False
            elif character == '"':
                quoted = True
            elif character in "[{":
                depth += 1
                if depth > 17:
                    raise SecurityError("JSON nesting exceeds 16 levels")
            elif character in "]}":
                depth -= 1
        document = json.loads(text, object_pairs_hook=pairs, parse_float=reject_number,
                              parse_constant=reject_number)
        validate_portable(document)
        return document
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise SecurityError("invalid portable UTF-8 JSON") from exc


def validate_portable(value: Any, depth: int = 0) -> None:
    if depth > 16:
        raise SecurityError("JSON nesting exceeds 16 levels")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 9_007_199_254_740_991:
            raise SecurityError("integer is not exactly portable")
        return
    if isinstance(value, str):
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise SecurityError("string is not valid UTF-8") from exc
        if "\x00" in value or len(encoded) > 65_536:
            raise SecurityError("string contains NUL or is oversized")
        if not unicodedata.is_normalized("NFC", value):
            raise SecurityError("JSON strings must use NFC normalization")
        return
    if isinstance(value, list):
        for item in value:
            validate_portable(item, depth + 1)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for key, item in value.items():
            validate_portable(key, depth + 1)
            validate_portable(item, depth + 1)
        return
    raise SecurityError("only portable JSON values are accepted; floats are forbidden")


def _check_file(metadata: os.stat_result, path: Path, limit: int, secret: bool) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise SecurityError(f"path must be a regular non-symlink file: {path}")
    if secret and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise SecurityError(f"secret file must be owner-controlled with mode 0600: {path}")
    if metadata.st_size > limit:
        raise SecurityError(f"file exceeds {limit} bytes: {path}")


def _read_descriptor(descriptor: int, limit: int) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(65_536, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise SecurityError(f"file exceeds {limit} bytes")


@contextmanager
def _locked_file(path: Path, limit: int, *, create: bool = False, exclusive: bool = True):
    """Bound lock acquisition and recheck the locked, nonblocking-opened inode."""
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
        raise SecurityError("state parent must be an owner-controlled non-symlink directory")
    flags = (os.O_RDWR if exclusive else os.O_RDONLY) | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags | (os.O_CREAT if create else 0), 0o600)
    try:
        _check_file(os.fstat(descriptor), path, limit, True)
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(descriptor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise SecurityError("state lock timed out")
                time.sleep(0.01)
        opened, named = os.fstat(descriptor), path.lstat()
        _check_file(opened, path, limit, True)
        _check_file(named, path, limit, True)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise SecurityError("state path changed while locking")
        yield descriptor
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise SecurityError("state write made no progress")
        view = view[written:]


def _hex_bytes(value: Any, length: int, label: str) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{%d}" % (2 * length), value) is None:
        raise SecurityError(f"invalid canonical {label}")
    return bytes.fromhex(value)


def secure_read(path: Path, limit: int = MAX_JSON, *, secret: bool = False) -> bytes:
    if type(limit) is not int or limit < 1:
        raise SecurityError("file limit must be a positive integer")
    before = path.lstat()
    _check_file(before, path, limit, secret)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        _check_file(opened, path, limit, secret)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise SecurityError("file changed while being opened")
        data = _read_descriptor(descriptor, limit)
        _check_file(os.fstat(descriptor), path, limit, secret)
        return data
    finally:
        os.close(descriptor)


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise SecurityError("refusing to replace a symlink")
    descriptor, temporary = tempfile.mkstemp(prefix=".shadow6-security-", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sha256_file(path: Path, limit: int = 128 * 1024 * 1024) -> str:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise SecurityError(f"unsafe or oversized inventory path: {path}")
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > limit or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise SecurityError("inventory file changed while opening")
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise SecurityError("inventory file grew beyond size limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise SecurityError("inventory file changed while reading")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def bounded_run(command: list[str], cwd: Path, timeout: float,
                max_output: int = MAX_JSON, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run a trusted argv with a hard deadline and a combined output byte cap.

    POSIX children get a new session. TimeoutExpired signals the deadline;
    SecurityError signals excess output or invalid UTF-8. Never invokes a shell.
    """
    if (not isinstance(command, list) or not command or
            any(not isinstance(arg, str) or "\x00" in arg for arg in command) or
            isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or
            not math.isfinite(timeout) or timeout <= 0 or
            type(max_output) is not int or not 1 <= max_output <= MAX_LEDGER):
        raise SecurityError("invalid bounded command, timeout, or output limit")
    if os.name != "posix":
        raise SecurityError("bounded process groups require POSIX on this assistant platform")
    deadline = time.monotonic() + timeout
    output = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    with selectors.DefaultSelector() as selector:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, close_fds=True)
        try:
            for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, min(65_536, max_output + 1 - total))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > max_output:
                        raise SecurityError(f"command output exceeds {max_output} bytes")
                    output[key.data].extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            returncode = process.wait(timeout=remaining)
        except BaseException:
            # Only this child's session/process group; no PID or name search.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            raise
        finally:
            process.stdout.close()
            process.stderr.close()
    try:
        return subprocess.CompletedProcess(command, returncode,
                                           output["stdout"].decode("utf-8", errors="strict"),
                                           output["stderr"].decode("utf-8", errors="strict"))
    except UnicodeError as exc:
        raise SecurityError("command output is not valid UTF-8") from exc


def run_json(command: list[str], cwd: Path, timeout: int = 10) -> dict[str, Any]:
    completed = bounded_run(command, cwd, timeout)
    if completed.returncode != 0:
        raise SecurityError((completed.stderr or completed.stdout).strip() or "command failed")
    result = strict_json_loads(completed.stdout)
    if not isinstance(result, dict):
        raise SecurityError("command returned a non-object")
    return result


def feature_report(binary: Path, root: Path) -> dict[str, Any]:
    metadata = binary.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_mode & 0o022:
        raise SecurityError(f"unsafe Core binary permissions: {binary}")
    report = run_json([str(binary.resolve()), "--feature-report"], root)
    _validate_feature_report(report)
    return report


def _validate_feature_report(report: dict[str, Any]) -> None:
    boolean_fields = {"crosed_compiled", "app_transport", "qubes_isolation", "gate_compiled", "gate_enabled_by_default", "utf8"}
    required = boolean_fields | {"core", "version", "crosed_max_level", "crosed_capabilities"}
    if (not isinstance(report, dict) or set(report) != required or
            any(type(report[field]) is not bool for field in boolean_fields) or
            type(report["crosed_max_level"]) is not int or not 0 <= report["crosed_max_level"] <= 5 or
            any(not isinstance(report[field], str) or not SAFE_TOKEN.fullmatch(report[field]) for field in ("core", "version"))):
        raise SecurityError("invalid Core feature report schema")
    _token_list(report["crosed_capabilities"], "Core capabilities")


def doctor(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": passed, "detail": detail})

    required = [definition["source"] for definition in COMPONENTS.values()] + ["shadow6_audit.py", "Makefile"]
    missing = [item for item in required if not (root / item).is_file()]
    record("component-surface", not missing, "complete" if not missing else f"missing: {missing}")

    fields = ("version", "crosed_max_level", "app_transport", "qubes_isolation", "gate_compiled", "gate_enabled_by_default", "utf8", "crosed_capabilities")
    default_reports = []
    for relative in ("Core-Go/shadow6-go", "Core-Rust/shadow6-rust"):
        try:
            default_reports.append(feature_report(root / relative, root))
        except (OSError, SecurityError, subprocess.TimeoutExpired) as exc:
            record(f"feature-report:{relative}", False, str(exc))
    if len(default_reports) == 2:
        parity = all(default_reports[0].get(field) == default_reports[1].get(field) for field in fields)
        record("default-core-parity", parity, "matching" if parity else "Go/Rust contracts differ")
        minimal = all(report.get("crosed_max_level") == 0 and not report.get("app_transport") and not report.get("qubes_isolation") for report in default_reports)
        record("default-minimum-privilege", minimal, "optional privileged features are disabled" if minimal else "default Core has privileged features")

    variant_reports = []
    for relative in ("Core-Go/shadow6-go-crosed", "Core-Rust/shadow6-rust-crosed"):
        path = root / relative
        if path.is_file():
            try:
                variant_reports.append(feature_report(path, root))
            except (OSError, SecurityError, subprocess.TimeoutExpired) as exc:
                record(f"feature-report:{relative}", False, str(exc))
    if variant_reports:
        complete = len(variant_reports) == 2 and all(
            item.get("crosed_max_level") == 5 and item.get("app_transport") is True and item.get("qubes_isolation") is True and item.get("utf8") is True
            for item in variant_reports
        ) and all(variant_reports[0].get(field) == variant_reports[1].get(field) for field in fields)
        record("privileged-variant-contract", complete, "matching L5 variants" if complete else "variant missing or incomplete")

    try:
        _, manifests = _plugin_inventory(root, verify_signatures=True)
        record("signed-plugins", bool(manifests), "all bundled manifests and code digests verified" if manifests else "no bundled manifests")
    except (OSError, SecurityError) as exc:
        record("signed-plugins", False, str(exc))
    try:
        source_audit = bounded_run([sys.executable, str(root / "shadow6_audit.py"), "--source-only"], root, 30)
        record("source-audit", source_audit.returncode == 0, "offline source checks passed" if source_audit.returncode == 0 else source_audit.stdout[-1000:])
    except (OSError, SecurityError, subprocess.TimeoutExpired) as exc:
        record("source-audit", False, str(exc))
    passed = sum(1 for item in checks if item["passed"])
    return {
        "assistant": "doctor", "version": VERSION,
        "status": "pass" if passed == len(checks) else "fail",
        "score": {"passed": passed, "total": len(checks)}, "checks": checks,
    }


def parse_go_modules(path: Path) -> list[dict[str, str]]:
    components = []
    for line in secure_read(path).decode("utf-8").splitlines():
        match = re.match(r"\s*(?:require\s+)?([^\s()]+)\s+(v[0-9][^\s]*)", line)
        if match:
            components.append({"type": "library", "name": match.group(1), "version": match.group(2), "purl": f"pkg:golang/{match.group(1)}@{match.group(2)}"})
    return components


def generate_sbom(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    components: list[dict[str, str]] = []
    for path in (root / "Core-Go/go.mod", root / "Guard/go.mod", root / "Gate/go.mod"):
        components.extend(parse_go_modules(path))
    cargo = tomllib.loads(secure_read(root / "Core-Rust/Cargo.lock").decode("utf-8"))
    for package in cargo.get("package", []):
        name, version = package.get("name"), package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            components.append({"type": "library", "name": name, "version": version, "purl": f"pkg:cargo/{name}@{version}"})
    for requirement_file in (root / "requirements.txt", root / "requirements-ml.txt"):
        for raw in secure_read(requirement_file).decode("utf-8").splitlines():
            line = raw.strip()
            match = re.match(r"^([A-Za-z0-9_.-]+)==([^\s;]+)", line)
            if match:
                components.append({"type": "library", "name": match.group(1), "version": match.group(2), "purl": f"pkg:pypi/{match.group(1).lower()}@{match.group(2)}"})
    for name, definition in COMPONENTS.items():
        if (root / definition["source"]).is_file():
            components.append({"type": "application", "name": f"shadow6-{name}", "version": "1.1.0", "purl": f"pkg:generic/shadow6-{name}@1.1.0"})
    unique = {item["purl"]: item for item in components}
    binaries = []
    for relative in (item for definition in COMPONENTS.values() for item in definition["binaries"]):
        path = root / relative
        if path.is_file():
            metadata = path.lstat()
            binaries.append({"path": relative, "sha256": sha256_file(path), "size": metadata.st_size,
                             "mode": f"{stat.S_IMODE(metadata.st_mode):04o}", "uid": metadata.st_uid, "gid": metadata.st_gid})
    serial_material = canonical({"components": sorted(unique), "binaries": binaries})
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": uuid.uuid5(uuid.NAMESPACE_URL, "shadow6-sbom:" + hashlib.sha256(serial_material).hexdigest()).urn,
        "metadata": {"component": {"type": "application", "name": "Shadow6", "version": "1.1.0"}},
        "components": [unique[key] for key in sorted(unique)],
        "properties": [{"name": "shadow6.binary-inventory", "value": json.dumps(binaries, sort_keys=True, separators=(",", ":"))}],
    }


def generate_ledger_key(private_path: Path, public_path: Path) -> dict[str, str]:
    if private_path.exists() or public_path.exists():
        raise SecurityError("refusing to overwrite an existing ledger key")
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = hashlib.sha256(public).hexdigest()[:16]
    atomic_write(private_path, private_pem, 0o600)
    atomic_write(public_path, canonical({"version": 1, "key_id": key_id, "public_key": public.hex()}) + b"\n", 0o644)
    return {"key_id": key_id, "private_key": str(private_path), "public_key": str(public_path)}


def load_private(path: Path) -> tuple[Ed25519PrivateKey, str]:
    key = serialization.load_pem_private_key(secure_read(path, 16_384, secret=True), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SecurityError("ledger key must be Ed25519")
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, hashlib.sha256(public).hexdigest()[:16]


def load_public(path: Path) -> tuple[Ed25519PublicKey, str]:
    document = strict_json_loads(secure_read(path, 16_384), 16_384)
    if not isinstance(document, dict) or set(document) != {"version", "key_id", "public_key"} or type(document["version"]) is not int or document["version"] != 1:
        raise SecurityError("invalid ledger public-key document")
    raw = _hex_bytes(document["public_key"], 32, "public key")
    if document["key_id"] != hashlib.sha256(raw).hexdigest()[:16]:
        raise SecurityError("ledger public-key id mismatch")
    return Ed25519PublicKey.from_public_bytes(raw), document["key_id"]


def verify_lines(data: bytes, public: Ed25519PublicKey, key_id: str) -> tuple[int, str]:
    if len(data) > MAX_LEDGER:
        raise SecurityError("ledger exceeds 16 MiB")
    if data and not data.endswith(b"\n"):
        raise SecurityError("ledger contains an incomplete record")
    previous = "0" * 64
    sequence = 0
    for raw in data.splitlines():
        if not raw:
            raise SecurityError("ledger contains an empty record")
        event = strict_json_loads(raw)
        required = {"version", "sequence", "timestamp", "event_type", "actor", "payload", "previous_hash", "key_id", "signature"}
        if (not isinstance(event, dict) or set(event) != required or
                type(event["version"]) is not int or event["version"] != 1 or
                type(event["sequence"]) is not int or event["sequence"] != sequence + 1 or
                type(event["timestamp"]) is not int or event["timestamp"] < 0 or
                not isinstance(event["event_type"], str) or not SAFE_TOKEN.fullmatch(event["event_type"]) or
                not isinstance(event["actor"], str) or not SAFE_TOKEN.fullmatch(event["actor"]) or
                not isinstance(event["payload"], dict) or len(canonical(event["payload"])) > 65_536):
            raise SecurityError("ledger schema or sequence is invalid")
        if event["previous_hash"] != previous or event["key_id"] != key_id:
            raise SecurityError("ledger hash chain or signing key does not match")
        unsigned = dict(event)
        try:
            signature = _hex_bytes(unsigned.pop("signature"), 64, "ledger signature")
            public.verify(signature, canonical(unsigned))
        except (ValueError, InvalidSignature) as exc:
            raise SecurityError("ledger signature verification failed") from exc
        validate_portable(event["payload"])
        previous = hashlib.sha256(canonical(event)).hexdigest()
        sequence += 1
    return sequence, previous


def checkpoint_path(ledger: Path) -> Path:
    return ledger.with_name(ledger.name + ".checkpoint")


def append_event(ledger: Path, private_path: Path, event_type: str, actor: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(event_type, str) or not isinstance(actor, str) or not SAFE_TOKEN.fullmatch(event_type) or not SAFE_TOKEN.fullmatch(actor):
        raise SecurityError("invalid event type or actor")
    if not isinstance(payload, dict):
        raise SecurityError("ledger payload must be an object")
    validate_portable(payload)
    if len(canonical(payload)) > 65_536:
        raise SecurityError("audit payload exceeds 64 KiB")
    private, key_id = load_private(private_path)
    ledger.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _locked_file(ledger, MAX_LEDGER, create=True) as descriptor:
        data = _read_descriptor(descriptor, MAX_LEDGER)
        sequence, previous = verify_lines(data, private.public_key(), key_id)
        checkpoint_file = checkpoint_path(ledger)
        if sequence or checkpoint_file.exists() or checkpoint_file.is_symlink():
            # Never legitimize a truncated or rolled-back ledger by signing a new head.
            _verify_checkpoint(ledger, private.public_key(), key_id, sequence, previous)
        event = {
            "version": 1, "sequence": sequence + 1, "timestamp": int(time.time()),
            "event_type": event_type, "actor": actor, "payload": payload,
            "previous_hash": previous, "key_id": key_id,
        }
        event["signature"] = private.sign(canonical(event)).hex()
        encoded = canonical(event) + b"\n"
        if len(data) + len(encoded) > MAX_LEDGER:
            raise SecurityError("ledger capacity reached; rotate it with an external signed archive")
        os.lseek(descriptor, 0, os.SEEK_END)
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
        head = hashlib.sha256(canonical(event)).hexdigest()
        checkpoint = {"version": 1, "sequence": sequence + 1, "head_hash": head, "key_id": key_id, "timestamp": event["timestamp"]}
        checkpoint["signature"] = private.sign(canonical(checkpoint)).hex()
        atomic_write(checkpoint_path(ledger), canonical(checkpoint) + b"\n", 0o600)
        return event


def _verify_checkpoint(ledger: Path, public: Ed25519PublicKey, key_id: str, sequence: int, head: str) -> None:
    try:
        checkpoint = strict_json_loads(secure_read(checkpoint_path(ledger), 16_384, secret=True), 16_384)
    except OSError as exc:
        raise SecurityError("ledger checkpoint is missing or unreadable") from exc
    required = {"version", "sequence", "head_hash", "key_id", "timestamp", "signature"}
    if (not isinstance(checkpoint, dict) or set(checkpoint) != required or
            type(checkpoint["version"]) is not int or checkpoint["version"] != 1 or
            type(checkpoint["sequence"]) is not int or checkpoint["sequence"] < 1 or
            type(checkpoint["timestamp"]) is not int or checkpoint["timestamp"] < 0):
        raise SecurityError("invalid ledger checkpoint schema")
    unsigned = dict(checkpoint)
    try:
        signature = _hex_bytes(unsigned.pop("signature"), 64, "checkpoint signature")
        public.verify(signature, canonical(unsigned))
    except (ValueError, InvalidSignature) as exc:
        raise SecurityError("checkpoint signature verification failed") from exc
    if checkpoint["sequence"] != sequence or checkpoint["head_hash"] != head or checkpoint["key_id"] != key_id:
        raise SecurityError("ledger tail does not match the signed checkpoint")


def verify_ledger(ledger: Path, public_path: Path) -> dict[str, Any]:
    public, key_id = load_public(public_path)
    with _locked_file(ledger, MAX_LEDGER, exclusive=False) as descriptor:
        sequence, head = verify_lines(_read_descriptor(descriptor, MAX_LEDGER), public, key_id)
        _verify_checkpoint(ledger, public, key_id, sequence, head)
    return {"assistant": "ledger", "status": "pass", "sequence": sequence, "head_hash": head, "key_id": key_id}


def _token_list(value: Any, label: str) -> set[str]:
    if (not isinstance(value, list) or len(value) > 128 or
            any(not isinstance(item, str) or not SAFE_TOKEN.fullmatch(item) for item in value)):
        raise SecurityError(f"invalid {label} list")
    if len(set(value)) != len(value):
        raise SecurityError(f"duplicate {label}")
    return set(value)


def _plugin_inventory(root: Path, *, verify_signatures: bool) -> tuple[set[str], list[dict[str, Any]]]:
    trust = strict_json_loads(secure_read(root / "Plugin-System/trusted_signers.json", 65_536), 65_536)
    if not isinstance(trust, dict) or set(trust) != {"signers"} or not isinstance(trust["signers"], dict) or not 1 <= len(trust["signers"]) <= 128:
        raise SecurityError("invalid plugin trust schema")
    keys = {}
    for name, encoded in trust["signers"].items():
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,63}", name):
            raise SecurityError("invalid plugin signer name")
        keys[name] = Ed25519PublicKey.from_public_bytes(_hex_bytes(encoded, 32, "plugin public key"))
    plugin_root = root / "plugins"
    metadata = plugin_root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise SecurityError("unsafe plugin root")
    manifests = []
    required = {"schema_version", "id", "name", "version", "runtime", "entrypoint", "capabilities",
                "hooks", "timeout_seconds", "max_output_bytes", "sha256", "signer", "signature"}
    for index, directory in enumerate(plugin_root.iterdir()):
        if index >= 1024:
            raise SecurityError("plugin inventory exceeds 1024 entries")
        metadata = directory.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise SecurityError("plugin directory must not be a symlink")
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
            raise SecurityError("unsafe plugin directory permissions")
        manifest = strict_json_loads(secure_read(directory / "plugin.json", 65_536), 65_536)
        if (not isinstance(manifest, dict) or set(manifest) != required or
                type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1 or
                manifest["runtime"] != "python3" or manifest["id"] != directory.name or
                re.fullmatch(r"[a-z][a-z0-9-]{1,63}", directory.name) is None or
                not isinstance(manifest["name"], str) or not 1 <= len(manifest["name"]) <= 100 or
                not isinstance(manifest["version"], str) or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?", manifest["version"]) is None or
                type(manifest["timeout_seconds"]) is not int or not 1 <= manifest["timeout_seconds"] <= 30 or
                type(manifest["max_output_bytes"]) is not int or not 1024 <= manifest["max_output_bytes"] <= MAX_JSON or
                not isinstance(manifest["signer"], str)):
            raise SecurityError("invalid plugin manifest schema")
        capabilities = _token_list(manifest["capabilities"], "plugin capabilities")
        hooks = _token_list(manifest["hooks"], "plugin hooks")
        if len(capabilities) > 32 or len(hooks) > 32 or not hooks <= capabilities:
            raise SecurityError("invalid plugin hooks or capability count")
        entry = manifest["entrypoint"]
        if not isinstance(entry, str) or "/" in entry or "\\" in entry or Path(entry).name != entry or not entry.endswith(".py"):
            raise SecurityError("plugin entrypoint must be a local Python filename")
        digest = _hex_bytes(manifest["sha256"], 32, "plugin digest")
        code = secure_read(directory / entry)
        if hashlib.sha256(code).digest() != digest:
            raise SecurityError("plugin code digest mismatch")
        signature = _hex_bytes(manifest["signature"], 64, "plugin signature")
        if verify_signatures:
            key = keys.get(manifest["signer"])
            if key is None:
                raise SecurityError("untrusted plugin signer")
            unsigned = dict(manifest)
            unsigned.pop("signature")
            try:
                key.verify(signature, canonical(unsigned))
            except InvalidSignature as exc:
                raise SecurityError("plugin manifest signature verification failed") from exc
        manifests.append(manifest)
    return set(keys), manifests


def evaluate_policy(root: Path, policy_path: Path) -> dict[str, Any]:
    policy = strict_json_loads(secure_read(policy_path, 65_536), 65_536)
    required = {"version", "profile", "core", "plugins", "audit"}
    if (not isinstance(policy, dict) or set(policy) != required or type(policy["version"]) is not int or
            policy["version"] != 1 or not isinstance(policy["profile"], str) or policy["profile"] not in {"baseline", "high", "maximum"}):
        raise SecurityError("invalid security policy schema or profile")
    core_required = {"default_crosed_max_level", "variant_min_level", "require_app_transport", "require_qubes_isolation", "require_utf8"}
    plugin_required = {"require_signatures", "allowed_signers", "allowed_capabilities"}
    audit_required = {"require_ledger", "ledger_path", "public_key"}
    if any(not isinstance(policy[name], dict) or set(policy[name]) != fields for name, fields in
           (("core", core_required), ("plugins", plugin_required), ("audit", audit_required))):
        raise SecurityError("security policy subsection fields differ from schema")
    for field in ("default_crosed_max_level", "variant_min_level"):
        if type(policy["core"][field]) is not int or not 0 <= policy["core"][field] <= 5:
            raise SecurityError("policy levels must be integers in 0..5")
    for section, field in (("core", "require_app_transport"), ("core", "require_qubes_isolation"),
                           ("core", "require_utf8"), ("plugins", "require_signatures"), ("audit", "require_ledger")):
        if type(policy[section][field]) is not bool:
            raise SecurityError("policy requirement flags must be booleans")
    allowed_signers = _token_list(policy["plugins"]["allowed_signers"], "allowed signers")
    allowed_capabilities = _token_list(policy["plugins"]["allowed_capabilities"], "allowed capabilities")
    for field in ("ledger_path", "public_key"):
        if not isinstance(policy["audit"][field], str) or (policy["audit"]["require_ledger"] and not Path(policy["audit"][field]).is_absolute()):
            raise SecurityError("required audit paths must be absolute strings")
    results = []

    def rule(name: str, passed: bool, detail: str) -> None:
        results.append({"rule": name, "passed": passed, "detail": detail})

    default_reports = [feature_report(root / item, root) for item in ("Core-Go/shadow6-go", "Core-Rust/shadow6-rust")]
    expected_max = policy["core"]["default_crosed_max_level"]
    rule("default-crosed-level", all(item["crosed_max_level"] <= expected_max for item in default_reports), f"maximum allowed={expected_max}")
    rule("utf8", not policy["core"]["require_utf8"] or all(item["utf8"] for item in default_reports), "UTF-8 contract")
    variants = [feature_report(root / item, root) for item in ("Core-Go/shadow6-go-crosed", "Core-Rust/shadow6-rust-crosed")]
    minimum = policy["core"]["variant_min_level"]
    rule("variant-level", all(item["crosed_max_level"] >= minimum for item in variants), f"minimum required={minimum}")
    rule("variant-app", not policy["core"]["require_app_transport"] or all(item["app_transport"] for item in variants), "application transport")
    rule("variant-qubes", not policy["core"]["require_qubes_isolation"] or all(item["qubes_isolation"] for item in variants), "compartment isolation")

    try:
        required_signatures = policy["plugins"]["require_signatures"]
        signers, manifests = _plugin_inventory(root, verify_signatures=required_signatures)
        used_signers = {manifest["signer"] for manifest in manifests}
        rule("plugin-signers", not required_signatures or bool(manifests) and signers <= allowed_signers and used_signers <= allowed_signers, f"trusted={sorted(signers)}")
        rule("plugin-signatures", True, "Ed25519 signatures and code digests verified" if required_signatures else "signatures not required; code digests verified")
        manifest_capabilities = {capability for manifest in manifests for capability in manifest["capabilities"]}
        rule("plugin-capabilities", manifest_capabilities <= allowed_capabilities, f"declared={sorted(manifest_capabilities)}")
    except (OSError, SecurityError) as exc:
        rule("plugin-integrity", False, str(exc))

    audit_policy = policy["audit"]
    if audit_policy["require_ledger"]:
        try:
            verified = verify_ledger(Path(audit_policy["ledger_path"]), Path(audit_policy["public_key"]))
            rule("audit-ledger", True, f"sequence={verified['sequence']}")
        except (OSError, SecurityError, ValueError) as exc:
            rule("audit-ledger", False, str(exc))
    else:
        rule("audit-ledger", True, "not required by profile")
    passed = all(item["passed"] for item in results)
    return {"assistant": "policy", "version": VERSION, "profile": policy["profile"], "status": "pass" if passed else "fail", "results": results}


def emit(document: dict[str, Any], output: Path | None = None) -> None:
    data = json.dumps(document, ensure_ascii=False, indent=2).encode() + b"\n"
    if output:
        atomic_write(output, data, 0o600)
    else:
        sys.stdout.buffer.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="Shadow6 defensive infrastructure assistants")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    doctor_parser = commands.add_parser("doctor")
    doctor_parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    doctor_parser.add_argument("--output", type=Path)
    sbom = commands.add_parser("sbom")
    sbom.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    sbom.add_argument("--output", type=Path)
    keygen = commands.add_parser("ledger-keygen")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-key", type=Path, required=True)
    append = commands.add_parser("ledger-append")
    append.add_argument("--ledger", type=Path, required=True)
    append.add_argument("--private-key", type=Path, required=True)
    append.add_argument("--event-type", required=True)
    append.add_argument("--actor", required=True)
    append.add_argument("--payload", default="{}")
    verify = commands.add_parser("ledger-verify")
    verify.add_argument("--ledger", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    policy = commands.add_parser("policy-check")
    policy.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    policy.add_argument("--policy", type=Path, required=True)
    policy.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "list":
        emit({"version": VERSION, "assistants": ASSISTANTS})
        return 0
    if args.command == "doctor":
        result = doctor(args.root)
        emit(result, args.output)
        return 0 if result["status"] == "pass" else 1
    if args.command == "sbom":
        emit(generate_sbom(args.root), args.output)
        return 0
    if args.command == "ledger-keygen":
        emit(generate_ledger_key(args.private_key, args.public_key))
        return 0
    if args.command == "ledger-append":
        payload = strict_json_loads(args.payload, 65_536)
        if not isinstance(payload, dict):
            raise SecurityError("ledger payload must be an object")
        emit(append_event(args.ledger, args.private_key, args.event_type, args.actor, payload))
        return 0
    if args.command == "ledger-verify":
        emit(verify_ledger(args.ledger, args.public_key))
        return 0
    result = evaluate_policy(args.root.resolve(strict=True), args.policy)
    emit(result, args.output)
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SecurityError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
