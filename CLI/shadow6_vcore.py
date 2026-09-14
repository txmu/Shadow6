#!/usr/bin/env python3
"""Signed, bounded VCore control plane. Does not translate data-plane packets."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if not (ROOT / "Makefile").is_file():
    ROOT = Path(os.environ.get("SHADOW6_ROOT", str(HERE.parent)))
for directory in (ROOT / "Security-Assistants", ROOT / "Crosed",
                  HERE.parent / "share/shadow6/assistants", HERE.parent / "share/shadow6/modules"):
    if directory.is_dir():
        sys.path.insert(0, str(directory))
from shadow6_security import (SecurityError, atomic_write, bounded_run, canonical,
                             load_private, load_public, secure_read, strict_json_loads)
from feature_contract import CORE_PATHS as FAMILY_PATHS, CAPABILITY_LEVELS, validate_feature_report
from vcore_adapters import ADAPTERS, translate

CORE_PATHS = {name.removeprefix("shadow6-"): path for name, path in FAMILY_PATHS.items()}
MAX_REPORT = 131072
MAX_BINARY = 512 * 1024 * 1024
SLOTS = threading.BoundedSemaphore(2)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def core_path(root, name):
    if (root / "Makefile").is_file() or (root / CORE_PATHS[name]).exists():
        return root / CORE_PATHS[name]
    return root / "bin" / ("shadow6-" + name)


def _only(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError("unknown or missing fields")


def _timeout(value):
    if type(value) is not int or not 1 <= value <= 30:
        raise ValueError("timeout must be integer seconds in 1..30")
    return value


@contextmanager
def _binary(path):
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or before.st_mode & 0o022 or not before.st_mode & 0o111
            or not 1 <= before.st_size <= MAX_BINARY):
        raise ValueError("core must be an owned regular executable, not writable by others")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        if _identity(opened) != _identity(before):
            raise ValueError("core changed while opening")
        digest, total = hashlib.sha256(), 0
        while chunk := os.read(fd, 65536):
            total += len(chunk)
            if total > MAX_BINARY:
                raise ValueError("core exceeds size bound")
            digest.update(chunk)
        if _identity(os.fstat(fd)) != _identity(opened):
            raise ValueError("core changed while hashing")
        os.lseek(fd, 0, os.SEEK_SET)
        yield fd, digest.hexdigest(), opened
    finally:
        os.close(fd)


def _run(path, fd, args, timeout):
    if sys.platform != "linux":
        raise ValueError("VCore execution requires Linux resource-limit helpers")
    for helper in ("/usr/bin/prlimit", "/usr/bin/setpriv"):
        if not os.access(helper, os.X_OK):
            raise ValueError("VCore execution requires " + helper)
    # Native cores execute the verified inode. Idris' generated launcher needs its bundle path.
    executable = f"/proc/self/fd/{fd}" if os.pread(fd, 4, 0) == b"\x7fELF" else str(path)
    command = ["/usr/bin/prlimit", "--cpu=30:30", "--as=8589934592:8589934592",
               "--nofile=128:128", "--nproc=256:256", "--fsize=1048576:1048576", "--core=0:0",
               "--", "/usr/bin/setpriv", "--no-new-privs", "--", executable, *args]
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "GOMAXPROCS": "2",
           "ERL_FLAGS": "+S 2:2 +SDcpu 1 +SDio 1"}
    if not SLOTS.acquire(blocking=False):
        raise ValueError("VCore concurrency limit reached")
    try:
        return bounded_run(command, path.parent, timeout, MAX_REPORT, env, pass_fds=(fd,))
    finally:
        SLOTS.release()


def _bundle(root, name):
    if name != "idris":
        return {}
    files = {}
    for directory in (root / "Core-Idris/shadow6-idris_app", root / "Core-Idris/ffi"):
        if directory.is_symlink():
            raise ValueError("Idris bundle cannot be a symlink")
        if directory.is_dir():
            for path in directory.rglob("*"):
                if path.is_symlink():
                    raise ValueError("Idris bundle cannot contain symlinks")
                if path.is_file():
                    if len(files) >= 128:
                        raise ValueError("Idris bundle is oversized")
                    info = path.lstat()
                    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                        raise ValueError("Idris bundle must be owner-controlled")
                    files[str(path.relative_to(root))] = hashlib.sha256(secure_read(path, MAX_BINARY)).hexdigest()
    return files


def sign_inventory(root, private_key, output, timeout=5):
    """Explicit operator action: probe trusted local builds and sign their exact inventory."""
    _timeout(timeout)
    if output.exists() or output.is_symlink():
        raise ValueError("inventory output exists")
    private, key_id = load_private(private_key)
    entries = {}
    for name, relative in CORE_PATHS.items():
        path = core_path(root, name)
        if not path.exists() and not path.is_symlink():
            continue
        with _binary(path) as (fd, digest, metadata):
            result = _run(path, fd, ["--feature-report"], timeout)
            if result.returncode:
                raise ValueError(name + ": feature-report failed: " + result.stderr[:256])
            report = validate_feature_report(strict_json_loads(result.stdout, MAX_REPORT), "shadow6-" + name)
            if _identity(os.fstat(fd)) != _identity(metadata) or _identity(path.lstat()) != _identity(metadata):
                raise ValueError("core changed during attestation")
            entries[name] = {"sha256": digest, "report": report, "bundle": _bundle(root, name)}
    now = int(time.time())
    document = {"version": 1, "key_id": key_id, "issued_at": now, "expires_at": now + 300,
                "nonce": secrets.token_hex(32), "cores": entries}
    document["signature"] = private.sign(canonical(document)).hex()
    atomic_write(output, canonical(document) + b"\n", 0o600)
    return {"signed": sorted(entries), "expires_at": document["expires_at"]}


def _inventory(manifest, public_key):
    doc = strict_json_loads(secure_read(manifest, MAX_REPORT, secret=True), MAX_REPORT)
    _only(doc, ("version", "key_id", "issued_at", "expires_at", "nonce", "cores", "signature"))
    if type(doc["version"]) is not int or doc["version"] != 1:
        raise ValueError("unsupported inventory version")
    now = int(time.time())
    if (type(doc["issued_at"]) is not int or type(doc["expires_at"]) is not int
            or not now - 300 <= doc["issued_at"] <= now
            or not now < doc["expires_at"] <= doc["issued_at"] + 300):
        raise ValueError("inventory expired or invalid validity window")
    for field, size in (("nonce", 64), ("signature", 128)):
        if not isinstance(doc[field], str) or not re.fullmatch("[0-9a-f]{" + str(size) + "}", doc[field]):
            raise ValueError("invalid inventory " + field)
    public, key_id = load_public(public_key)
    if doc["key_id"] != key_id:
        raise ValueError("inventory signer mismatch")
    from cryptography.exceptions import InvalidSignature
    try:
        public.verify(bytes.fromhex(doc["signature"]), canonical({k: v for k, v in doc.items() if k != "signature"}))
    except InvalidSignature as exc:
        raise ValueError("invalid inventory signature") from exc
    if not isinstance(doc["cores"], dict) or set(doc["cores"]) - set(CORE_PATHS):
        raise ValueError("unknown inventory core")
    for name, entry in doc["cores"].items():
        _only(entry, ("sha256", "report", "bundle"))
        if not isinstance(entry["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", entry["sha256"]):
            raise ValueError("invalid core digest")
        validate_feature_report(entry["report"], "shadow6-" + name)
        if not isinstance(entry["bundle"], dict) or len(entry["bundle"]) > 128:
            raise ValueError("invalid core bundle")
    return doc


def discover(root: Path, timeout: int = 5, manifest=None, public_key=None) -> dict:
    _timeout(timeout)
    root = root.absolute()
    installed = [n for n in CORE_PATHS if core_path(root, n).is_file()]
    reports, errors = {}, {}
    if (manifest is None) != (public_key is None):
        raise ValueError("manifest and public_key must be provided together")
    inventory = _inventory(Path(manifest), Path(public_key)) if manifest is not None else None
    for name in installed:
        try:
            if inventory is None or name not in inventory["cores"]:
                raise ValueError("unsigned core; no execution performed")
            entry = inventory["cores"][name]
            with _binary(core_path(root, name)) as (_, digest, __):
                if digest != entry["sha256"] or _bundle(root, name) != entry["bundle"]:
                    raise ValueError("signed core digest mismatch")
            reports[name] = entry["report"]
        except (OSError, ValueError, SecurityError) as exc:
            errors[name] = str(exc)
    common = set.intersection(*(set(r["crosed_capabilities"]) for r in reports.values())) if reports else set()
    return {"version": 1, "cores": reports, "installed": installed, "errors": errors,
            "capability_intersection": sorted(common)}


def select(discovery, cores=None, priority=None, capabilities=None):
    cores = list(CORE_PATHS) if cores is None else cores
    priority = [] if priority is None else priority
    capabilities = [] if capabilities is None else capabilities
    for values, allowed in ((cores, CORE_PATHS), (priority, CORE_PATHS), (capabilities, CAPABILITY_LEVELS)):
        if (not isinstance(values, list) or len(values) > 12
                or any(not isinstance(x, str) or x not in allowed for x in values)
                or len(set(values)) != len(values)):
            raise ValueError("invalid selection or capability constraint")
    order = [n for n in priority if n in cores] + [n for n in cores if n not in priority]
    eligible = [n for n in order if n in discovery["cores"]
                and set(capabilities) <= set(discovery["cores"][n]["crosed_capabilities"])]
    return {"selected": eligible[0] if eligible else None, "fallback": eligible[1:]}


def invoke(root, request, manifest, public_key):
    request = strict_json_loads(request if isinstance(request, (str, bytes)) else canonical(request), 65536)
    _only(request, ("version", "operation", "cores", "priority", "capabilities", "timeout", "config"))
    if type(request["version"]) is not int or request["version"] != 1:
        raise ValueError("unsupported control-plane version")
    timeout = _timeout(request["timeout"])
    if request["operation"] not in ("feature-report", "version", "status", "check-config"):
        raise ValueError("unsupported read-only control-plane operation")
    if request["config"] is not None and not isinstance(request["config"], str):
        raise ValueError("config must be a path or null")
    discovery = discover(root, timeout, manifest, public_key)
    chosen = select(discovery, request["cores"], request["priority"], request["capabilities"])
    if chosen["selected"] is None:
        return {"version": 1, "ok": False, "error": "no_eligible_core", "attempts": []}
    inventory = _inventory(Path(manifest), Path(public_key))
    attempts = []
    for name in [chosen["selected"], *chosen["fallback"]]:
        try:
            args = translate(name, request["operation"], request["config"])
            entry, path = inventory["cores"][name], core_path(root, name)
            with _binary(path) as (fd, digest, metadata):
                if digest != entry["sha256"] or _bundle(root, name) != entry["bundle"]:
                    raise ValueError("signed core digest mismatch")
                result = _run(path, fd, args, timeout)
                if _identity(os.fstat(fd)) != _identity(metadata) or _identity(path.lstat()) != _identity(metadata):
                    raise ValueError("core changed during execution")
            if result.returncode:
                attempts.append({"core": name, "error": "core_exit", "exit_code": result.returncode})
                continue
            if request["operation"] == "check-config":
                value = {"valid": True}
            else:
                report = validate_feature_report(strict_json_loads(result.stdout, MAX_REPORT), "shadow6-" + name)
                if report != entry["report"]:
                    raise ValueError("feature report differs from signed inventory")
                value = report if request["operation"] == "feature-report" else (
                    {"version": report["version"]} if request["operation"] == "version" else
                    {"state": "probe_completed", "running": False, "adapter": ADAPTERS[name].description})
            return {"version": 1, "ok": True, "core": name, "result": value, "attempts": attempts}
        except subprocess.TimeoutExpired:
            attempts.append({"core": name, "error": "timeout"})
        except (OSError, ValueError, SecurityError):
            attempts.append({"core": name, "error": "rejected"})
    return {"version": 1, "ok": False, "error": "all_cores_failed", "attempts": attempts}


def main() -> int:
    parser = argparse.ArgumentParser(prog="shadow6 vcore")
    parser.add_argument("action", nargs="?", choices=("discover", "sign", "invoke"), default="discover")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--timeout", type=int, default=5)
    for flag in ("manifest", "public-key", "private-key", "output", "request"):
        parser.add_argument("--" + flag, type=Path)
    args = parser.parse_args()
    try:
        root = args.root.absolute()
        if args.action == "sign":
            if args.private_key is None or args.output is None:
                raise ValueError("sign requires --private-key and --output; only sign trusted builds")
            result = sign_inventory(root, args.private_key, args.output, args.timeout)
        elif args.action == "invoke":
            if args.request is None or args.manifest is None or args.public_key is None:
                raise ValueError("invoke requires --request, --manifest and --public-key")
            result = invoke(root, secure_read(args.request, 65536), args.manifest, args.public_key)
        else:
            result = discover(root, args.timeout, args.manifest, args.public_key)
        print(canonical(result).decode())
        return 0 if result.get("ok", True) else 1
    except (ValueError, OSError, SecurityError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"version": 1, "ok": False, "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
