#!/usr/bin/env python3
"""Read-only component eyes and signed fixed-action hands for Shadow6."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SECURITY_MODULE_DIR = ROOT / "Security-Assistants"
if not SECURITY_MODULE_DIR.is_dir():
    SECURITY_MODULE_DIR = ROOT / "share" / "shadow6" / "assistants"
sys.path.insert(0, str(SECURITY_MODULE_DIR))
from shadow6_security import (  # noqa: E402
    COMPONENTS, MAX_JSON, SecurityError, atomic_write, bounded_run, canonical,
    feature_report, load_private, load_public, secure_read, sha256_file,
    strict_json_loads, validate_portable, _hex_bytes, _locked_file,
    _read_descriptor, _write_all,
)
from cryptography.exceptions import InvalidSignature  # noqa: E402


VERSION = "1.0.0"
RUNBOOKS = {
    "build": (["make", "build"], 600),
    "test": (["make", "test"], 900),
    "check": (["make", "check"], 600),
    "audit": (["make", "audit"], 120),
    "integration-test": (["make", "integration-test"], 180),
    "package-release": (["bash", "Tools/package_release.sh"], 300),
}


class InfrastructureError(SecurityError):
    pass


def running_binary_pids(binary_paths: list[Path]) -> dict[str, list[int]]:
    resolved = {str(path.resolve()): [] for path in binary_paths if path.is_file()}
    proc = Path("/proc")
    if not proc.is_dir():
        return resolved
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            executable = os.readlink(entry / "exe")
        except OSError:
            continue
        if executable in resolved:
            resolved[executable].append(int(entry.name))
    for pids in resolved.values():
        pids.sort()
    return resolved


def observe(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    components: dict[str, Any] = {}
    all_binaries: list[Path] = []
    for name, definition in COMPONENTS.items():
        source = root / definition["source"]
        binaries = []
        for relative in definition["binaries"]:
            path = root / relative
            if path.is_file():
                metadata = path.lstat()
                item: dict[str, Any] = {
                    "path": relative, "sha256": sha256_file(path), "size": metadata.st_size,
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}", "uid": metadata.st_uid, "gid": metadata.st_gid,
                }
                if name in {"core-go", "core-rust"}:
                    if metadata.st_mode & 0o022:
                        item["features_error"] = "unsafe binary permissions; feature execution refused"
                    else:
                        item["features"] = feature_report(path, root)
                binaries.append(item)
                all_binaries.append(path)
        components[name] = {
            "source": definition["source"], "source_present": source.is_file(),
            "source_sha256": sha256_file(source) if source.is_file() else None,
            "binaries": binaries,
        }
        if source.is_file():
            metadata = source.lstat()
            components[name].update({"source_mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                                     "source_uid": metadata.st_uid, "source_gid": metadata.st_gid})
    process_map = running_binary_pids(all_binaries)
    for component in components.values():
        for binary in component["binaries"]:
            binary["running_pids"] = process_map.get(str((root / binary["path"]).resolve()), [])
    stable_components = {name: {**component, "binaries": [
        {key: value for key, value in binary.items() if key != "running_pids"}
        for binary in component["binaries"]]} for name, component in components.items()}
    stable = {"version": VERSION, "components": stable_components}
    return {
        "assistant": "eyes", "version": VERSION, "generated_at": int(time.time()),
        "snapshot_id": hashlib.sha256(canonical(stable)).hexdigest(), "components": components,
    }


def _validate_snapshot(snapshot: Any) -> None:
    required = {"assistant", "version", "generated_at", "snapshot_id", "components"}
    if (not isinstance(snapshot, dict) or set(snapshot) != required or snapshot["assistant"] != "eyes" or
            snapshot["version"] != VERSION or type(snapshot["generated_at"]) is not int or
            not isinstance(snapshot["components"], dict) or len(snapshot["components"]) > 128):
        raise InfrastructureError("invalid baseline snapshot schema")
    _hex_bytes(snapshot["snapshot_id"], 32, "snapshot ID")
    for name, component in snapshot["components"].items():
        required_component = {"source", "source_present", "source_sha256", "binaries"}
        if (not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name) or
                not isinstance(component, dict) or not required_component <= set(component) or
                set(component) - required_component - {"source_mode", "source_uid", "source_gid"} or
                not isinstance(component["source"], str) or type(component["source_present"]) is not bool or
                not isinstance(component["binaries"], list) or len(component["binaries"]) > 128):
            raise InfrastructureError("invalid baseline component schema")
        if component["source_sha256"] is not None:
            _hex_bytes(component["source_sha256"], 32, "source digest")
        paths = set()
        for binary in component["binaries"]:
            required_binary = {"path", "sha256", "size", "mode", "running_pids"}
            if (not isinstance(binary, dict) or not required_binary <= set(binary) or
                    set(binary) - required_binary - {"uid", "gid", "features", "features_error"} or
                    not isinstance(binary["path"], str) or binary["path"] in paths or
                    type(binary["size"]) is not int or binary["size"] < 0 or
                    not isinstance(binary["running_pids"], list) or
                    any(type(pid) is not int or pid <= 0 for pid in binary["running_pids"])):
                raise InfrastructureError("invalid baseline binary schema")
            paths.add(binary["path"])
            _hex_bytes(binary["sha256"], 32, "binary digest")
        for item, prefix in [(component, "source_")] + [(binary, "") for binary in component["binaries"]]:
            for key in ("uid", "gid"):
                if prefix + key in item and (type(item[prefix + key]) is not int or item[prefix + key] < 0):
                    raise InfrastructureError("invalid baseline ownership")
            if prefix + "mode" in item and (not isinstance(item[prefix + "mode"], str) or not re.fullmatch(r"[0-7]{4}", item[prefix + "mode"])):
                raise InfrastructureError("invalid baseline mode")


def compare_snapshot(root: Path, baseline_path: Path) -> dict[str, Any]:
    baseline = strict_json_loads(secure_read(baseline_path, 4 * MAX_JSON), 4 * MAX_JSON)
    _validate_snapshot(baseline)
    current = observe(root)
    changes = []
    old_components = baseline.get("components", {})
    for name in sorted(set(old_components) - set(current["components"])):
        changes.append({"component": name, "change": "removed"})
    for name, current_component in current["components"].items():
        old = old_components.get(name)
        if old is None:
            changes.append({"component": name, "change": "added"})
            continue
        if old.get("source_sha256") != current_component.get("source_sha256"):
            changes.append({"component": name, "change": "source-digest"})
        for field, change in (("source", "source-path"), ("source_present", "source-presence"),
                              ("source_mode", "source-mode"), ("source_uid", "source-owner"), ("source_gid", "source-group")):
            if old.get(field) != current_component.get(field):
                changes.append({"component": name, "change": change})
        old_binaries = {item["path"]: item for item in old.get("binaries", [])}
        new_binaries = {item["path"]: item for item in current_component.get("binaries", [])}
        for path in sorted(set(old_binaries) | set(new_binaries)):
            if path not in old_binaries:
                changes.append({"component": name, "path": path, "change": "binary-added"})
            elif path not in new_binaries:
                changes.append({"component": name, "path": path, "change": "binary-removed"})
            else:
                for field, change in (("sha256", "binary-digest"), ("mode", "binary-mode"), ("uid", "binary-owner"),
                                      ("gid", "binary-group"), ("features", "feature-contract"), ("features_error", "feature-error")):
                    if old_binaries[path].get(field) != new_binaries[path].get(field):
                        changes.append({"component": name, "path": path, "change": change})
    return {"assistant": "drift", "version": VERSION, "status": "clean" if not changes else "changed", "changes": changes, "current_snapshot_id": current["snapshot_id"]}


def create_plan(root: Path, action: str, private_key: Path, ttl: int = 300) -> dict[str, Any]:
    if not isinstance(action, str) or action not in RUNBOOKS or type(ttl) is not int or not 30 <= ttl <= 300:
        raise InfrastructureError("unknown runbook or TTL outside 30..300 seconds")
    root = root.resolve(strict=True)
    if not (root / "Makefile").is_file():
        raise InfrastructureError("runbook root is not a Shadow6 tree")
    private, key_id = load_private(private_key)
    issued = int(time.time())
    plan = {
        "version": 1, "action": action, "root": str(root), "issued_at": issued,
        "expires_at": issued + ttl, "nonce": os.urandom(16).hex(), "key_id": key_id,
    }
    plan["signature"] = private.sign(canonical(plan)).hex()
    return plan


def verify_plan(plan: dict[str, Any], public_key: Path, expected_root: Path) -> dict[str, Any]:
    validate_portable(plan)
    required = {"version", "action", "root", "issued_at", "expires_at", "nonce", "key_id", "signature"}
    if (not isinstance(plan, dict) or set(plan) != required or type(plan["version"]) is not int or plan["version"] != 1 or
            not isinstance(plan["action"], str) or plan["action"] not in RUNBOOKS or
            not isinstance(plan["root"], str) or type(plan["issued_at"]) is not int or
            type(plan["expires_at"]) is not int or plan["issued_at"] < 0):
        raise InfrastructureError("invalid signed runbook schema")
    _hex_bytes(plan["nonce"], 16, "runbook nonce")
    _hex_bytes(plan["key_id"], 8, "runbook key ID")
    signature = _hex_bytes(plan["signature"], 64, "runbook signature")
    public, key_id = load_public(public_key)
    unsigned = dict(plan)
    try:
        unsigned.pop("signature")
        public.verify(signature, canonical(unsigned))
    except (ValueError, InvalidSignature) as exc:
        raise InfrastructureError("runbook signature verification failed") from exc
    now = int(time.time())
    if plan["key_id"] != key_id or plan["root"] != str(expected_root.resolve(strict=True)):
        raise InfrastructureError("runbook key or root binding mismatch")
    if not plan["issued_at"] <= now <= plan["expires_at"] or not 30 <= plan["expires_at"] - plan["issued_at"] <= 300:
        raise InfrastructureError("runbook approval is expired or overlong")
    return plan


def execute_plan(plan_path: Path, public_key: Path, expected_root: Path, state_dir: Path) -> dict[str, Any]:
    plan = strict_json_loads(secure_read(plan_path, 65_536, secret=True), 65_536)
    verify_plan(plan, public_key, expected_root)
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = state_dir.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise InfrastructureError("runbook state directory must be owner-controlled and mode 0700")
    state = state_dir / "consumed-runbooks"
    with _locked_file(state, MAX_JSON, create=True) as descriptor:
        existing = _read_descriptor(descriptor, MAX_JSON)
        if existing and (not existing.endswith(b"\n") or any(re.fullmatch(rb"[0-9a-f]{32}", line) is None for line in existing.splitlines())):
            raise InfrastructureError("invalid runbook replay journal")
        nonces = existing.splitlines()
        if len(set(nonces)) != len(nonces):
            raise InfrastructureError("duplicate nonce in replay journal")
        if plan["nonce"].encode("ascii") in nonces:
            raise InfrastructureError("runbook approval has already been consumed")
        encoded = (plan["nonce"] + "\n").encode("ascii")
        if len(existing) + len(encoded) > MAX_JSON:
            raise InfrastructureError("runbook replay capacity reached; archive expired approvals before rotating state")
        verify_plan(plan, public_key, expected_root)
        os.lseek(descriptor, 0, os.SEEK_END)
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
    command, timeout = RUNBOOKS[plan["action"]]
    environment = os.environ.copy()
    for name in ("LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME", "BASH_ENV", "ENV", "GIT_CONFIG_COUNT",
                 "MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKEFILES", "SHELLOPTS", "BASHOPTS"):
        environment.pop(name, None)
    completed = bounded_run(command, expected_root.resolve(), timeout, env=environment)
    output = (completed.stdout + completed.stderr)[-65_536:]
    return {
        "assistant": "hands", "version": VERSION, "action": plan["action"],
        "status": "pass" if completed.returncode == 0 else "fail",
        "returncode": completed.returncode, "output_tail": output,
    }


def emit(document: dict[str, Any], output: Path | None = None, mode: int = 0o600) -> None:
    data = json.dumps(document, ensure_ascii=False, indent=2).encode() + b"\n"
    if output:
        atomic_write(output, data, mode)
    else:
        sys.stdout.buffer.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="Shadow6 component hands and eyes")
    commands = parser.add_subparsers(dest="command", required=True)
    observe_parser = commands.add_parser("observe")
    observe_parser.add_argument("--root", type=Path, default=ROOT)
    observe_parser.add_argument("--output", type=Path)
    drift = commands.add_parser("drift")
    drift.add_argument("--root", type=Path, default=ROOT)
    drift.add_argument("--baseline", type=Path, required=True)
    plan_parser = commands.add_parser("plan")
    plan_parser.add_argument("--root", type=Path, default=ROOT)
    plan_parser.add_argument("--action", choices=sorted(RUNBOOKS), required=True)
    plan_parser.add_argument("--private-key", type=Path, required=True)
    plan_parser.add_argument("--output", type=Path, required=True)
    plan_parser.add_argument("--ttl", type=int, default=300)
    execute = commands.add_parser("execute")
    execute.add_argument("--root", type=Path, default=ROOT)
    execute.add_argument("--plan", type=Path, required=True)
    execute.add_argument("--public-key", type=Path, required=True)
    execute.add_argument("--state-dir", type=Path, default=Path.home() / ".local/state/shadow6")
    args = parser.parse_args()
    if args.command == "observe":
        emit(observe(args.root), args.output)
        return 0
    if args.command == "drift":
        result = compare_snapshot(args.root, args.baseline)
        emit(result)
        return 0 if result["status"] == "clean" else 1
    if args.command == "plan":
        plan = create_plan(args.root, args.action, args.private_key, args.ttl)
        emit(plan, args.output)
        print(f"signed runbook plan written to {args.output}")
        return 0
    result = execute_plan(args.plan, args.public_key, args.root, args.state_dir)
    emit(result)
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (InfrastructureError, SecurityError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
