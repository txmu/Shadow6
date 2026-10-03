#!/usr/bin/env python3
"""External Core driver contract.

Drivers consume an already-built Core. They never compile it and never pass
untrusted shell text. Native configuration remains Core-specific; the driver
only selects a declared application boundary and turns it into fixed argv.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

try:
    from .shadow6_abi import capability_payload
except ImportError:  # direct import from an installed deployment module path
    from shadow6_abi import capability_payload

CORE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def validate_report(report: dict, core: str) -> dict:
    if not isinstance(report, dict) or report.get("core") not in (core, "shadow6-" + core):
        raise ValueError("feature report Core mismatch")
    if report.get("schema") not in (None, "shadow6.feature-report.v1"):
        raise ValueError("unsupported feature report schema")
    return report


def read_feature_report(binary: str | Path, *, timeout: int = 10) -> dict:
    path = Path(binary)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("Core binary is unavailable or not executable")
    result = subprocess.run([str(path), "--feature-report"], capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode != 0 or len(result.stdout) > 262144:
        raise ValueError("Core feature-report failed")
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("Core feature-report is not JSON") from exc
    return report


def _boundaries(report: dict) -> list[dict]:
    values = report.get("application_boundaries", report.get("applicationBoundaries", []))
    if not isinstance(values, list):
        return []
    return [item for item in values if isinstance(item, dict)]


def select_boundary(report: dict, requirements: dict) -> dict:
    if not isinstance(requirements, dict) or requirements.get("boundary") not in ("stream", "message", "credited"):
        raise ValueError("application boundary is required")
    boundary = requirements["boundary"]
    candidates = []
    for item in _boundaries(report):
        kind = item.get("kind", item.get("type", item.get("boundary")))
        if kind != boundary:
            continue
        if any(item.get(key) is False for key in ("ordered", "reliable", "fullDuplex") if requirements.get(key) is True):
            continue
        max_record = requirements.get("maxRecord")
        limit = item.get("max_record", item.get("maxRecord"))
        if max_record is not None and isinstance(limit, int) and limit < max_record:
            continue
        candidates.append(item)
    if not candidates:
        raise ValueError(f"Core does not provide a compatible {boundary} application boundary")
    if len(candidates) > 1:
        raise ValueError("AmbiguousApplicationBoundary: Core declares multiple compatible boundaries")
    selected = dict(candidates[0])
    selected.setdefault("kind", boundary)
    return selected


def invocation(core: str, binary: str | Path, config: str | Path, *, role: str, boundary: dict | None = None, ttl: int = 300) -> list[str]:
    if not isinstance(core, str) or not CORE_NAME.fullmatch(core) or role not in ("broker", "agent", "client", "gate"):
        raise ValueError("invalid Core or role")
    path = Path(binary)
    if not path.is_file() or not Path(config).is_file():
        raise ValueError("Core binary/config is unavailable")
    if not 30 <= ttl <= 3600:
        raise ValueError("ttl must be 30..3600 seconds")
    args = [str(path), "--role", role, "--config", str(Path(config).resolve()), "--ttl", str(ttl)]
    if boundary:
        kind = boundary.get("kind", boundary.get("type", boundary.get("boundary")))
        if kind not in ("stream", "message", "credited"):
            raise ValueError("invalid selected boundary")
        args += ["--application-boundary", kind]
    return args


def ready_event(line: str) -> dict:
    if not isinstance(line, str) or len(line) > 65536:
        raise ValueError("ready event is oversized")
    try:
        value = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError("ready event is not JSON") from exc
    if not isinstance(value, dict) or value.get("event") not in ("ready", "shadow6.ready"):
        raise ValueError("unexpected ready event")
    endpoint = value.get("endpoint")
    if not isinstance(endpoint, str) or not endpoint.startswith(("127.0.0.1:", "[::1]:")):
        raise ValueError("ready endpoint must be loopback")
    return value


def application_capability(report: dict, core: str, requirements: dict) -> dict:
    selected = select_boundary(report, requirements)
    return capability_payload(report, boundary=selected.get("kind", selected.get("type", requirements["boundary"])), core=core, limits=selected)
