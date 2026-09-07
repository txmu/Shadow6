#!/usr/bin/env python3
"""Public6 suite profile and bounded optional-feature negotiation."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import unicodedata
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Crosed"))
from feature_contract import TRANSPORTS, validate_feature_report


MAX_DOCUMENT = 1_048_576
MAX_GROUPS = 128
MAX_VALUES = 128
MAX_STRING = 256
MAX_DEPTH = 16
MAX_INTEGER = (1 << 53) - 1
IDENTIFIER = re.compile(r"^[a-z][a-z0-9.-]{1,63}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]{1,32})?$")
CORE_FAMILIES = set(TRANSPORTS)
OFFER_FIELDS = {"schema_version", "suite", "core", "applications", "dimensions", "extensions"}


class Public6Error(ValueError):
    pass


def _reject_float(_: str) -> None:
    raise Public6Error("floats are not permitted in portable Public6 JSON")


def _integer(value: str) -> int:
    if len(value.lstrip("-")) > 16 or abs(int(value)) > MAX_INTEGER:
        raise Public6Error("integer exceeds the portable JSON range")
    return int(value)


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Public6Error("duplicate JSON field")
        result[key] = value
    return result


def _decode(payload: bytes) -> Any:
    if not payload or len(payload) > MAX_DOCUMENT:
        raise Public6Error("JSON input is empty or oversized")
    try:
        source = payload.decode("utf-8", errors="strict")
        depth = 0
        quoted = escaped = False
        for char in source:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > MAX_DEPTH:
                    raise Public6Error("JSON nesting exceeds the limit")
            elif char in "}]":
                depth -= 1
        return json.loads(source, object_pairs_hook=_object, parse_int=_integer,
                          parse_float=_reject_float, parse_constant=_reject_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Public6Error("invalid UTF-8 Public6 JSON") from exc


def _validate_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise Public6Error(f"invalid {label}")
    return value


def _validate_string(value: Any, label: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > MAX_STRING
            or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value)
            or unicodedata.normalize("NFC", value) != value
            or len(value.encode("utf-8")) > MAX_STRING):
        raise Public6Error(f"invalid {label}")
    return value


def _validate_groups(value: Any, label: str, *, integers: bool) -> dict[str, list[Any]]:
    if not isinstance(value, dict) or len(value) > MAX_GROUPS:
        raise Public6Error(f"{label} must be a bounded object")
    result: dict[str, list[Any]] = {}
    for raw_name, raw_values in value.items():
        name = _validate_identifier(raw_name, f"{label} name")
        if not isinstance(raw_values, list) or not raw_values or len(raw_values) > MAX_VALUES:
            raise Public6Error(f"{label}.{name} must be a non-empty bounded list")
        if integers:
            if any(isinstance(item, bool) or not isinstance(item, int) or not 1 <= item <= 65535 for item in raw_values):
                raise Public6Error(f"{label}.{name} contains an invalid version")
        else:
            for item in raw_values:
                _validate_string(item, f"{label}.{name} value")
        if len(set(raw_values)) != len(raw_values):
            raise Public6Error(f"{label}.{name} contains duplicate values")
        result[name] = sorted(raw_values)
    return result


def validate_offer(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != OFFER_FIELDS:
        raise Public6Error("Public6 offer has an unknown or missing field")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1 or document["suite"] != "public6":
        raise Public6Error("unsupported Public6 offer schema")
    core = document["core"]
    if not isinstance(core, dict) or set(core) != {"family", "version"}:
        raise Public6Error("invalid Core identity")
    family = _validate_string(core["family"], "Core family")
    version = _validate_string(core["version"], "Core version")
    if family not in CORE_FAMILIES or not VERSION.fullmatch(version):
        raise Public6Error("unsupported Core family or malformed Core version")
    result = {
        "schema_version": 1,
        "suite": "public6",
        "core": {"family": family, "version": version},
        "applications": _validate_groups(document["applications"], "applications", integers=True),
        "dimensions": _validate_groups(document["dimensions"], "dimensions", integers=False),
        "extensions": _validate_groups(document["extensions"], "extensions", integers=True),
    }
    if len(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)) > MAX_DOCUMENT:
        raise Public6Error("canonical Public6 offer is oversized")
    return result


def decode_offer(payload: bytes) -> dict[str, Any]:
    return validate_offer(_decode(payload))


def _read_bounded_regular(path: Path) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_size > MAX_DOCUMENT:
        raise Public6Error("input must be a bounded regular non-symlink file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino
                or not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_DOCUMENT):
            raise Public6Error("input changed while opening")
        chunks: list[bytes] = []
        remaining = MAX_DOCUMENT + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    if not payload or len(payload) > MAX_DOCUMENT:
        raise Public6Error("input is empty or oversized")
    return payload


def read_offer(path: Path) -> dict[str, Any]:
    return decode_offer(_read_bounded_regular(path))


def read_json(path: Path) -> Any:
    return _decode(_read_bounded_regular(path))


def _intersection(local: dict[str, list[Any]], peer: dict[str, list[Any]], *, highest: bool) -> dict[str, Any]:
    negotiated: dict[str, Any] = {}
    for name in sorted(local.keys() & peer.keys()):
        common = sorted(set(local[name]) & set(peer[name]))
        if common:
            negotiated[name] = common[-1] if highest else common
    return negotiated


def negotiate(local_document: Any, peer_document: Any) -> dict[str, Any]:
    local = validate_offer(local_document)
    peer = validate_offer(peer_document)
    if local["core"] != peer["core"]:
        return {
            "schema_version": 1,
            "suite": "public6",
            "compatible": False,
            "reason": "Core family and version must match exactly",
            "core": None,
            "applications": {},
            "dimensions": {},
            "extensions": {},
        }
    # Every field below Core identity is optional. Differences reduce the
    # negotiated intersection and never reject the base Core connection.
    return {
        "schema_version": 1,
        "suite": "public6",
        "compatible": True,
        "reason": "",
        "core": local["core"],
        "applications": _intersection(local["applications"], peer["applications"], highest=True),
        "dimensions": _intersection(local["dimensions"], peer["dimensions"], highest=False),
        "extensions": _intersection(local["extensions"], peer["extensions"], highest=True),
    }


def offer_from_feature_report(report: Any) -> dict[str, Any]:
    try:
        validate_feature_report(report)
    except ValueError as exc:
        raise Public6Error(str(exc)) from exc
    if (
        not isinstance(report["core"], str)
        or report["core"] not in CORE_FAMILIES
        or not isinstance(report["version"], str)
        or any(not isinstance(report[field], bool) for field in ("crosed_compiled", "app_transport", "qubes_isolation", "gate_compiled", "gate_enabled_by_default", "utf8"))
        or isinstance(report["crosed_max_level"], bool)
        or not isinstance(report["crosed_max_level"], int)
        or not 0 <= report["crosed_max_level"] <= 5
        or not isinstance(report["crosed_capabilities"], list)
        or any(not isinstance(item, str) for item in report["crosed_capabilities"])
    ):
        raise Public6Error("Core feature report contains invalid values")
    if (not report["crosed_compiled"] and (report["crosed_max_level"] != 0 or report["crosed_capabilities"])
            or report["gate_enabled_by_default"] and not report["gate_compiled"]):
        raise Public6Error("Core feature report contains contradictory capabilities")
    applications = {"shadow.application": [1]} if report["app_transport"] else {}
    dimensions = {
        "crosed.capability": report["crosed_capabilities"] or ["none"],
        "crosed.level": [str(report["crosed_max_level"])],
        "isolation.qubes": ["enabled" if report["qubes_isolation"] else "disabled"],
        "text.utf8": ["enabled" if report["utf8"] else "disabled"],
        "gate.available": ["enabled" if report["gate_compiled"] else "disabled"],
        "gate.default": ["enabled" if report["gate_enabled_by_default"] else "disabled"],
    }
    return validate_offer({
        "schema_version": 1,
        "suite": "public6",
        "core": {"family": report["core"], "version": report["version"]},
        "applications": applications,
        "dimensions": dimensions,
        "extensions": {},
    })


def suite_profile() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "suite": "public6",
        "components": "all",
        "compliance": False,
        "core_engines": ["shadow6-go", "shadow6-rust"],
        "compiled_optional_features": "all",
        "compatibility_gate": ["core.family", "core.version"],
        "optional_negotiation": "intersection",
        "extension_policy": "bounded namespaced data; signed isolated Plugins provide code",
    }


def _print(document: dict[str, Any]) -> None:
    print(json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def main() -> int:
    parser = argparse.ArgumentParser(description="Public6 suite compatibility tools")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("profile")
    offer_parser = commands.add_parser("offer")
    offer_parser.add_argument("feature_report", type=Path)
    negotiate_parser = commands.add_parser("negotiate")
    negotiate_parser.add_argument("local", type=Path)
    negotiate_parser.add_argument("peer", type=Path)
    args = parser.parse_args()
    if args.command == "profile":
        _print(suite_profile())
    elif args.command == "offer":
        _print(offer_from_feature_report(read_json(args.feature_report)))
    else:
        _print(negotiate(read_offer(args.local), read_offer(args.peer)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, Public6Error) as error:
        print(f"Public6 error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
