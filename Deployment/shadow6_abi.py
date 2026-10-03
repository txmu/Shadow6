#!/usr/bin/env python3
"""S6ABI/1 process-boundary application contract.

This is a control/data framing layer.  It does not assert that different
native Cores speak the same wire protocol; capabilities and limits are carried
in every opened session.
"""
from __future__ import annotations

import base64
import json
import struct
import uuid
from typing import Any

ABI_VERSION = "S6ABI/1"
MAX_CONTROL = 262144
MAX_DATA = 16 * 1024 * 1024
MAX_META = 65536
STATES = frozenset(("accepted", "queued", "delivered", "backpressure", "closed", "retry_exhausted"))
METHODS = frozenset(("capabilities", "open", "status", "send", "receive", "credit", "half_close", "pause", "resume", "close"))


def _reject_float(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("floating-point values are not permitted in S6ABI")
    if isinstance(value, dict):
        for item in value.values():
            _reject_float(item)
    elif isinstance(value, list):
        for item in value:
            _reject_float(item)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate S6ABI field")
        result[key] = value
    return result


def _token(value: Any, label: str, size: int = 128) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= size:
        raise ValueError(f"invalid {label}")
    return value


def _check_message(value: dict) -> dict:
    if not isinstance(value, dict) or set(value) != {"abi", "kind", "id", "method", "state", "session", "payload"}:
        raise ValueError("invalid S6ABI control frame")
    if value["abi"] != ABI_VERSION or value["kind"] not in ("request", "response", "event"):
        raise ValueError("invalid S6ABI version or kind")
    _token(value["id"], "correlation id")
    if value["method"] not in METHODS:
        raise ValueError("unsupported S6ABI method")
    if value["state"] not in STATES:
        raise ValueError("invalid S6ABI state")
    _token(value["session"], "session", 128)
    if not isinstance(value["payload"], dict):
        raise ValueError("S6ABI payload must be an object")
    _reject_float(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    if len(raw) > MAX_CONTROL:
        raise ValueError("S6ABI control frame is oversized")
    if value["method"] == "send" and "data" in value["payload"]:
        if not isinstance(value["payload"]["data"], str) or len(value["payload"]["data"]) > MAX_DATA * 2:
            raise ValueError("S6ABI send payload is oversized")
    return value


def encode_control(method: str, payload: dict | None = None, *, session: str = "control", state: str = "accepted", kind: str = "request", correlation_id: str | None = None) -> bytes:
    message = {"abi": ABI_VERSION, "kind": kind, "id": correlation_id or str(uuid.uuid4()), "method": method, "state": state, "session": session, "payload": payload or {}}
    _check_message(message)
    raw = json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    return struct.pack(">I", len(raw)) + raw


def decode_control(frame: bytes) -> dict:
    if not isinstance(frame, (bytes, bytearray)) or len(frame) < 4:
        raise ValueError("truncated S6ABI control frame")
    size = struct.unpack(">I", frame[:4])[0]
    if size > MAX_CONTROL or len(frame) != size + 4:
        raise ValueError("invalid S6ABI control frame length")
    value = json.loads(bytes(frame[4:]).decode("utf-8"), object_pairs_hook=_pairs, parse_float=lambda _: (_ for _ in ()).throw(ValueError("float")), parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    return _check_message(value)


def encode_data(data: bytes, *, session: str, sequence: int, final: bool = False, message: bool = False) -> bytes:
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_DATA:
        raise ValueError("S6ABI data frame is oversized")
    if not isinstance(session, str) or not 1 <= len(session) <= 128 or type(sequence) is not int or not 0 <= sequence <= 2**63 - 1:
        raise ValueError("invalid S6ABI data metadata")
    flags = (1 if final else 0) | (2 if message else 0)
    meta = json.dumps({"abi": ABI_VERSION, "session": session, "sequence": sequence, "flags": flags}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    if len(meta) > MAX_META:
        raise ValueError("S6ABI data metadata is oversized")
    return struct.pack(">II", len(meta), len(data)) + meta + bytes(data)


def decode_data(frame: bytes) -> dict:
    if not isinstance(frame, (bytes, bytearray)) or len(frame) < 8:
        raise ValueError("truncated S6ABI data frame")
    meta_size, data_size = struct.unpack(">II", frame[:8])
    if meta_size > MAX_META or data_size > MAX_DATA or len(frame) != 8 + meta_size + data_size:
        raise ValueError("invalid S6ABI data frame length")
    meta = json.loads(bytes(frame[8:8 + meta_size]).decode("utf-8"), object_pairs_hook=_pairs, parse_float=lambda _: (_ for _ in ()).throw(ValueError("float")), parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    if set(meta) != {"abi", "session", "sequence", "flags"} or meta["abi"] != ABI_VERSION or type(meta["sequence"]) is not int or not 0 <= meta["sequence"] <= 2**63 - 1 or type(meta["flags"]) is not int or not 0 <= meta["flags"] <= 3:
        raise ValueError("invalid S6ABI data metadata")
    _token(meta["session"], "session")
    return {"abi": ABI_VERSION, "session": meta["session"], "sequence": meta["sequence"], "final": bool(meta["flags"] & 1), "message": bool(meta["flags"] & 2), "data": bytes(frame[8 + meta_size:])}


def capability_payload(feature_report: dict, *, boundary: str, core: str, limits: dict | None = None) -> dict:
    if boundary not in ("stream", "message", "credited") or not isinstance(core, str) or not core:
        raise ValueError("invalid S6ABI capability")
    _reject_float(feature_report)
    selected = limits or {}
    def guarantee(key, alias=None):
        value = selected.get(key, selected.get(alias) if alias else None)
        return value if type(value) is bool else None
    return {"abi": ABI_VERSION, "core": core, "boundary": boundary,
            "guarantees": {"ordered":guarantee('ordered'), "reliable":guarantee('reliable'),
                           "fullDuplex":guarantee('fullDuplex','full_duplex')},
            "limits":selected, "featureReport":feature_report}


def s6ar_request(method: str, params: dict, *, context: str | None = None) -> str:
    """Create an S6AR1 request without duplicating its framing rules."""
    from pathlib import Path
    import sys
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "Control-Center"))
    import s6ar
    component, _, action = method.partition(".")
    if not component or not action:
        raise ValueError("S6AR1 method must be component.action")
    return s6ar.request(component, "default", action, params=params, context=context)
