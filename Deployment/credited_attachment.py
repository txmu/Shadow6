"""Strict material admission for an explicitly configured S6NA attachment."""
from __future__ import annotations

import hashlib
import ipaddress
import sys
from pathlib import Path

try:
    from .service_storage import private_read, strict_json
except ImportError:
    from service_storage import private_read, strict_json


def credited_core(core, profile_binding):
    """Map the Gleam companion Profile onto its distinct S6NA policy name."""
    if core == "gleam" and isinstance(profile_binding, dict) and profile_binding.get("profile") == "gleam-micro-mux":
        return "gleam-mux"
    return core


def validate_attachment(path, *, root, expected_core=None):
    """Validate and digest private S6NA config/key material without opening UDP."""
    path = Path(path)
    config_bytes = private_read(path, limit=16384)
    value = strict_json(config_bytes)
    allowed = {"schema", "core", "key_file", "bind", "peer", "side", "stream", "limits"}
    required = {"schema", "core", "key_file", "bind", "peer"}
    if (not isinstance(value, dict) or set(value) - allowed or not required <= set(value)
            or value["schema"] != "shadow6.s6na-attachment.v1"):
        raise ValueError("invalid S6NA attachment schema")
    core = value["core"]
    if not isinstance(core, str) or not core.isascii() or not core or len(core) > 32:
        raise ValueError("invalid S6NA Profile family")
    if expected_core is not None and core != expected_core:
        raise ValueError("S6NA attachment Core differs from Named Service")
    key_path = value["key_file"]
    if not isinstance(key_path, str) or not Path(key_path).is_absolute():
        raise ValueError("S6NA key_file must be absolute")
    key_bytes = private_read(key_path, limit=32)
    if len(key_bytes) != 32:
        raise ValueError("S6NA key must contain exactly 32 bytes")

    endpoints = {}
    for name in ("bind", "peer"):
        endpoint = value[name]
        if (not isinstance(endpoint, list) or len(endpoint) != 2
                or not isinstance(endpoint[0], str) or type(endpoint[1]) is not int):
            raise ValueError("invalid S6NA " + name + " endpoint")
        try:
            address = ipaddress.ip_address(endpoint[0])
        except ValueError as error:
            raise ValueError("S6NA endpoints require literal IP addresses") from error
        if address.is_multicast or (name == "peer" and address.is_unspecified):
            raise ValueError("invalid S6NA " + name + " address")
        low = 0 if name == "bind" else 1
        if not low <= endpoint[1] <= 65535:
            raise ValueError("invalid S6NA " + name + " port")
        endpoints[name] = (address, endpoint[1])
    if endpoints["bind"][0].version != endpoints["peer"][0].version:
        raise ValueError("S6NA address families differ")

    limits = value.get("limits", {})
    if not isinstance(limits, dict):
        raise ValueError("invalid S6NA limits")
    adapter = Path(root) / "Network-Adapter"
    if not (adapter / "shadow6_network.py").is_file():
        adapter = Path(root) / "share/shadow6/modules"
    if not (adapter / "shadow6_network.py").is_file():
        raise ValueError("S6NA runtime module is unavailable")
    if str(adapter) not in sys.path:
        sys.path.insert(0, str(adapter))
    from shadow6_network import Limits
    if set(limits) - set(Limits.__dataclass_fields__):
        raise ValueError("invalid S6NA limits")
    resolved_limits = Limits(**limits)
    side = value.get("side", 0)
    stream = value.get("stream", 0)
    if type(side) is not int or side not in (0, 1):
        raise ValueError("invalid S6NA direction")
    if type(stream) is not int or not 0 <= stream < resolved_limits.max_streams:
        raise ValueError("invalid S6NA application stream")
    return {
        "configPath": str(path.absolute()),
        "configDigest": "sha256:" + hashlib.sha256(config_bytes).hexdigest(),
        "keyPath": key_path,
        "keyDigest": "sha256:" + hashlib.sha256(key_bytes).hexdigest(),
        "core": core,
    }
