#!/usr/bin/env python3
"""Atomic Crosed + application-frame + isolated-Plugin extension pipeline."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
for candidate in (
    ROOT / "Crosed", ROOT / "Application-Layer", ROOT / "Plugin-System",
    ROOT / "Slot-System", ROOT / "Security-Assistants",
    ROOT / "share" / "shadow6" / "modules",
    ROOT / "share" / "shadow6" / "application",
):
    if candidate.is_dir():
        sys.path.insert(0, str(candidate))

from crosedctl import CAPABILITY_LEVELS, CrosedError, negotiate, secure_read, strict_json  # noqa: E402
from shadow_protocols import ProtocolError, decode_frame, encode_frame, normalized_text  # noqa: E402
from shadow6_plugins import PluginRegistry  # noqa: E402
from shadow6_slots import SLOTS, SlotError, invoke as invoke_slot, load_bindings  # noqa: E402

VERSION = "1.0.0"
MAX_REQUEST = 65_536


class ExtensionError(RuntimeError):
    pass


def _slot_capability(slot: str) -> str:
    definition = SLOTS[slot]
    if definition["phase"] == "identity":
        return "identity.assert"
    if definition["phase"] == "security":
        return "policy.request"
    if definition["level"] >= 4:
        return "core.hook"
    if definition["level"] >= 3:
        return "core.lifecycle"
    return "transport.application"


def _application(request: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    payload = request.get("payload")
    if not isinstance(payload, dict) or set(payload) != {"application"}:
        raise ExtensionError("Crosed payload must contain exactly one application frame")
    document = payload["application"]
    required = {"protocol", "version", "slot", "source_domain", "target_domain", "payload"}
    if not isinstance(document, dict) or set(document) != required:
        raise ExtensionError("invalid extension application schema")
    if document["protocol"] != "shadow.extension" or type(document["version"]) is not int or document["version"] != 1:
        raise ExtensionError("unsupported extension application protocol")
    if not isinstance(document["slot"], str) or document["slot"] not in SLOTS or not isinstance(document["payload"], dict):
        raise ExtensionError("extension references an invalid Slot or payload")
    # Round-trip through the shared bounded frame parser. This rejects unknown
    # encodings and non-portable JSON before any Plugin sees the payload.
    decoded = decode_frame(encode_frame(document))
    for name in ("source_domain", "target_domain"):
        value = decoded[name]
        if value != request.get(name, ""):
            raise ExtensionError(f"application {name} does not match signed Crosed domain")
        if value and normalized_text(value) != value:
            raise ExtensionError(f"application {name} must be NFC")
    return decoded["slot"], decoded["payload"]


def invoke(
    core: Path, request_path: Path, crosed_trust: Path, bindings_path: Path,
    registry: PluginRegistry, *, allow_privileged: bool = False,
) -> dict[str, Any]:
    """Authorize and invoke one inseparable three-system extension transaction."""
    try:
        request_bytes = secure_read(request_path, MAX_REQUEST)
        request = strict_json(request_bytes, MAX_REQUEST)
        slot, payload = _application(request)
        required_capability = _slot_capability(slot)
        requested = request.get("capabilities")
        if not isinstance(requested, list) or "transport.application" not in requested or required_capability not in requested:
            raise ExtensionError("signed request lacks the application/Slot capabilities")
        providers = [item for item in load_bindings(bindings_path, registry) if item["slot"] == slot and item["enabled"]]
        if not providers:
            raise ExtensionError("extension Slot has no enabled signed Plugin provider")

        # Negotiate the exact bytes parsed above, avoiding a pathname replacement
        # between application validation and the Core's signature verification.
        descriptor, snapshot_name = tempfile.mkstemp(prefix=".shadow6-extension-")
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=False) as snapshot:
                snapshot.write(request_bytes)
                snapshot.flush()
                os.fsync(snapshot.fileno())
            grant = negotiate(core, Path(snapshot_name), crosed_trust)
        finally:
            os.close(descriptor)
            os.unlink(snapshot_name)

        granted = grant.get("granted_capabilities")
        if grant.get("status") != "granted" or not isinstance(granted, list):
            raise ExtensionError("Core denied the Crosed extension request")
        if "transport.application" not in granted or required_capability not in granted:
            raise ExtensionError("Core grant does not cover the application/Slot transaction")
        level = grant.get("granted_level")
        required_level = max(3, CAPABILITY_LEVELS[required_capability])
        if type(level) is not int or level < required_level:
            raise ExtensionError("Core grant level is below the extension Slot requirement")

        result = invoke_slot(slot, payload, bindings_path, registry, allow_privileged=allow_privileged)
        return {
            "protocol": "shadow6.extension.v1", "version": VERSION,
            "core": grant.get("core"), "slot": slot, "capability": required_capability,
            "source_domain": request.get("source_domain", ""),
            "target_domain": request.get("target_domain", ""), "result": result,
        }
    except (CrosedError, ProtocolError, SlotError, OSError, ValueError, KeyError) as exc:
        if isinstance(exc, ExtensionError):
            raise
        raise ExtensionError(str(exc)) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Shadow6 atomic Crosed/App/Plugin extension pipeline")
    parser.add_argument("--core", required=True, type=Path)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--crosed-trust", required=True, type=Path)
    parser.add_argument("--bindings", required=True, type=Path)
    parser.add_argument("--plugin-root", type=Path, default=ROOT / "plugins")
    parser.add_argument("--plugin-trust", type=Path, default=ROOT / "Plugin-System" / "trusted_signers.json")
    parser.add_argument("--allow-privileged", action="store_true")
    args = parser.parse_args()
    registry = PluginRegistry(args.plugin_root, args.plugin_trust)
    result = invoke(args.core, args.request, args.crosed_trust, args.bindings, registry, allow_privileged=args.allow_privileged)
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ExtensionError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
