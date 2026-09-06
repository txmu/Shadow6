#!/usr/bin/env python3
"""Typed, capability-scoped extension slots backed by signed isolated plugins."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
for candidate in (ROOT / "Plugin-System", ROOT / "Security-Assistants", ROOT / "share" / "shadow6" / "modules", ROOT / "share" / "shadow6" / "assistants"):
    if candidate.is_dir():
        sys.path.insert(0, str(candidate))

from shadow6_plugins import PluginError, PluginRegistry, canonical, run_plugin, secure_read, strict_json  # noqa: E402

VERSION = "1.0.0"
MAX_BINDINGS = 128
ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")

# Level 0 is observational; 1 transforms application data; 2 affects policy or
# identity; 3 participates in lifecycle/configuration; 4 requests fixed hands.
SLOTS: dict[str, dict[str, Any]] = {
    "slot.lifecycle.before-start": {"level": 3, "phase": "lifecycle", "mode": "serial", "max_providers": 8},
    "slot.lifecycle.after-stop": {"level": 3, "phase": "lifecycle", "mode": "serial", "max_providers": 8},
    "slot.config.validate": {"level": 3, "phase": "configuration", "mode": "all-must-pass", "max_providers": 8},
    "slot.transport.observe": {"level": 0, "phase": "transport", "mode": "fanout", "max_providers": 16},
    "slot.transport.transform": {"level": 1, "phase": "transport", "mode": "pipeline", "max_providers": 4},
    "slot.protocol.factory": {"level": 1, "phase": "application", "mode": "first-success", "max_providers": 8},
    "slot.chat.filter": {"level": 1, "phase": "application", "mode": "pipeline", "max_providers": 8},
    "slot.identity.verify": {"level": 2, "phase": "identity", "mode": "all-must-pass", "max_providers": 8},
    "slot.security.policy": {"level": 2, "phase": "security", "mode": "all-must-pass", "max_providers": 8},
    "slot.telemetry.sink": {"level": 0, "phase": "observability", "mode": "fanout", "max_providers": 16},
    "slot.assistant.eye": {"level": 0, "phase": "assistant", "mode": "fanout", "max_providers": 16},
    "slot.assistant.hand": {"level": 4, "phase": "assistant", "mode": "serial", "max_providers": 4},
    "slot.init.decorate": {"level": 3, "phase": "service", "mode": "pipeline", "max_providers": 4},
    "slot.ui.panel": {"level": 0, "phase": "presentation", "mode": "fanout", "max_providers": 16},
}


class SlotError(RuntimeError):
    pass


def catalog() -> dict[str, Any]:
    return {
        "version": VERSION, "protocol": "shadow6.slot.v1",
        "isolation": "signed out-of-process plugin sandbox",
        "slots": SLOTS,
    }


def load_bindings(path: Path, registry: PluginRegistry) -> list[dict[str, Any]]:
    try:
        document = strict_json(secure_read(path, 1_048_576))
    except (OSError, ValueError, PluginError) as exc:
        raise SlotError(f"invalid slot binding document: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {"version", "bindings"} or type(document["version"]) is not int or document["version"] != 1:
        raise SlotError("slot document must contain exactly version=1 and bindings")
    bindings = document["bindings"]
    if not isinstance(bindings, list) or len(bindings) > MAX_BINDINGS:
        raise SlotError(f"bindings must be a list with at most {MAX_BINDINGS} entries")
    seen: set[tuple[str, str]] = set()
    counts: dict[str, int] = {}
    validated = []
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != {"slot", "plugin", "priority", "required", "enabled"}:
            raise SlotError("each binding has an exact five-field schema")
        slot, plugin = binding["slot"], binding["plugin"]
        if not isinstance(slot, str) or slot not in SLOTS or not isinstance(plugin, str) or not ID_RE.fullmatch(plugin):
            raise SlotError("binding references an unknown slot or invalid plugin")
        if not isinstance(binding["priority"], int) or isinstance(binding["priority"], bool) or not 0 <= binding["priority"] <= 1000:
            raise SlotError("binding priority must be an integer from 0 through 1000")
        if not isinstance(binding["required"], bool) or not isinstance(binding["enabled"], bool):
            raise SlotError("required and enabled must be booleans")
        key = (slot, plugin)
        if key in seen:
            raise SlotError("duplicate slot/provider binding")
        seen.add(key)
        counts[slot] = counts.get(slot, 0) + int(binding["enabled"])
        if counts[slot] > SLOTS[slot]["max_providers"]:
            raise SlotError(f"slot {slot} exceeds its provider limit")
        manifest = registry.load(plugin)
        if slot not in manifest.capabilities or slot not in manifest.hooks:
            raise SlotError(f"plugin {plugin} is not signed for {slot}")
        validated.append(dict(binding))
    return sorted(validated, key=lambda item: (item["slot"], item["priority"], item["plugin"]))


def invoke(slot: str, payload: dict[str, Any], bindings_path: Path, registry: PluginRegistry, *, allow_privileged: bool = False) -> dict[str, Any]:
    definition = SLOTS.get(slot) if isinstance(slot, str) else None
    if definition is None:
        raise SlotError("unknown slot")
    if definition["level"] >= 3 and not allow_privileged:
        raise SlotError("level 3/4 slot requires explicit privileged approval")
    if not isinstance(payload, dict):
        raise SlotError("slot payload must be an object")
    try:
        if len(canonical(payload)) > 60_000:
            raise SlotError("slot payload is too large")
    except PluginError as exc:
        raise SlotError(str(exc)) from exc
    bindings = [item for item in load_bindings(bindings_path, registry) if item["slot"] == slot and item["enabled"]]
    results = []
    current = payload
    for binding in bindings:
        manifest = registry.load(binding["plugin"])
        if slot not in manifest.capabilities or slot not in manifest.hooks:
            raise SlotError("provider lost its signed slot capability")
        request = {"protocol": "shadow6.slot.v1", "slot": slot, "level": definition["level"], "payload": current}
        try:
            result = run_plugin(manifest, request)
            canonical(result)
            if definition["mode"] == "pipeline":
                replacement = result.get("payload")
                if not isinstance(replacement, dict):
                    raise SlotError(f"pipeline provider {manifest.plugin_id} omitted object payload")
                current = replacement
            if definition["mode"] == "all-must-pass" and result.get("allow") is not True:
                raise SlotError(f"provider {manifest.plugin_id} did not explicitly allow")
            results.append({"plugin": manifest.plugin_id, "ok": True, "result": result})
            if definition["mode"] == "first-success":
                break
        except Exception as exc:
            results.append({"plugin": manifest.plugin_id, "ok": False, "error": str(exc)})
            if binding["required"] or definition["mode"] in {"pipeline", "all-must-pass"}:
                raise SlotError(f"required slot provider {manifest.plugin_id} failed: {exc}") from exc
    if bindings and definition["mode"] == "first-success" and not any(item["ok"] for item in results):
        raise SlotError("no slot provider succeeded")
    return {"protocol": "shadow6.slot.v1", "slot": slot, "level": definition["level"], "payload": current, "results": results}


def main() -> int:
    parser = argparse.ArgumentParser(description="Shadow6 typed extension slot manager")
    parser.add_argument("--plugin-root", type=Path, default=ROOT / "plugins")
    parser.add_argument("--trust-store", type=Path, default=ROOT / "Plugin-System" / "trusted_signers.json")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("catalog")
    validate = commands.add_parser("validate")
    validate.add_argument("--bindings", required=True, type=Path)
    call = commands.add_parser("invoke")
    call.add_argument("slot", choices=sorted(SLOTS))
    call.add_argument("--bindings", required=True, type=Path)
    call.add_argument("--payload", default="{}")
    call.add_argument("--allow-privileged", action="store_true")
    args = parser.parse_args()
    if args.command == "catalog":
        result = catalog()
    else:
        registry = PluginRegistry(args.plugin_root, args.trust_store)
        if args.command == "validate":
            result = {"valid": True, "bindings": load_bindings(args.bindings, registry)}
        else:
            result = invoke(args.slot, strict_json(args.payload, 65_536), args.bindings, registry, allow_privileged=args.allow_privileged)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SlotError, ValueError, OSError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
