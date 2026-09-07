#!/usr/bin/env python3
"""Versioned, deny-by-default operation and configuration API for Shadow6."""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hmac
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if not (ROOT / "Makefile").is_file():
    ROOT = Path(os.environ.get("SHADOW6_ROOT", "/usr/local/share/shadow6/tree"))
for directory in (
    ROOT / "Security-Assistants", ROOT / "Infrastructure-Assistants",
    ROOT / "Auto-Orchestrator", ROOT / "Plugin-System", ROOT / "Crosed",
    ROOT / "Slot-System", ROOT / "Extension-System", ROOT / "Application-Layer", ROOT / "Public6",
    ROOT / "Package-Manager",
    ROOT / "Migration",
    ROOT / "Online-Repository", ROOT / "Gate",
    ROOT / "Service-Init",
    HERE.parent / "share" / "shadow6" / "modules",
    HERE.parent / "share" / "shadow6" / "assistants",
):
    if directory.is_dir():
        sys.path.insert(0, str(directory))

from shadow6_security import SecurityError, atomic_write, bounded_run, doctor, evaluate_policy, generate_sbom, secure_read, strict_json_loads, validate_portable  # noqa: E402
from shadow6_infra import RUNBOOKS, compare_snapshot, create_plan, execute_plan, observe  # noqa: E402
from shadow6_init import generate_init_script, normalize_init_system  # noqa: E402
from shadow6_plugins import PluginRegistry  # noqa: E402
from crosedctl import inspect_binary  # noqa: E402
from shadow6_slots import catalog as slot_catalog, invoke as invoke_slot, load_bindings  # noqa: E402
from shadow6_extensions import invoke as invoke_extension  # noqa: E402
from shadow6_pkg import activate as package_activate, install_package, list_packages, verify_package  # noqa: E402
from shadow6_public import negotiate as public6_negotiate, offer_from_feature_report, read_json as public6_read_json, read_offer as public6_read_offer, suite_profile as public6_profile  # noqa: E402
from shadow6_migrate import export as migration_export, import_bundle as migration_import, plan as migration_plan  # noqa: E402
from shadow6_repo import build as repository_build, sync as repository_sync, verify as repository_verify, regular as repository_read  # noqa: E402
from portmap import generate as portmap_generate, validate as portmap_validate  # noqa: E402

VERSION = "1.3.0"
API_VERSION = "v1"
MAX_REQUEST = 65_536
MAX_RESPONSE = 1_048_576
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
BUILD_FLAGS = (
    "build_go", "build_rust", "build_relay", "build_guard", "build_auto",
    "build_detector", "build_plugins", "build_crosed", "build_app",
    "build_assistants", "build_control", "build_compliance",
    "build_slots", "build_public6", "build_gate", "build_migration",
)


def _input_schema(properties: dict[str, Any] | None = None, required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties or {},
        "required": list(required),
        "additionalProperties": False,
    }


def _method(description: str, properties: dict[str, Any] | None = None,
            required: tuple[str, ...] = (), *, mutating: bool = False) -> dict[str, Any]:
    return {
        "description": description,
        "input_schema": _input_schema(properties, required),
        "mutating": mutating,
    }


_STRING = {"type": "string", "maxLength": 4096}
_PATH = {"type": "string", "maxLength": 4096, "description": "Filesystem path"}
_BOOL = {"type": "boolean"}
_OBJECT = {"type": "object"}

METHOD_SPECS: dict[str, dict[str, Any]] = {
    "system.schema": _method("Return the complete versioned Shadow6 control schema."),
    "system.guide": _method("Read a bilingual guide to safe operations and privacy.", {"lang": {"type": "string", "enum": ["en", "zh"]}}),
    "privacy.report": _method("Return only aggregate health counts, without paths, identifiers or diagnostic details."),
    "system.status": _method("Run bounded read-only component health and observation checks.", {"root": _PATH}),
    "config.render": _method(
        "Render a strict Shadow6 build configuration, optionally to a file.",
        {
            **{flag: _BOOL for flag in BUILD_FLAGS},
            "crosed_level": {"type": "integer", "minimum": 0, "maximum": 5},
            "app_transport": _BOOL, "qubes_isolation": _BOOL, "output": _PATH,
        }, mutating=True,
    ),
    "config.validate": _method(
        "Validate a Core, topology, policy, Plugin, or Slot configuration.",
        {"kind": _STRING, "path": _PATH, "root": _PATH, "binary": _PATH,
         "plugin_root": _PATH, "trust_store": _PATH, "plugin_id": _STRING},
        ("kind", "path"),
    ),
    "init.render": _method(
        "Render an init definition with format-specific escaping.",
        {"system": _STRING, "name": _STRING, "binary": _PATH, "config": _PATH, "output": _PATH},
        ("system", "name", "binary", "config"), mutating=True,
    ),
    "assistant.doctor": _method("Run the read-only deployment doctor.", {"root": _PATH}),
    "assistant.sbom": _method("Generate an in-memory offline CycloneDX SBOM.", {"root": _PATH}),
    "assistant.observe": _method("Create a read-only component observation.", {"root": _PATH}),
    "assistant.drift": _method("Compare current components with a saved observation.", {"root": _PATH, "baseline": _PATH}, ("baseline",)),
    "assistant.policy": _method("Evaluate a strict security policy.", {"root": _PATH, "policy": _PATH}, ("policy",)),
    "plugins.list": _method("List signed out-of-process Plugins.", {"root": _PATH, "plugin_root": _PATH, "trust_store": _PATH, "plugin_id": _STRING}),
    "plugins.verify": _method("Verify one signed Plugin and its capabilities.", {"root": _PATH, "plugin_root": _PATH, "trust_store": _PATH, "plugin_id": _STRING}, ("plugin_id",)),
    "packages.list": _method("List installed Crosed Mod, Plugin, and App versions.", {"store": _PATH}, ("store",)),
    "packages.verify": _method("Verify one bounded signed Shadow6 package without installing it.", {"package": _PATH, "trust_store": _PATH}, ("package", "trust_store")),
    "packages.install": _method("Atomically install and optionally activate one verified package version.", {"package": _PATH, "trust_store": _PATH, "store": _PATH, "activate": _BOOL}, ("package", "trust_store", "store"), mutating=True),
    "packages.activate": _method("Atomically select an already installed package version.", {"store": _PATH, "kind": {"type": "string", "enum": ["app", "crosed-mod", "plugin"]}, "package_id": _STRING, "version": _STRING}, ("store", "kind", "package_id", "version"), mutating=True),
    "crosed.features": _method("Inspect exact compiled Crosed feature contracts.", {"cores": {"type": "array", "items": _PATH, "minItems": 1, "maxItems": 16}}, ("cores",)),
    "public6.profile": _method("Return the Public6 suite and compatibility contract."),
    "public6.offer": _method("Create a strict Public6 offer from a Core feature report.", {"feature_report": _PATH}, ("feature_report",)),
    "public6.negotiate": _method("Negotiate two Public6 offers; only Core family and version determine base compatibility.", {"local": _PATH, "peer": _PATH}, ("local", "peer")),
    "slots.catalog": _method("Return the typed Slot catalog."),
    "slots.validate": _method("Validate signed Plugin Slot bindings.", {"root": _PATH, "plugin_root": _PATH, "trust_store": _PATH, "bindings": _PATH, "slot": _STRING, "payload": _OBJECT, "allow_privileged": _BOOL}, ("bindings",)),
    "slots.invoke": _method("Invoke one typed Slot through a signed isolated Plugin.", {"root": _PATH, "plugin_root": _PATH, "trust_store": _PATH, "bindings": _PATH, "slot": _STRING, "payload": _OBJECT, "allow_privileged": _BOOL}, ("bindings", "slot"), mutating=True),
    "extensions.invoke": _method("Atomically authorize Crosed, validate an application frame, and invoke a signed isolated Plugin Slot.", {"root": _PATH, "core": _PATH, "request": _PATH, "crosed_trust": _PATH, "bindings": _PATH, "plugin_root": _PATH, "plugin_trust": _PATH, "allow_privileged": _BOOL}, ("core", "request", "crosed_trust", "bindings"), mutating=True),
    "runbook.plan": _method("Create a signed, short-lived plan for one fixed runbook.", {"root": _PATH, "action": {"type": "string", "enum": sorted(RUNBOOKS)}, "private_key": _PATH, "ttl": {"type": "integer", "minimum": 30, "maximum": 300}, "output": _PATH}, ("action", "private_key", "output"), mutating=True),
    "runbook.execute": _method("Verify and execute one signed fixed-command plan.", {"root": _PATH, "plan": _PATH, "public_key": _PATH, "state_dir": _PATH}, ("plan", "public_key", "state_dir"), mutating=True),
    "orchestrator.commands": _method("Describe every orchestrator CLI command and its bounded tool equivalent."),
    "orchestrator.dashboard.snapshot": _method("Return the dashboard's bounded component snapshot without starting a TUI.", {"root": _PATH}),
    "orchestrator.rpc.authorize": _method("Evaluate one target against the orchestrator Plugin RPC ACL without opening a listener.", {"target": _STRING, "allowed_ips": {"type": "array", "items": _STRING, "maxItems": 256}, "allowed_domains": {"type": "array", "items": _STRING, "maxItems": 256}}, ("target",)),
    "orchestrator.key.generate": _method("Generate an Ed25519 keypair; write the private key to an owner-only file.", {"private_key_output": _PATH, "public_key_output": _PATH}, ("private_key_output",), mutating=True),
    "orchestrator.spa.generate": _method("Generate one bounded SPA packet using an owner-only secret file.", {"secret_file": _PATH, "source_ip": _STRING}, ("secret_file", "source_ip")),
    "orchestrator.topology.apply": _method("Validate and apply one orchestrator MTD rotation.", {"path": _PATH}, ("path",), mutating=True),
    "orchestrator.client.knock": _method("Send one SPA packet and optionally start one selected Core client.", {"target_ip": _STRING, "target_port": {"type": "integer", "minimum": 1, "maximum": 65535}, "secret_file": _PATH, "source_ip": _STRING, "client_config": _PATH, "engine": {"type": "string", "enum": ["shadow6-go", "shadow6-rust"]}}, ("target_ip", "target_port", "secret_file"), mutating=True),
    "gate.features": _method("Inspect the independently compiled, default-disabled Gate contract.", {"binary": _PATH, "root": _PATH}),
    "gate.validate": _method("Strictly validate a Gate configuration without opening listeners.", {"config": _PATH, "binary": _PATH, "root": _PATH}, ("config",)),
    "gate.current_port": _method("Calculate the current deterministic MTD port without opening listeners.", {"config": _PATH, "binary": _PATH, "root": _PATH}, ("config",)),
    "migration.plan": _method("Plan a bounded Shadow6 migration by scope.", {"root": _PATH, "scopes": {"type":"array","items":_STRING,"maxItems":6}, "include_secrets": _BOOL}),
    "migration.export": _method("Export a manifest-verified migration bundle.", {"root": _PATH, "output": _PATH, "form": {"type":"string","enum":["directory","tar.gz","zip"]}, "scopes": {"type":"array","items":_STRING,"maxItems":6}, "include_secrets": _BOOL}, ("output",), mutating=True),
    "migration.import": _method("Validate or explicitly apply a migration bundle.", {"source": _PATH, "destination": _PATH, "apply": _BOOL}, ("source","destination"), mutating=True),
    "repository.verify": _method("Verify a signed online repository index.", {"index": _PATH, "trust_store": _PATH}, ("index","trust_store")),
    "repository.sync": _method("Fetch hash-verified packages from an HTTPS signed source.", {"url": _STRING, "trust_store": _PATH, "destination": _PATH, "names":{"type":"array","items":_STRING,"maxItems":256}}, ("url","trust_store","destination"), mutating=True),
    "repository.build": _method("Build a signed self-hosted repository index.", {"root":_PATH,"output":_PATH,"private_key":_PATH,"signer":_STRING}, ("root","output","private_key","signer"), mutating=True),
    "gate.portmap.generate": _method("Generate a bounded one-address-per-port logical E-class map.", {"ports":{"type":"array","items":{"type":"integer","minimum":1,"maximum":65535},"maxItems":4096},"start":_STRING}, ("ports",)),
    "gate.portmap.validate": _method("Validate a logical E-class Gate port map.", {"path":_PATH}, ("path",)),
    "process.catalog": _method("List fixed unified-CLI components and availability.", {"root":_PATH}),
    "result.validate": _method("Validate a bounded Control API result envelope.", {"result":_OBJECT}, ("result",)),
}

MUTATING_METHODS = {name for name, spec in METHOD_SPECS.items() if spec["mutating"]}


def schema() -> dict[str, Any]:
    return {
        "api_version": API_VERSION,
        "control_version": VERSION,
        "encoding": "UTF-8",
        "components": [
            "core-go", "core-rust", "relay", "guard", "orchestrator", "detector",
            "plugins", "crosed", "application-layer", "security-assistants",
            "infrastructure-assistants", "slots", "extension-system", "package-manager", "online-repository", "migration", "gate", "i18n", "unified-cli", "public6", "easybuild", "control-center",
        ],
        "features": {
            "crosed_level": {"type": "integer", "minimum": 0, "maximum": 5, "default": 0},
            "app_transport": {"type": "boolean", "default": False},
            "qubes_isolation": {"type": "boolean", "default": False},
            **{flag: {"type": "boolean", "default": flag != "build_compliance"} for flag in BUILD_FLAGS},
        },
        "init_systems": ["systemd", "openrc", "runit", "sysv", "rc.d", "procd", "launchd", "guix"],
        "config_kinds": ["core-go", "core-rust", "topology", "security-policy", "plugin", "package", "slots", "public6-offer"],
        "methods": METHOD_SPECS,
        "transport": {
            "jsonl": {"max_request_bytes": MAX_REQUEST, "mutations_default": False},
            "http": {"loopback_only": True, "bearer_token": True, "mutations_default": False},
            "mcp": {"stdio": True, "protocol_version": "2025-06-18", "mutations_default": False},
            "lsp": {"stdio": True, "execute_command": True, "mutations_default": False},
            "openai": {"responses_function_tools": True, "jsonl": True, "mutations_default": False},
        },
    }


def _params(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("params must be an object")
    return value


def _only(params: dict[str, Any], allowed: set[str]) -> None:
    unknown = set(params) - allowed
    if unknown:
        raise ValueError(f"unknown parameters: {sorted(unknown)}")


def _validate_input(value: Any, contract: dict[str, Any], name: str = "params") -> None:
    """Enforce the same bounded schema advertised to every API client."""
    kind = contract.get("type")
    expected = {"object": dict, "array": list, "string": str, "boolean": bool, "integer": int}
    if kind in expected and (not isinstance(value, expected[kind]) or kind == "integer" and isinstance(value, bool)):
        raise ValueError(f"{name} must be {kind}")
    if "enum" in contract and value not in contract["enum"]:
        raise ValueError(f"{name} is not an allowed value")
    if kind == "object":
        properties = contract.get("properties", {})
        if contract.get("additionalProperties") is False:
            _only(value, set(properties))
        missing = set(contract.get("required", [])) - set(value)
        if missing:
            raise ValueError(f"{name} missing required parameters: {sorted(missing)}")
        for key, item in value.items():
            if key in properties:
                _validate_input(item, properties[key], f"{name}.{key}")
    elif kind == "array":
        if not contract.get("minItems", 0) <= len(value) <= contract.get("maxItems", MAX_REQUEST):
            raise ValueError(f"{name} has an invalid number of items")
        for item in value:
            _validate_input(item, contract.get("items", {}), name + "[]")
    elif kind == "string" and len(value) > contract.get("maxLength", MAX_REQUEST):
        raise ValueError(f"{name} is too long")
    elif kind == "integer" and not contract.get("minimum", -MAX_REQUEST) <= value <= contract.get("maximum", MAX_REQUEST):
        raise ValueError(f"{name} is outside the allowed range")


def _transport_execution_policy(method: str, params: dict[str, Any]) -> None:
    # A read-only inspection can still execute a program. Tool callers cannot
    # replace the trusted repository or select arbitrary host executables.
    root = ROOT.resolve()
    if "root" in params and _root(params) != root:
        raise PermissionError("transport root must be the configured Shadow6 repository")
    if method == "extensions.invoke":
        plugin_root = Path(params.get("plugin_root", root / "plugins")).expanduser().absolute()
        plugin_trust = Path(params.get("plugin_trust", root / "Plugin-System" / "trusted_signers.json")).expanduser().absolute()
        if plugin_root != root / "plugins" or plugin_trust != root / "Plugin-System" / "trusted_signers.json":
            raise PermissionError("transport Plugin roots must be fixed Shadow6 components")
    cores = {root / directory / name for directory, family in (("Core-Go", "go"), ("Core-Rust", "rust"))
             for name in (f"shadow6-{family}", f"shadow6-{family}-crosed", f"shadow6-{family}-public6")}
    cores.update({root / "Core-Ada" / "shadow6-ada", root / "Core-Ada" / "shadow6-ada-crosed"})
    candidates: list[tuple[Any, set[Path]]] = []
    if method == "crosed.features":
        candidates.extend((item, cores) for item in params.get("cores", []))
    elif method == "extensions.invoke":
        candidates.append((params.get("core"), {path for path in cores if path.name.endswith("-crosed")}))
    elif method == "config.validate" and params.get("kind") in {"core-go", "core-rust"} and "binary" in params:
        family = params["kind"].removeprefix("core-")
        candidates.append((params["binary"], {path for path in cores if path.name.startswith(f"shadow6-{family}")}))
    elif method in {"gate.features", "gate.validate", "gate.current_port"} and "binary" in params:
        candidates.append((params["binary"], {root / "Gate/shadow6-gate"}))
    for candidate, allowed in candidates:
        path = Path(candidate).expanduser().absolute()
        if path not in allowed or path.is_symlink() or path.resolve(strict=True) != path:
            raise PermissionError("transport binary must be a fixed Shadow6 component")


def _root(params: dict[str, Any]) -> Path:
    return Path(params.get("root", ROOT)).expanduser().resolve(strict=True)


def _write(path: str, data: bytes, mode: int) -> dict[str, Any]:
    target = Path(path).expanduser()
    if not target.is_absolute():
        raise ValueError("output path must be absolute")
    atomic_write(target, data, mode)
    return {"path": str(target), "bytes": len(data), "mode": f"{mode:04o}"}


def render_build_config(params: dict[str, Any]) -> bytes:
    allowed = set(BUILD_FLAGS) | {"crosed_level", "app_transport", "qubes_isolation", "output"}
    _only(params, allowed)
    values: dict[str, int] = {}
    for flag in BUILD_FLAGS:
        value = params.get(flag, flag != "build_compliance")
        if not isinstance(value, bool):
            raise ValueError(f"{flag} must be boolean")
        values[flag.upper()] = int(value)
    level = params.get("crosed_level", 0)
    if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 5:
        raise ValueError("crosed_level must be an integer from 0 through 5")
    values["CROSED_LEVEL"] = level
    for field in ("app_transport", "qubes_isolation"):
        value = params.get(field, False)
        if not isinstance(value, bool):
            raise ValueError(f"{field} must be boolean")
        values[field.upper()] = int(value)
    return "".join(f"{key}={value}\n" for key, value in values.items()).encode("utf-8")


def _plugin_registry(params: dict[str, Any], root: Path) -> PluginRegistry:
    plugin_root = Path(params.get("plugin_root", root / "plugins"))
    trust_store = Path(params.get("trust_store", root / "Plugin-System" / "trusted_signers.json"))
    return PluginRegistry(plugin_root, trust_store)


def dispatch(method: str, raw_params: Any = None) -> Any:
    params = _params(raw_params)
    if not isinstance(method, str) or method not in METHOD_SPECS:
        raise ValueError("unknown method")
    validate_portable(params)
    _validate_input(params, METHOD_SPECS[method]["input_schema"])
    if method == "system.schema":
        _only(params, set())
        return schema()
    if method == "system.guide":
        zh = params.get("lang", "en") == "zh"
        return {
            "lang": "zh" if zh else "en",
            "message": ("欢迎。先查看功能，再做只读检查；分享诊断时，请使用隐私摘要。" if zh else
                        "Welcome. Check available features first, then local health. Use the privacy summary when sharing diagnostics."),
            "steps": ["shadow6 features", "shadow6 privacy", "shadow6 schema"],
            "privacy": ("摘要仅返回检查计数，不含路径、身份或原始日志；这不提供网络匿名性。" if zh else
                        "The summary contains check counts only, without paths, identities or raw logs. It does not provide network anonymity."),
            "permissions": ("RPC、MCP、LSP、函数工具和 HTTP 默认只读。核对任务后才使用 --allow-mutations。" if zh else
                            "RPC, MCP, LSP, function tools and HTTP are read-only by default. Review the task before using --allow-mutations."),
            "help": ("源码目录可用 .venv/bin/python CLI/shadow6.py 代替 shadow6；详细指引见 docs/getting-started.zh-CN.md。" if zh else
                     "In a source checkout, use .venv/bin/python CLI/shadow6.py in place of shadow6; see docs/getting-started.en.md."),
        }
    if method == "privacy.report":
        # Construct a fresh allowlisted result. Never copy free-form diagnostics,
        # paths, versions, timestamps or stable pseudonyms into a shareable report.
        checks = doctor(ROOT)["checks"]
        passed = sum(item.get("passed") is True for item in checks)
        return {"profile": "aggregate-only", "checks": len(checks), "passed": passed,
                "failed": len(checks) - passed, "network_anonymity": False}
    if method == "system.status":
        _only(params, {"root"})
        root = _root(params)
        return {"doctor": doctor(root), "observation": observe(root)}
    if method == "config.render":
        data = render_build_config(params)
        return _write(params["output"], data, 0o644) if "output" in params else {"content": data.decode()}
    if method == "config.validate":
        _only(params, {"kind", "path", "root", "binary", "plugin_root", "trust_store", "plugin_id"})
        kind, path, root = params.get("kind"), Path(params.get("path", "")), _root(params)
        if kind == "topology":
            from shadow6_auto import load_topology_file
            value = load_topology_file(str(path))
        elif kind == "security-policy":
            value = evaluate_policy(root, path)
        elif kind in {"core-go", "core-rust"}:
            default = root / ("Core-Go/shadow6-go" if kind == "core-go" else "Core-Rust/shadow6-rust")
            binary = Path(params.get("binary", default)).resolve(strict=True)
            completed = bounded_run([str(binary), "--config", str(path.absolute()), "--check-config"], cwd=root, timeout=10)
            if completed.returncode:
                raise ValueError((completed.stderr or completed.stdout).strip() or "Core rejected configuration")
            value = {"status": "valid", "core": kind}
        elif kind == "plugin":
            registry = _plugin_registry(params, root)
            manifest = registry.load(str(params.get("plugin_id", "")))
            value = {"status": "valid", "plugin": manifest.plugin_id, "version": manifest.version, "signer": manifest.signer}
        elif kind == "package":
            if "trust_store" not in params:
                raise ValueError("package validation requires an explicit trust_store")
            trust_store = Path(params["trust_store"])
            manifest, source = verify_package(path, trust_store)
            source.close()
            value = {"status": "valid", **{key: manifest[key] for key in ("kind", "id", "version", "signer")}}
        elif kind == "slots":
            registry = _plugin_registry(params, root)
            value = {"bindings": load_bindings(path, registry)}
        elif kind == "public6-offer":
            value = public6_read_offer(path)
        else:
            raise ValueError("unsupported config kind")
        return {"kind": kind, "valid": True, "result": value}
    if method == "init.render":
        _only(params, {"system", "name", "binary", "config", "output"})
        required = ("system", "name", "binary", "config")
        if any(not isinstance(params.get(key), str) for key in required):
            raise ValueError("system, name, binary and config are required strings")
        system = normalize_init_system(params["system"])
        content = generate_init_script(system, params["name"], params["binary"], params["config"])
        mode = 0o755 if system in {"openrc", "runit", "sysv", "rc.d", "procd"} else 0o644
        return _write(params["output"], content.encode(), mode) if "output" in params else {"system": system, "mode": f"{mode:04o}", "content": content}
    if method.startswith("assistant."):
        root = _root(params)
        if method == "assistant.doctor":
            _only(params, {"root"}); return doctor(root)
        if method == "assistant.sbom":
            _only(params, {"root"}); return generate_sbom(root)
        if method == "assistant.observe":
            _only(params, {"root"}); return observe(root)
        if method == "assistant.drift":
            _only(params, {"root", "baseline"}); return compare_snapshot(root, Path(params["baseline"]))
        if method == "assistant.policy":
            _only(params, {"root", "policy"}); return evaluate_policy(root, Path(params["policy"]))
    if method in {"plugins.list", "plugins.verify"}:
        _only(params, {"root", "plugin_root", "trust_store", "plugin_id"})
        registry = _plugin_registry(params, _root(params))
        if method == "plugins.list":
            return {"plugins": registry.discover()}
        manifest = registry.load(str(params.get("plugin_id", "")))
        return {"plugin": manifest.plugin_id, "version": manifest.version, "signer": manifest.signer, "capabilities": sorted(manifest.capabilities)}
    if method.startswith("packages."):
        if method == "packages.list":
            _only(params, {"store"})
            return {"packages": list_packages(Path(params["store"]).expanduser())}
        if method == "packages.verify":
            _only(params, {"package", "trust_store"})
            manifest, source = verify_package(Path(params["package"]), Path(params["trust_store"]))
            source.close()
            return {key: manifest[key] for key in ("kind", "id", "version", "signer")}
        if method == "packages.install":
            _only(params, {"package", "trust_store", "store", "activate"})
            if "activate" in params and not isinstance(params["activate"], bool):
                raise ValueError("activate must be boolean")
            manifest = install_package(Path(params["package"]), Path(params["trust_store"]), Path(params["store"]), params.get("activate", True))
            return {"installed": True, **{key: manifest[key] for key in ("kind", "id", "version", "signer")}}
        _only(params, {"store", "kind", "package_id", "version"})
        package_activate(Path(params["store"]), str(params["kind"]), str(params["package_id"]), str(params["version"]))
        return {"activated": True, "kind": params["kind"], "id": params["package_id"], "version": params["version"]}
    if method == "crosed.features":
        _only(params, {"cores"})
        cores = params.get("cores")
        if not isinstance(cores, list) or not cores or not all(isinstance(item, str) for item in cores):
            raise ValueError("cores must be a non-empty string list")
        return {"cores": [inspect_binary(Path(item)) for item in cores]}
    if method == "public6.profile":
        _only(params, set())
        return public6_profile()
    if method == "public6.offer":
        _only(params, {"feature_report"})
        return offer_from_feature_report(public6_read_json(Path(params["feature_report"])))
    if method == "public6.negotiate":
        _only(params, {"local", "peer"})
        return public6_negotiate(public6_read_offer(Path(params["local"])), public6_read_offer(Path(params["peer"])))
    if method == "gate.portmap.generate":
        _only(params,{"ports","start"});ports=params.get("ports")
        if not isinstance(ports,list): raise ValueError("ports must be a list")
        return portmap_generate(ports,str(params.get("start","240.0.0.1")))
    if method == "gate.portmap.validate":
        _only(params,{"path"});return portmap_validate(strict_json_loads(secure_read(Path(params["path"]))))
    if method.startswith("gate."):
        _only(params, {"root", "binary", "config"})
        root = _root(params)
        binary = Path(params.get("binary", root / "Gate/shadow6-gate")).resolve(strict=True)
        command = [str(binary), "--feature-report"]
        if method == "gate.validate":
            command = [str(binary), "--config", str(Path(params["config"]).absolute()), "--check-config"]
        elif method == "gate.current_port":
            command = [str(binary), "--config", str(Path(params["config"]).absolute()), "--current-port"]
        elif method != "gate.features":
            raise ValueError("unsupported Gate method")
        completed = bounded_run(command, cwd=root, timeout=10)
        if completed.returncode:
            raise ValueError((completed.stderr or completed.stdout).strip() or "Gate command failed")
        output = completed.stdout.strip()
        return strict_json_loads(output) if method == "gate.features" else ({"valid": True} if method == "gate.validate" else {"port": int(output)})
    if method.startswith("migration."):
        allowed = {"root", "output", "form", "scopes", "include_secrets", "source", "destination", "apply"}
        _only(params, allowed)
        scopes = params.get("scopes", [])
        if not isinstance(scopes, list) or len(scopes) > 6 or not all(isinstance(item, str) for item in scopes):
            raise ValueError("scopes must be a bounded string list")
        include_secrets = params.get("include_secrets", False)
        if not isinstance(include_secrets, bool): raise ValueError("include_secrets must be boolean")
        if method == "migration.plan":
            return migration_plan(_root(params), scopes, include_secrets)
        if method == "migration.export":
            return migration_export(_root(params), Path(params["output"]), str(params.get("form", "tar.gz")), scopes, include_secrets)
        if method == "migration.import":
            apply = params.get("apply", False)
            if not isinstance(apply, bool): raise ValueError("apply must be boolean")
            return migration_import(Path(params["source"]).resolve(strict=True), Path(params["destination"]).resolve(strict=True), not apply)
        raise ValueError("unsupported migration method")
    if method.startswith("repository."):
        if method=="repository.verify":
            _only(params,{"index","trust_store"});return repository_verify(repository_read(Path(params["index"]),1_048_576),Path(params["trust_store"]))
        if method=="repository.sync":
            _only(params,{"url","trust_store","destination","names"});names=params.get("names",[])
            if not isinstance(names,list) or len(names)>256 or not all(isinstance(x,str) for x in names):raise ValueError("names must be a bounded string list")
            return repository_sync(str(params["url"]),Path(params["trust_store"]),Path(params["destination"]),names)
        if method=="repository.build":
            _only(params,{"root","output","private_key","signer"});return repository_build(Path(params["root"]).resolve(strict=True),Path(params["output"]),Path(params["private_key"]),str(params["signer"]))
        raise ValueError("unsupported repository method")
    if method=="process.catalog":
        _only(params,{"root"});root=_root(params);paths={"go":"Core-Go/shadow6-go","rust":"Core-Rust/shadow6-rust","gate":"Gate/shadow6-gate","control":"Control-Center/shadow6_control.py","migrate":"Migration/shadow6_migrate.py","repo":"Online-Repository/shadow6_repo.py"};return {"components":[{"name":name,"available":(root/path).is_file()} for name,path in paths.items()]}
    if method=="result.validate":
        _only(params,{"result"});result=params.get("result")
        if not isinstance(result,dict) or set(result)-{"id","ok","result","error"} or not isinstance(result.get("ok"),bool):raise ValueError("invalid result envelope")
        if result["ok"] and "error" in result or not result["ok"] and "result" in result:raise ValueError("inconsistent result envelope")
        return {"valid":True,"ok":result["ok"]}
    if method == "slots.catalog":
        _only(params, set())
        return slot_catalog()
    if method in {"slots.validate", "slots.invoke"}:
        _only(params, {"root", "plugin_root", "trust_store", "bindings", "slot", "payload", "allow_privileged"})
        root = _root(params)
        registry = _plugin_registry(params, root)
        bindings = Path(params["bindings"])
        if method == "slots.validate":
            return {"valid": True, "bindings": load_bindings(bindings, registry)}
        return invoke_slot(str(params.get("slot", "")), params.get("payload", {}), bindings, registry, allow_privileged=params.get("allow_privileged") is True)
    if method == "extensions.invoke":
        _only(params, {"root", "core", "request", "crosed_trust", "bindings", "plugin_root", "plugin_trust", "allow_privileged"})
        root = _root(params)
        registry = PluginRegistry(
            Path(params.get("plugin_root", root / "plugins")),
            Path(params.get("plugin_trust", root / "Plugin-System" / "trusted_signers.json")),
        )
        return invoke_extension(
            Path(params["core"]), Path(params["request"]), Path(params["crosed_trust"]),
            Path(params["bindings"]), registry,
            allow_privileged=params.get("allow_privileged") is True,
        )
    if method == "runbook.plan":
        _only(params, {"root", "action", "private_key", "ttl", "output"})
        action = params.get("action")
        if action not in RUNBOOKS or "output" not in params:
            raise ValueError("fixed action and output are required")
        plan = create_plan(_root(params), action, Path(params["private_key"]), int(params.get("ttl", 300)))
        return _write(params["output"], json.dumps(plan, sort_keys=True, separators=(",", ":")).encode() + b"\n", 0o600)
    if method == "runbook.execute":
        _only(params, {"root", "plan", "public_key", "state_dir"})
        return execute_plan(Path(params["plan"]), Path(params["public_key"]), _root(params), Path(params["state_dir"]))
    if method == "orchestrator.commands":
        _only(params, set())
        return {
            "commands": {
                "apply": {"tool": "orchestrator.topology.apply", "bounded": True},
                "client-knock": {"tool": "orchestrator.client.knock", "bounded": True},
                "dashboard": {"tool": "orchestrator.dashboard.snapshot", "reason": "bounded snapshot; interactive TUI remains terminal-only"},
                "mtd-daemon": {"tool": "orchestrator.topology.apply", "reason": "tool performs one bounded rotation; schedule repetitions with the host service manager"},
                "rpc-server": {"tool": "orchestrator.rpc.authorize", "reason": "bounded ACL decision; use a protocol adapter instead of nesting a listener"},
            }
        }
    if method == "orchestrator.dashboard.snapshot":
        _only(params, {"root"})
        return {"telemetry": "not-configured", "observation": observe(_root(params))}
    if method == "orchestrator.rpc.authorize":
        from shadow6_auto import PluginACL
        _only(params, {"target", "allowed_ips", "allowed_domains"})
        allowed_ips = params.get("allowed_ips", [])
        allowed_domains = params.get("allowed_domains", [])
        if not isinstance(allowed_ips, list) or not isinstance(allowed_domains, list):
            raise ValueError("allowed_ips and allowed_domains must be lists")
        if len(allowed_ips) > 256 or len(allowed_domains) > 256 or not all(isinstance(item, str) for item in allowed_ips + allowed_domains):
            raise ValueError("ACL lists must contain at most 256 strings")
        target = params.get("target")
        if not isinstance(target, str) or len(target) > 255:
            raise ValueError("target must be a bounded string")
        return {"target": target, "authorized": PluginACL(allowed_ips, allowed_domains).is_allowed(target)}
    if method == "orchestrator.key.generate":
        from shadow6_auto import generate_ed25519_keypair
        _only(params, {"private_key_output", "public_key_output"})
        if "private_key_output" not in params:
            raise ValueError("private_key_output is required")
        public_key, private_key = generate_ed25519_keypair()
        private_result = _write(params["private_key_output"], (private_key + "\n").encode(), 0o600)
        result = {"algorithm": "Ed25519", "public_key": public_key, "private_key_file": private_result}
        if "public_key_output" in params:
            result["public_key_file"] = _write(params["public_key_output"], (public_key + "\n").encode(), 0o644)
        return result
    if method == "orchestrator.spa.generate":
        from shadow6_auto import generate_spa_packet
        _only(params, {"secret_file", "source_ip"})
        secret = secure_read(Path(params["secret_file"]), 4096, secret=True).decode("utf-8").strip()
        packet = generate_spa_packet(secret, str(params["source_ip"]))
        return {"encoding": "base64", "packet": base64.b64encode(packet).decode("ascii"), "bytes": len(packet)}
    if method == "orchestrator.topology.apply":
        from shadow6_auto import apply_topology
        _only(params, {"path"})
        apply_topology(str(params["path"]))
        return {"applied": True, "path": str(Path(params["path"]).expanduser().resolve())}
    if method == "orchestrator.client.knock":
        from shadow6_auto import send_client_knock
        _only(params, {"target_ip", "target_port", "secret_file", "source_ip", "client_config", "engine"})
        secret = secure_read(Path(params["secret_file"]), 4096, secret=True).decode("utf-8").strip()
        return send_client_knock(
            str(params["target_ip"]), params["target_port"], secret,
            params.get("source_ip"), params.get("client_config"), params.get("engine", "shadow6-rust"),
        )
    raise ValueError("unknown method")


def _safe_error(exc: Exception) -> str:
    """Fixed messages prevent exception text from reflecting secrets or paths."""
    if isinstance(exc, PermissionError):
        return "Operation denied. Check the transport policy and explicit mutation permission."
    if isinstance(exc, (ValueError, KeyError, TypeError, SecurityError)):
        return "Request rejected. Check method names, required fields and types in system.schema."
    if isinstance(exc, OSError):
        return "Local resource unavailable. Check file existence, ownership and permissions locally."
    if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)):
        return "Operation timed out. Check local component health before retrying."
    return "Operation failed. Run a local health check; implementation details are withheld."


def response(request: Any, *, allow_mutations: bool = False) -> dict[str, Any]:
    request_id = request.get("id") if isinstance(request, dict) else None
    try:
        if not isinstance(request, dict) or set(request) - {"id", "method", "params"}:
            raise ValueError("request must contain only id, method and params")
        method = request.get("method")
        if not isinstance(method, str):
            raise ValueError("method must be a string")
        if request_id is not None and (type(request_id) not in (str, int) or isinstance(request_id, str) and len(request_id) > 256):
            request_id = None
            raise ValueError("id must be a bounded string or integer")
        validate_portable(request)
        if method in MUTATING_METHODS and not allow_mutations:
            raise PermissionError("mutating method is disabled on this transport")
        params = _params(request.get("params"))
        _transport_execution_policy(method, params)
        result = {"id": request_id, "ok": True, "result": dispatch(method, params)}
        _bounded_json(result)
        return result
    except Exception as exc:  # API boundary intentionally normalizes implementation errors.
        return {"id": request_id, "ok": False, "error": {"code": type(exc).__name__, "message": _safe_error(exc)}}


def _bounded_lines():
    """Stop at an oversized frame without allocating or draining an endless line."""
    while raw := sys.stdin.buffer.readline(MAX_REQUEST + 1):
        yield raw
        if len(raw) > MAX_REQUEST:
            return


def jsonl(allow_mutations: bool = False) -> int:
    for raw in _bounded_lines():
        if len(raw) > MAX_REQUEST:
            result = {"id": None, "ok": False, "error": {"code": "RequestTooLarge", "message": "request exceeds 65536 bytes"}}
        else:
            try:
                with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink):
                    result = response(strict_json_loads(raw, limit=MAX_REQUEST), allow_mutations=allow_mutations)
            except (UnicodeDecodeError, ValueError, SecurityError) as exc:
                result = {"id": None, "ok": False, "error": {"code": "InvalidJSON", "message": _safe_error(exc)}}
        print(_bounded_json(result), flush=True)
    return 0


def _tool_name(method: str) -> str:
    return "shadow6_" + method.replace(".", "_").replace("-", "_")


TOOL_METHODS = {_tool_name(method): method for method in METHOD_SPECS}


def _tool_definitions(protocol: str) -> list[dict[str, Any]]:
    definitions = []
    for name, method in TOOL_METHODS.items():
        spec = METHOD_SPECS[method]
        if protocol == "mcp":
            definitions.append({
                "name": name,
                "description": spec["description"],
                "inputSchema": spec["input_schema"],
                "annotations": {
                    "readOnlyHint": not spec["mutating"],
                    "destructiveHint": spec["mutating"],
                    "idempotentHint": not spec["mutating"],
                },
            })
        elif protocol == "openai":
            definitions.append({
                "type": "function",
                "name": name,
                "description": spec["description"],
                "parameters": spec["input_schema"],
                # Dispatch rejects unknown fields.  This is false because some
                # optional parameters are omitted rather than represented as null.
                "strict": False,
            })
    return definitions


def _bounded_json(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) > MAX_RESPONSE:
        raise ValueError(f"response exceeds {MAX_RESPONSE} bytes")
    return encoded


def _invoke_tool(name: str, arguments: Any, allow_mutations: bool) -> Any:
    method = TOOL_METHODS.get(name)
    if method is None:
        raise ValueError("unknown tool")
    if method in MUTATING_METHODS and not allow_mutations:
        raise PermissionError("mutating tool is disabled; restart this adapter with --allow-mutations")
    validate_portable(arguments)
    _transport_execution_policy(method, _params(arguments))
    # Component progress may contain paths and identities. Discard it at the
    # adapter boundary; structured results remain the supported interface.
    with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink):
        result = dispatch(method, arguments)
    _bounded_json(result)
    return result


def _jsonrpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message[:1024]}}


def mcp(allow_mutations: bool = False) -> int:
    """Serve MCP JSON-RPC over bounded newline-delimited stdio."""
    initialized = False
    supported_versions = {"2024-11-05", "2025-03-26", "2025-06-18"}
    for raw in _bounded_lines():
        request: Any = None
        request_id = None
        reply: dict[str, Any] | None = None
        if len(raw) > MAX_REQUEST:
            reply = _jsonrpc_error(None, -32600, "request exceeds 65536 bytes")
        else:
            try:
                request = strict_json_loads(raw, limit=MAX_REQUEST)
                if not isinstance(request, dict) or request.get("jsonrpc") != "2.0" or set(request) - {"jsonrpc", "id", "method", "params"}:
                    raise ValueError("invalid JSON-RPC request")
                request_id = request.get("id")
                if request_id is not None and (type(request_id) not in (str, int) or isinstance(request_id, str) and len(request_id) > 256):
                    request_id = None
                    raise ValueError("id must be a bounded string or integer")
                method = request.get("method")
                params = request.get("params", {})
                if not isinstance(method, str) or not isinstance(params, dict):
                    raise ValueError("method and params have invalid types")
                if method == "initialize":
                    requested = params.get("protocolVersion")
                    version = requested if requested in supported_versions else "2025-06-18"
                    initialized = True
                    reply = {"jsonrpc": "2.0", "id": request_id, "result": {
                        "protocolVersion": version,
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "shadow6-control", "version": VERSION},
                    }}
                elif method in {"notifications/initialized", "notifications/cancelled"}:
                    continue
                elif method == "ping":
                    reply = {"jsonrpc": "2.0", "id": request_id, "result": {}}
                elif not initialized:
                    reply = _jsonrpc_error(request_id, -32002, "server is not initialized")
                elif method == "tools/list":
                    if set(params) - {"cursor"} or params.get("cursor") not in (None, ""):
                        raise ValueError("pagination cursor is not supported")
                    reply = {"jsonrpc": "2.0", "id": request_id, "result": {"tools": _tool_definitions("mcp")}}
                elif method == "tools/call":
                    if set(params) - {"name", "arguments"} or not isinstance(params.get("name"), str):
                        raise ValueError("tools/call requires only name and arguments")
                    try:
                        result = _invoke_tool(params["name"], params.get("arguments", {}), allow_mutations)
                        text = _bounded_json(result)
                        reply = {"jsonrpc": "2.0", "id": request_id, "result": {
                            "content": [{"type": "text", "text": text}],
                            "structuredContent": result,
                            "isError": False,
                        }}
                    except Exception as exc:  # MCP tool errors are successful JSON-RPC results.
                        reply = {"jsonrpc": "2.0", "id": request_id, "result": {
                            "content": [{"type": "text", "text": _safe_error(exc)}], "isError": True,
                        }}
                else:
                    reply = _jsonrpc_error(request_id, -32601, "method not found")
            except (UnicodeDecodeError, json.JSONDecodeError, SecurityError):
                reply = _jsonrpc_error(None, -32700, "invalid JSON")
            except (ValueError, TypeError) as exc:
                reply = _jsonrpc_error(request_id, -32602, _safe_error(exc))
        if isinstance(request, dict) and "id" not in request:
            reply = None
        if reply is not None:
            try:
                encoded = _bounded_json(reply)
            except (ValueError, UnicodeError):
                encoded = _bounded_json(_jsonrpc_error(request_id, -32603, "response exceeds transport bounds"))
            print(encoded, flush=True)
    return 0


def _read_lsp_message() -> dict[str, Any] | None:
    content_length = None
    header_bytes = 0
    while True:
        line = sys.stdin.buffer.readline(8193)
        if not line:
            if header_bytes:
                raise ValueError("truncated LSP header")
            return None
        header_bytes += len(line)
        if header_bytes > 8192:
            raise ValueError("LSP headers exceed 8192 bytes")
        if line in {b"\r\n", b"\n"}:
            break
        try:
            name, value = line.decode("ascii").split(":", 1)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("malformed LSP header") from exc
        if name.lower() == "content-length":
            if content_length is not None or not re.fullmatch(r"[0-9]+", value.strip()):
                raise ValueError("duplicate or invalid LSP Content-Length")
            content_length = int(value.strip())
    if content_length is None or not 0 <= content_length <= MAX_REQUEST:
        raise ValueError("invalid or excessive LSP Content-Length")
    body = sys.stdin.buffer.read(content_length)
    if len(body) != content_length:
        raise ValueError("truncated LSP message")
    value = strict_json_loads(body, limit=MAX_REQUEST)
    if not isinstance(value, dict):
        raise ValueError("LSP message must be an object")
    return value


def _write_lsp_message(value: dict[str, Any]) -> None:
    body = _bounded_json(value).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body)
    sys.stdout.buffer.flush()


def lsp(allow_mutations: bool = False) -> int:
    """Serve a small LSP 3.17 command server for IDE integrations."""
    shutdown = False
    while True:
        try:
            request = _read_lsp_message()
        except (ValueError, SecurityError) as exc:
            print(f"LSP framing error: {exc}", file=sys.stderr)
            return 2
        if request is None:
            return 0
        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})
        if method == "exit":
            return 0 if shutdown else 1
        if "id" not in request:
            continue
        try:
            if request.get("jsonrpc") != "2.0" or set(request) - {"jsonrpc", "id", "method", "params"}:
                raise ValueError("invalid JSON-RPC request")
            if request_id is not None and (type(request_id) not in (str, int) or isinstance(request_id, str) and len(request_id) > 256):
                request_id = None
                raise ValueError("id must be a bounded string or integer")
            if shutdown:
                raise ValueError("server has shut down")
            if method == "initialize":
                result = {"capabilities": {"executeCommandProvider": {"commands": sorted(TOOL_METHODS)}},
                          "serverInfo": {"name": "shadow6-control", "version": VERSION}}
            elif method == "shutdown":
                shutdown = True
                result = None
            elif method == "shadow6/tools":
                result = _tool_definitions("mcp")
            elif method == "workspace/executeCommand":
                if not isinstance(params, dict) or set(params) - {"command", "arguments", "workDoneToken"}:
                    raise ValueError("invalid executeCommand parameters")
                arguments = params.get("arguments", [])
                if not isinstance(arguments, list) or len(arguments) > 1:
                    raise ValueError("executeCommand accepts zero or one object argument")
                tool_arguments = arguments[0] if arguments else {}
                result = _invoke_tool(params.get("command"), tool_arguments, allow_mutations)
            else:
                _write_lsp_message(_jsonrpc_error(request_id, -32601, "method not found"))
                continue
            _write_lsp_message({"jsonrpc": "2.0", "id": request_id, "result": result})
        except Exception as exc:
            _write_lsp_message(_jsonrpc_error(request_id, -32602, _safe_error(exc)))


def openai_jsonl(allow_mutations: bool = False) -> int:
    """Translate Responses API function_call items to function_call_output items."""
    for raw in _bounded_lines():
        call_id = None
        try:
            if len(raw) > MAX_REQUEST:
                raise ValueError("request exceeds 65536 bytes")
            item = strict_json_loads(raw, limit=MAX_REQUEST)
            if not isinstance(item, dict) or set(item) - {"type", "call_id", "name", "arguments"}:
                raise ValueError("invalid function_call item")
            if item.get("type", "function_call") != "function_call":
                raise ValueError("item type must be function_call")
            call_id = item.get("call_id")
            if not isinstance(call_id, str) or len(call_id) > 256:
                call_id = None
                raise ValueError("call_id must be a bounded string")
            arguments = item.get("arguments", "{}")
            if isinstance(arguments, str):
                arguments = strict_json_loads(arguments, limit=MAX_REQUEST)
            result = {"ok": True, "result": _invoke_tool(item.get("name"), arguments, allow_mutations)}
        except Exception as exc:
            result = {"ok": False, "error": {"code": type(exc).__name__, "message": _safe_error(exc)}}
        try:
            output = _bounded_json(result)
            encoded = _bounded_json({"type": "function_call_output", "call_id": call_id, "output": output})
        except (ValueError, UnicodeError):
            encoded = _bounded_json({"type": "function_call_output", "call_id": call_id,
                                     "output": '{"ok":false,"error":{"code":"ResponseTooLarge","message":"response exceeds transport bounds"}}'})
        print(encoded, flush=True)
    return 0


def _loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def http_app(token: str, allow_mutations: bool = False):
    from aiohttp import web
    if not 32 <= len(token) <= 4096 or any(not 33 <= ord(char) <= 126 for char in token):
        raise ValueError("bearer token must contain 32..4096 visible ASCII bytes")
    expected = f"Bearer {token}".encode("ascii")
    semaphore = asyncio.Semaphore(16)

    @web.middleware
    async def security(request: web.Request, handler):
        authorization = request.headers.getall("Authorization", [])
        provided = (authorization[0] if len(authorization) == 1 else "").encode("utf-8", errors="replace")
        # Pin the authority to the actual listening socket, never proxy headers
        # or DNS. A browser reaching loopback through a hostile name is denied.
        local = request.transport.get_extra_info("sockname") if request.transport else None
        hosts = request.headers.getall("Host", [])
        allowed_hosts = set()
        if local and _loopback(local[0]):
            address = f"[{local[0]}]" if ":" in local[0] else local[0]
            allowed_hosts = {f"{address}:{local[1]}", f"localhost:{local[1]}"}
            if local[1] == 80:
                allowed_hosts.update({address, "localhost"})
        host = hosts[0].lower() if len(hosts) == 1 else ""
        origins = request.headers.getall("Origin", [])
        fetch_sites = request.headers.getall("Sec-Fetch-Site", [])
        if not hmac.compare_digest(provided, expected):
            result = web.json_response({"error": "unauthorized"}, status=401)
            result.headers["WWW-Authenticate"] = 'Bearer realm="shadow6-control"'
        elif host not in allowed_hosts:
            result = web.json_response({"error": "use the loopback address and listening port"}, status=403)
        elif (origins and origins != [f"http://{host}"]) or (fetch_sites and fetch_sites not in (["same-origin"], ["none"])):
            result = web.json_response({"error": "cross-origin browser requests are not allowed"}, status=403)
        elif semaphore.locked():
            result = web.json_response({"error": "server busy"}, status=503)
        else:
            async with semaphore:
                try:
                    result = await handler(request)
                except web.HTTPException as exc:
                    result = web.json_response({"error": exc.reason}, status=exc.status)
        result.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"})
        return result

    app = web.Application(client_max_size=MAX_REQUEST, middlewares=[security])

    async def get_schema(request):
        return web.Response(text=_bounded_json(schema()), content_type="application/json")

    async def get_status(request):
        result = await asyncio.to_thread(response, {"method": "system.status"}, allow_mutations=False)
        return web.Response(text=_bounded_json(result["result"] if result["ok"] else result),
                            status=200 if result["ok"] else 400, content_type="application/json")

    app.router.add_get("/v1/schema", get_schema)
    app.router.add_get("/v1/status", get_status)

    async def rpc(request: web.Request) -> web.Response:
        if (len(request.headers.getall("Content-Type", [])) != 1
                or request.content_type != "application/json"):
            return web.json_response({"error": "send Content-Type: application/json with a UTF-8 JSON body"}, status=415)
        if request.headers.getall("Content-Encoding", []) not in ([], ["identity"]):
            return web.json_response({"error": "send an uncompressed JSON body"}, status=415)
        try:
            async with asyncio.timeout(10):
                body = strict_json_loads(await request.read(), limit=MAX_REQUEST)
        except TimeoutError:
            return web.json_response({"error": "request body timed out"}, status=408)
        except (ValueError, SecurityError):
            return web.json_response({"error": "invalid JSON"}, status=400)
        result = await asyncio.to_thread(response, body, allow_mutations=allow_mutations)
        return web.Response(text=_bounded_json(result), status=200 if result["ok"] else 400,
                            content_type="application/json")

    app.router.add_post("/v1/rpc", rpc)
    return app


def http_runner(app):
    from aiohttp import web

    class BoundedServer(web.Server):
        def connection_made(self, handler, transport):
            if len(self.connections) >= 64:
                transport.close()
                return
            super().connection_made(handler, transport)

    class BoundedRunner(web.AppRunner):
        async def _make_server(self):
            server = await super()._make_server()
            return BoundedServer(server.request_handler, request_factory=server.request_factory,
                                 access_log=None, keepalive_timeout=15, max_headers=64,
                                 max_line_size=8192, max_field_size=8192, read_bufsize=65_536,
                                 auto_decompress=False, handler_cancellation=False)

    return BoundedRunner(app, access_log=None)


async def serve(host: str, port: int, token_file: Path, allow_mutations: bool) -> None:
    from aiohttp import web
    if not _loopback(host) or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("HTTP API must use a loopback host and a valid port")
    token = secure_read(token_file, 4096, secret=True).decode("utf-8").strip()
    runner = http_runner(http_app(token, allow_mutations))
    await runner.setup()
    try:
        await web.TCPSite(runner, "127.0.0.1" if host.lower() == "localhost" else host, port, backlog=64).start()
        print(f"Shadow6 Control Center listening on http://{host}:{port}/v1", flush=True)
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description="Shadow6 one-stop operation and configuration center")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("schema")
    commands.add_parser("status").add_argument("--root", type=Path, default=ROOT)
    call = commands.add_parser("call")
    call.add_argument("method")
    call.add_argument("--params", default="{}", help="JSON object")
    commands.add_parser("rpc", help="serve read-only JSONL; opt in to writes explicitly").add_argument("--allow-mutations", action="store_true")
    commands.add_parser("guide", help="read the shared bilingual guide").add_argument("--lang", choices=("en", "zh"), default="en")
    commands.add_parser("privacy", help="show aggregate diagnostics suitable for sharing")
    mcp_server = commands.add_parser("mcp", help="serve MCP for Claude/Cursor over stdio")
    mcp_server.add_argument("--allow-mutations", action="store_true")
    lsp_server = commands.add_parser("lsp", help="serve LSP workspace commands over stdio")
    lsp_server.add_argument("--allow-mutations", action="store_true")
    commands.add_parser("openai-tools", help="print Responses API function tool definitions")
    openai_server = commands.add_parser("openai-rpc", help="translate OpenAI function calls over JSONL")
    openai_server.add_argument("--allow-mutations", action="store_true")
    server = commands.add_parser("serve", help="serve authenticated loopback HTTP for GUI/Web UI")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=9466)
    server.add_argument("--token-file", type=Path, required=True)
    server.add_argument("--allow-mutations", action="store_true")
    args = parser.parse_args()
    if args.command == "schema":
        result = schema()
    elif args.command == "status":
        result = dispatch("system.status", {"root": str(args.root)})
    elif args.command == "call":
        result = dispatch(args.method, strict_json_loads(args.params, limit=MAX_REQUEST))
    elif args.command == "guide":
        result = dispatch("system.guide", {"lang": args.lang})
    elif args.command == "privacy":
        result = dispatch("privacy.report")
    elif args.command == "rpc":
        return jsonl(args.allow_mutations)
    elif args.command == "mcp":
        return mcp(args.allow_mutations)
    elif args.command == "lsp":
        return lsp(args.allow_mutations)
    elif args.command == "openai-tools":
        result = _tool_definitions("openai")
    elif args.command == "openai-rpc":
        return openai_jsonl(args.allow_mutations)
    else:
        asyncio.run(serve(args.host, args.port, args.token_file, args.allow_mutations))
        return 0
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, PermissionError, SecurityError, json.JSONDecodeError) as error:
        print(f"error: {_safe_error(error)}", file=sys.stderr)
        raise SystemExit(2)
