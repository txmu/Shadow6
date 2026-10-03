"""Explicit Core catalog, descriptors, schemas, and candidate resolution.

The catalog is data driven: built-ins are descriptors, while third-party
implementations are admitted only after the same descriptor contract passes.
It never chooses a winner.
"""
from __future__ import annotations
import hashlib, json, os, platform, re
from pathlib import Path
from typing import Any

CORE_IDS = ("go", "rust", "gleam", "ada", "nim", "pony", "zig", "d", "cpp", "idris", "hare", "carp")
CATALOG_SCHEMA = "shadow6.core-catalog.v1"
DESCRIPTOR_SCHEMA = "shadow6.core-descriptor.v1"
CONFIG_SCHEMA = "shadow6.core-config.v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")

def _schema(core: str) -> dict[str, Any]:
    return {"schema": CONFIG_SCHEMA, "version": "1", "core": core, "fields": [
        {"id":"config_path", "type":"path", "required":True, "optional":False,
         "description":"Path to the Core-specific configuration file", "secret":False,
         "restartRequired":True, "roles":["broker","agent","client","gate"],
         "dependencies":[], "conflicts":[], "hasDefault":False}
    ]}

def _descriptor(core: str, root: Path | None = None) -> dict[str, Any]:
    root = root or Path(__file__).resolve().parents[1]
    path = root / f"Core-{core.title() if core != 'cpp' else 'Cpp'}" / f"shadow6-{core}"
    return {"schema": DESCRIPTOR_SCHEMA, "id": core, "displayName": f"Shadow6 {core.title()} Core",
            "implementation": {"name": core, "version": "unknown", "language": core},
            "executable": str(path), "binaryDigest": _digest(path), "publisher": "Shadow6",
            "source": "builtin", "trust": {"status":"builtin"}, "protocolFamily": "core-native",
            "applicationBoundaries": ["stream", "message", "credited"],
            "guarantees": {}, "limits": {}, "roles":["broker","agent","client","gate"],
            "platforms":[platform.system().lower()], "architectures":[platform.machine()],
            "featureReportDigest": None, "configurationSchema": _schema(core),
            "configurationSchemaVersion":"1"}

def _digest(path: Path) -> str | None:
    try:
        if path.is_file(): return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError: pass
    return None

def validate_descriptor(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != DESCRIPTOR_SCHEMA or not _ID.fullmatch(str(value.get("id", ""))):
        raise ValueError("invalid Core descriptor")
    if not isinstance(value.get("configurationSchema"), dict) or value["configurationSchema"].get("schema") != CONFIG_SCHEMA:
        raise ValueError("Core descriptor requires a configuration schema")
    if value["configurationSchema"].get("core") != value["id"]:
        raise ValueError("Core descriptor/schema identity mismatch")
    for key in ("displayName", "implementation", "protocolFamily", "applicationBoundaries", "roles"):
        if key not in value: raise ValueError(f"Core descriptor missing {key}")
    return value

def validate_config(descriptor: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    validate_descriptor(descriptor)
    if not isinstance(config, dict): raise ValueError("Core configuration must be an object")
    fields = descriptor["configurationSchema"]["fields"]
    known = {f["id"] for f in fields}
    if set(config) - known: raise ValueError("unknown Core configuration field")
    for field in fields:
        if field["required"] and field["id"] not in config: raise ValueError(f"missing Core configuration field: {field['id']}")
    return {k: config[k] for k in sorted(config)}

class CoreCatalog:
    def __init__(self, root: Path | None = None):
        self.root = root or Path(__file__).resolve().parents[1]
        self._items = {c: _descriptor(c, self.root) for c in CORE_IDS}

    def register(self, descriptor: dict[str, Any]) -> dict[str, Any]:
        item = validate_descriptor(descriptor)
        if item["source"] == "builtin" and item["id"] not in CORE_IDS: raise ValueError("unknown builtin Core")
        self._items[item["id"]] = json.loads(json.dumps(item))
        return self._items[item["id"]]

    def import_file(self, path: str | os.PathLike[str]) -> dict[str, Any]:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        value.setdefault("source", "imported")
        value.setdefault("trust", {"status":"unverified"})
        return self.register(value)

    def list(self) -> list[dict[str, Any]]: return [self._items[k] for k in sorted(self._items)]
    def inspect(self, core: str) -> dict[str, Any]:
        if core not in self._items: raise ValueError("unknown Core identity")
        return self._items[core]
    def resolve(self, requirements: dict[str, Any], core: str | None = None) -> dict[str, Any]:
        matches, rejected = [], []
        for item in self.list():
            if core and item["id"] != core: rejected.append({"core":item["id"],"reason":"not explicitly requested"}); continue
            missing = [k for k,v in requirements.items() if v not in item.get(k, []) and item.get(k) != v]
            (matches if not missing else rejected).append(item if not missing else {"core":item["id"],"reason":"requirements not met"})
        return {"schema":"shadow6.core-resolution.v1", "candidates":matches, "rejected":rejected,
                "bindingRequired":len(matches) != 1, "ambiguous":len(matches)>1}

    def binding(self, core: str, config: dict[str, Any], version: str | None = None) -> dict[str, Any]:
        descriptor = self.inspect(core); normalized = validate_config(descriptor, config)
        payload = {"core":core, "version":version or descriptor["implementation"]["version"],
                   "binaryDigest":descriptor.get("binaryDigest"), "featureReportDigest":descriptor.get("featureReportDigest"),
                   "configSchemaVersion":descriptor["configurationSchemaVersion"], "config":normalized}
        payload["configDigest"] = "sha256:" + hashlib.sha256(json.dumps(normalized,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        return payload

def default_catalog(root: Path | None = None) -> CoreCatalog: return CoreCatalog(root)
