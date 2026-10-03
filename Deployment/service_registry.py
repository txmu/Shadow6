"""Persistent named service registry with explicit Core bindings."""
from __future__ import annotations
import json, re
from pathlib import Path
from typing import Any
try:
    from .core_catalog import CoreCatalog
except ImportError:
    from core_catalog import CoreCatalog

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

class ServiceRegistry:
    def __init__(self, path: str | Path | None = None, catalog: CoreCatalog | None = None):
        self.path = Path(path or Path.home() / ".config/shadow6/services.json")
        self.catalog = catalog or CoreCatalog()
        self.services: dict[str, dict[str, Any]] = {}
        if self.path.is_file():
            data = json.loads(self.path.read_text(encoding="utf-8")); self.services = data.get("services", {})

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"schema":"shadow6.service-registry.v1","services":self.services}, sort_keys=True, indent=2)+"\n", encoding="utf-8")

    def create(self, name: str, *, core: str | None, config: dict[str, Any] | None, spec: dict[str, Any] | None = None) -> dict[str, Any]:
        if not NAME.fullmatch(name): raise ValueError("service name must be namespace/name")
        if name in self.services: raise ValueError("service already exists")
        binding = None if core is None else self.catalog.binding(core, config or {})
        item = {"name":name, "spec":spec or {}, "coreBinding":binding, "state":"unresolved" if binding is None else "ready"}
        self.services[name] = item; self._save(); return item

    def configure(self, name: str, *, core: str, config: dict[str, Any]) -> dict[str, Any]:
        item = self.inspect(name); item["coreBinding"] = self.catalog.binding(core, config); item["state"] = "ready"; self._save(); return item
    def list(self) -> list[dict[str, Any]]: return [self.services[k] for k in sorted(self.services)]
    def inspect(self, name: str) -> dict[str, Any]:
        if name not in self.services: raise ValueError("unknown named service")
        return self.services[name]
    def require_binding(self, name: str) -> dict[str, Any]:
        item = self.inspect(name); binding = item.get("coreBinding")
        if not isinstance(binding, dict) or not binding.get("core"): raise ValueError("service has unresolved Core binding")
        return binding
