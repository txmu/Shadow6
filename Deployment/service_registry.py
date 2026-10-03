"""Persistent named service registry with explicit Core bindings."""
from __future__ import annotations
import json, re, os, platform, time, hashlib
from pathlib import Path
from typing import Any
try:
    from .core_catalog import CoreCatalog
except ImportError:
    from core_catalog import CoreCatalog

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

class ServiceRegistry:
    def __init__(self, path: str | Path | None = None, catalog: CoreCatalog | None = None):
        self.path = Path(path or os.environ.get("SHADOW6_SERVICE_REGISTRY", Path.home() / ".config/shadow6/services.json"))
        self.catalog = catalog or CoreCatalog()
        self.services: dict[str, dict[str, Any]] = {}
        if self.path.is_file():
            data = json.loads(self.path.read_text(encoding="utf-8")); self.services = data.get("services", {})

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"schema":"shadow6.service-registry.v1","services":self.services}, sort_keys=True, indent=2)+"\n", encoding="utf-8")
        os.chmod(self.path, 0o600)

    def init(self):
        self.path.parent.mkdir(parents=True, exist_ok=True); self._save()
        return {"schema":"shadow6.lifecycle.v1","stage":"init","platform":platform.system(),"architecture":platform.machine(),"statePath":str(self.path)}

    def create(self, name: str, *, core: str | None, config: dict[str, Any] | None, spec: dict[str, Any] | None = None, privacy: str = "native") -> dict[str, Any]:
        if not NAME.fullmatch(name): raise ValueError("service name must be namespace/name")
        if name in self.services: raise ValueError("service already exists")
        binding = None if core is None else self.catalog.binding(core, config or {})
        if privacy not in {"native", "envelope"}: raise ValueError("privacy must be native or envelope")
        item = {"name":name, "spec":spec or {}, "privacy":privacy, "coreBinding":binding, "state":"unresolved" if binding is None else "ready"}
        self.services[name] = item; self._save(); return item

    def configure(self, name: str, *, core: str, config: dict[str, Any]) -> dict[str, Any]:
        item = self.inspect(name); item["coreBinding"] = self.catalog.binding(core, config); item["state"] = "ready"; self._save(); return item
    def lock(self, name):
        item=self.inspect(name); binding=self.require_binding(name)
        material=json.dumps({"name":name,"spec":item.get("spec",{}),"binding":binding},sort_keys=True,separators=(",",":"))
        item["deploymentLock"]={"schema":"shadow6.deployment-lock.v2","digest":"sha256:"+hashlib.sha256(material.encode()).hexdigest(),"coreBinding":binding}; item["state"]="locked"; self._save(); return item["deploymentLock"]
    def apply(self, name):
        item=self.inspect(name)
        if not item.get("deploymentLock"): self.lock(name)
        item["state"]="applied"; self._save(); return item
    def run(self, name):
        item=self.inspect(name); binding=self.require_binding(name); lock=item.get("deploymentLock") or self.lock(name)
        runtime=item.get("runtime")
        if runtime and runtime.get("state")=="running" and runtime.get("core")==binding["core"] and runtime.get("lockDigest")==lock["digest"]: return item
        item["runtime"]={"state":"running","core":binding["core"],"coreVersion":binding.get("version"),"lockDigest":lock["digest"],"pid":None,"endpoint":item.get("spec",{}).get("endpoint",{"mode":"private"}),"privacy":item.get("privacy","native"),"readyAt":time.time(),"drift":False}; item["state"]="running"; self._save(); return item
    def status(self, name): return self.inspect(name)
    def stop(self, name):
        item=self.inspect(name)
        if item.get("runtime"): item["runtime"]["state"]="stopped"
        item["state"]="stopped"; self._save(); return item
    def restart(self, name):
        item=self.inspect(name); binding=self.require_binding(name); old=item.get("runtime",{}).get("core")
        if old and old != binding["core"]: raise ValueError("Core migration requires explicit reconfigure")
        self.stop(name); return self.run(name)
    def remove(self, name):
        self.stop(name) if self.inspect(name).get("runtime",{}).get("state")=="running" else None
        self.services.pop(name); self._save(); return {"removed":name}
    def list(self) -> list[dict[str, Any]]: return [self.services[k] for k in sorted(self.services)]
    def inspect(self, name: str) -> dict[str, Any]:
        if name not in self.services: raise ValueError("unknown named service")
        return self.services[name]
    def require_binding(self, name: str) -> dict[str, Any]:
        item = self.inspect(name); binding = item.get("coreBinding")
        if not isinstance(binding, dict) or not binding.get("core"): raise ValueError("service has unresolved Core binding")
        return binding
