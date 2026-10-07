"""Explicit Core catalog, descriptors, schemas, and candidate resolution.

The catalog is data driven: built-ins are descriptors, while third-party
implementations are admitted only after the same descriptor contract passes.
It never chooses a winner.
"""
from __future__ import annotations
import hashlib, json, os, platform, re, sys
try:
    from .service_storage import private_read, strict_json, atomic_write
except ImportError:
    from service_storage import private_read, strict_json, atomic_write
from pathlib import Path
from typing import Any

try:
    from .profile_registry import CORE_IDS, application_boundaries, select_profile
except ImportError:
    from profile_registry import CORE_IDS, application_boundaries, select_profile
CATALOG_SCHEMA = "shadow6.core-catalog.v1"
DESCRIPTOR_SCHEMA = "shadow6.core-descriptor.v1"
CONFIG_SCHEMA = "shadow6.core-config.v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")

def _schema(core: str) -> dict[str, Any]:
    return {"schema": CONFIG_SCHEMA, "version": "1", "core": core, "fields": [
        {"id":"config_path", "type":"path", "required":True, "optional":False,
         "description":"Path to the Core-specific configuration file", "secret":False,
         "restartRequired":True, "roles":["broker","agent","client"],
         "dependencies":[], "conflicts":[], "hasDefault":False}
    ]}

def _descriptor(core: str, root: Path | None = None) -> dict[str, Any]:
    root = root or Path(__file__).resolve().parents[1]
    profile = select_profile(core)
    path = root / profile['artifact']
    boundaries = list(dict.fromkeys(b['kind'] for b in application_boundaries(core)))
    return {"schema": DESCRIPTOR_SCHEMA, "id": core, "displayName": f"Shadow6 {core.title()} Core",
            "implementation": {"name": core, "version": "unknown", "language": core},
            "executable": str(path), "binaryDigest": None, "publisher": "Shadow6",
            "source": "builtin", "trust": {"status":"builtin"}, "protocolFamily": "core-native",
            "applicationBoundaries": boundaries,
            "guarantees": {}, "limits": {}, "roles":["broker","agent","client"],
            "platforms":[platform.system().lower()], "architectures":[platform.machine()],
            "featureReportDigest": None, "configurationSchema": _schema(core),
            "configurationSchemaVersion":"1", "launchAdapter":profile["realization"]["launcher"], "privacyEnvelope": {"available": (root / "OCaml/privacy_envelope/shadow6-privacy-envelope").is_file(), "implementation":"ocaml", "mode":"authenticated-envelope", "nativeProtocolUnchanged":True, "preauthIdentityDisclosure":False, "publicCoreListenerRequired":False}}

def _digest(path: Path) -> str | None:
    try:
        if path.is_file():
            if path.stat().st_size > 536870912: return None
            value = hashlib.sha256()
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(65536), b""): value.update(chunk)
            return "sha256:" + value.hexdigest()
    except OSError: pass
    return None

def validate_descriptor(value: dict[str, Any]) -> dict[str, Any]:
    strict_json(json.dumps(value,allow_nan=False).encode())
    if not isinstance(value, dict) or value.get("schema") != DESCRIPTOR_SCHEMA or not _ID.fullmatch(str(value.get("id", ""))):
        raise ValueError("invalid Core descriptor")
    if not isinstance(value.get("configurationSchema"), dict) or value["configurationSchema"].get("schema") != CONFIG_SCHEMA:
        raise ValueError("Core descriptor requires a configuration schema")
    if value["configurationSchema"].get("core") != value["id"]:
        raise ValueError("Core descriptor/schema identity mismatch")
    allowed = {'schema','id','displayName','implementation','executable','binaryDigest','publisher','source','trust','protocolFamily','applicationBoundaries','guarantees','limits','roles','platforms','architectures','featureReportDigest','configurationSchema','configurationSchemaVersion','privacyEnvelope','launchAdapter'}
    if set(value) - allowed: raise ValueError('unknown Core descriptor field')
    if not isinstance(value.get('applicationBoundaries'),list) or not value['applicationBoundaries'] or any(b not in {'stream','message','credited'} for b in value['applicationBoundaries']): raise ValueError('invalid application boundaries')
    if not isinstance(value.get('roles'),list) or not value['roles'] or any(r not in {'broker','agent','client','gate'} for r in value['roles']): raise ValueError('invalid descriptor roles')
    if value.get('launchAdapter','native-config') not in {'native-config','native-files'}: raise ValueError('unsupported launch adapter')
    if not isinstance(value.get('executable'),str) or not Path(value['executable']).is_absolute(): raise ValueError('absolute Core executable required')
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
    path = config.get("config_path")
    if not isinstance(path, str) or not path or len(path.encode()) > 4096 or "\0" in path:
        raise ValueError("config_path requires a bounded nonempty path")
    return {"config_path": str(Path(path).expanduser().absolute())}

class CoreCatalog:
    def __init__(self, root: Path | None = None, *, descriptor_path: Path | None = None):
        if root is None:
            try:
                from install_layout import tree_root
                root = tree_root(__file__)
            except ImportError:
                here = Path(__file__).resolve()
                root = next((ancestor / 'share/shadow6/tree' for ancestor in here.parents
                             if (ancestor / 'share/shadow6/tree/Makefile').is_file()), here.parents[1])
        self.root = Path(root)
        self._items = {c: _descriptor(c, self.root) for c in CORE_IDS}
        self.descriptor_path = Path(descriptor_path) if descriptor_path is not None else Path(os.environ.get('SHADOW6_CORE_DESCRIPTORS',Path.home()/'.config/shadow6/cores.json'))
        self._load_imported()

    def _load_imported(self):
        try: items = strict_json(private_read(self.descriptor_path))
        except FileNotFoundError: return
        if not isinstance(items,dict) or len(items)>128: raise ValueError('invalid imported Core catalog')
        for identity,item in items.items():
            if identity in CORE_IDS or item.get('id') != identity or item.get('source') != 'imported': raise ValueError('imported descriptors cannot replace built-in Core identities')
            self.register(item)

    def component_binary(self, component):
        if component not in ("gate", "guard"): raise ValueError("unknown peripheral component")
        return self.root / component.title() / ("shadow6-" + component)

    def envelope_binary(self):
        return self.root / "OCaml/privacy_envelope/shadow6-privacy-envelope"

    def register(self, descriptor: dict[str, Any]) -> dict[str, Any]:
        item = validate_descriptor(descriptor)
        if item["source"] == "builtin" and item["id"] not in CORE_IDS: raise ValueError("unknown builtin Core")
        self._items[item["id"]] = json.loads(json.dumps(item))
        return self._items[item["id"]]

    def import_file(self, path: str | os.PathLike[str]) -> dict[str, Any]:
        raw = Path(path).read_bytes()
        if len(raw)>262144: raise ValueError("descriptor size limit")
        value = strict_json(raw)
        value.setdefault("source", "imported")
        value.setdefault("trust", {"status":"unverified"})
        if value.get('id') in CORE_IDS or value.get('source') != 'imported': raise ValueError('cannot import over a builtin Core')
        item=self.register(value)
        atomic_write(self.descriptor_path,json.dumps({k:v for k,v in self._items.items() if k not in CORE_IDS},sort_keys=True,allow_nan=False).encode())
        return item

    def list(self) -> list[dict[str, Any]]: return [self._items[k] for k in sorted(self._items)]
    def inspect(self, core: str) -> dict[str, Any]:
        if core not in self._items: raise ValueError("unknown Core identity")
        return self._items[core]
    def resolve(self, requirements: dict[str, Any], core: str | None = None) -> dict[str, Any]:
        matches, rejected = [], []
        for item in self.list():
            if core and item["id"] != core: rejected.append({"core":item["id"],"reason":"not explicitly requested"}); continue
            def meets(key, wanted):
                actual=item.get(key)
                if isinstance(actual,list):
                    return all(v in actual for v in (wanted if isinstance(wanted,list) else [wanted]))
                return actual == wanted
            missing = [k for k,v in requirements.items() if not meets(k,v)]
            (matches if not missing else rejected).append(item if not missing else {"core":item["id"],"reason":"requirements not met"})
        return {"schema":"shadow6.core-resolution.v1", "candidates":matches, "rejected":rejected,
                "bindingRequired":not bool(core), "ambiguous":len(matches)>1}

    def binding(self, core: str, config: dict[str, Any], version: str | None = None) -> dict[str, Any]:
        if core is None or core == '': raise ValueError('CoreSelectionRequired')
        descriptor = self.inspect(core); normalized = validate_config(descriptor, config)
        payload = {"core":core, "version":version or descriptor["implementation"]["version"],
                   "binaryDigest":_digest(Path(descriptor["executable"])), "featureReportDigest":descriptor.get("featureReportDigest"),
                   "configSchemaVersion":descriptor["configurationSchemaVersion"], "config":normalized,
                   "descriptorDigest":"sha256:"+hashlib.sha256(json.dumps(descriptor,sort_keys=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()}
        payload["configDigest"] = "sha256:" + hashlib.sha256(json.dumps(normalized,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        return payload

def default_catalog(root: Path | None = None) -> CoreCatalog: return CoreCatalog(root)
