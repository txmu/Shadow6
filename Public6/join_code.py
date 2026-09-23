#!/usr/bin/env python3
"""Portable 40-character Virtual Broker invitation codes and trusted profiles."""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

if __name__ == "__main__":
    _root = Path(__file__).resolve().parents[1]
    for _candidate in (_root / "Tools", _root / "share/shadow6/modules"):
        if (_candidate / "python_runtime.py").is_file():
            sys.path.insert(0, str(_candidate))
            from python_runtime import bootstrap
            bootstrap(_root, Path(__file__).absolute())
            break
    for _candidate in (_root / "Public6", _root / "share/shadow6/modules"):
        if (_candidate / "virtual_broker.py").is_file():
            sys.path.insert(0, str(_candidate))
            break

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MODES = {1: "directory", 2: "manual", 3: "ipv4-https"}
CODE_RE = re.compile(r"^[A-Za-z0-9_-]{40}$")
CORE_NAMES = frozenset(("go", "rust", "gleam", "ada", "nim", "pony", "zig", "d", "cpp", "idris", "hare", "carp"))
PROFILE_SCHEMA = "shadow6.public-node-profile.v1"


def issue(mode: str, host: str | None = None, port: int | None = None) -> str:
    if mode not in MODES.values():
        raise ValueError("unknown join-code mode")
    number = next(k for k, v in MODES.items() if v == mode)
    if mode == "ipv4-https":
        address = ipaddress.ip_address(host or "")
        if address.version != 4 or address.is_unspecified or address.is_multicast or address.is_loopback:
            raise ValueError("IPv4 HTTPS mode requires a reachable public IPv4 address")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid HTTPS port")
        raw = bytes([number]) + address.packed + port.to_bytes(2, "big") + os.urandom(23)
    else:
        if host is not None or port is not None:
            raise ValueError("host and port are only encoded in IPv4 HTTPS mode")
        raw = bytes([number]) + os.urandom(29)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode(code: str) -> dict:
    if type(code) is not str or not CODE_RE.fullmatch(code):
        raise ValueError("join code must contain exactly 40 base64url characters")
    raw = base64.urlsafe_b64decode(code)
    if len(raw) != 30 or raw[0] not in MODES or base64.urlsafe_b64encode(raw).decode().rstrip("=") != code:
        raise ValueError("invalid join-code version or encoding")
    result = {"mode": MODES[raw[0]], "lookup_id": hashlib.sha256(raw).hexdigest()}
    if raw[0] == 3:
        result["https_host"] = str(ipaddress.ip_address(raw[1:5]))
        result["https_port"] = int.from_bytes(raw[5:7], "big")
        if result["https_port"] == 0:
            raise ValueError("invalid HTTPS port")
    return result


def peer_seed(code: str, purpose: str) -> bytes:
    if purpose not in ("admission", "gate") and not re.fullmatch(r"core:(go|rust|gleam|ada|nim|pony|zig|d|cpp|idris|hare|carp):(client|agent)", purpose):
        raise ValueError("unknown key purpose")
    decode(code)
    return hashlib.sha256(b"shadow6.public-node.v1\x00" + purpose.encode() + b"\x00" +
                          base64.urlsafe_b64decode(code)).digest()


def peer_public(code: str, purpose: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(peer_seed(code, purpose))
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _private_file(path: Path, limit: int) -> bytes:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > limit:
        raise ValueError("profile must be an owner-only regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        data = os.read(descriptor, limit + 1)
        after = os.fstat(descriptor)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_uid, s.st_nlink, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(opened) or identity(opened) != identity(after) or len(data) > limit:
            raise ValueError("profile changed while reading")
        return data
    finally:
        os.close(descriptor)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate profile field")
        result[key] = value
    return result


def _reject_float(_):
    raise ValueError("floats are forbidden in profiles")


def validate_profile(data: bytes, code: str) -> dict:
    if not 1 <= len(data) <= 65536:
        raise ValueError("profile is empty or oversized")
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs,
                       parse_float=_reject_float, parse_constant=_reject_float)
    if type(value) is not dict or set(value) != {"schema", "lookup_id", "tenant", "admission_public_key", "routes"} or value["schema"] != PROFILE_SCHEMA or value["lookup_id"] != decode(code)["lookup_id"]:
        raise ValueError("profile does not match join code")
    if value["admission_public_key"] != peer_public(code, "admission"):
        raise ValueError("profile admission identity does not match code")
    if type(value["tenant"]) is not str or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value["tenant"]):
        raise ValueError("invalid tenant")
    routes = value["routes"]
    if type(routes) is not list or not 1 <= len(routes) <= 12:
        raise ValueError("invalid Core routes")
    seen = set()
    for route in routes:
        if type(route) is not dict or set(route) != {"core", "transport", "gate_host", "gate_port", "gate_public_key", "native_broker_public_key", "native_client_public_key", "native_agent_public_key", "default_agent_id", "default_agent_public_key"}:
            raise ValueError("unknown Core route field")
        core = route["core"]
        if type(core) is not str or core not in CORE_NAMES or core in seen:
            raise ValueError("invalid or duplicate Core route")
        seen.add(core)
        if type(route["transport"]) is not str or route["transport"] not in ("tcp", "udp"):
            raise ValueError("invalid Core carrier")
        if type(route["gate_host"]) is not str or ipaddress.ip_address(route["gate_host"]).is_unspecified or ipaddress.ip_address(route["gate_host"]).is_multicast:
            raise ValueError("invalid Gate address")
        if type(route["gate_public_key"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", route["gate_public_key"]):
            raise ValueError("invalid Gate public key")
        if type(route["native_broker_public_key"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", route["native_broker_public_key"]):
            raise ValueError("invalid native Broker public key")
        for role in ("client", "agent"):
            if route[f"native_{role}_public_key"] != peer_public(code, f"core:{core}:{role}"):
                raise ValueError("native Core identity does not match join code")
        if type(route["default_agent_id"]) is not str or type(route["default_agent_public_key"]) is not str or bool(route["default_agent_id"]) != bool(route["default_agent_public_key"]):
            raise ValueError("incomplete default Agent identity")
        if route["default_agent_id"] and (not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", route["default_agent_id"]) or not re.fullmatch(r"[0-9a-f]{64}", route["default_agent_public_key"])):
            raise ValueError("invalid default Agent identity")
        if type(route["gate_port"]) is not int or not 1024 <= route["gate_port"] <= 65534:
            raise ValueError("invalid fixed Gate port")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("profile redirect is forbidden")


def resolve(code: str, directory: str | None = None, manual_profile: Path | None = None,
            manual_pin: str | None = None) -> dict:
    metadata = decode(code)
    if metadata["mode"] == "manual":
        if directory is not None:
            raise ValueError("manual mode does not use a directory")
        if manual_profile is None:
            raise ValueError("manual mode requires an owner-only profile file")
        data = _private_file(manual_profile, 65536)
    else:
        if manual_profile is not None or manual_pin is not None:
            raise ValueError("unexpected manual profile or pin")
        if metadata["mode"] == "directory":
            if directory is None:
                raise ValueError("directory mode requires a trusted HTTPS directory")
            parsed = urllib.parse.urlsplit(directory)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError("directory must be a trusted HTTPS origin")
            origin = directory.rstrip("/")
        else:
            if directory is not None:
                raise ValueError("IPv4 code already contains its HTTPS origin")
            origin = f"https://{metadata['https_host']}:{metadata['https_port']}"
        url = origin + "/.well-known/shadow6/" + metadata["lookup_id"] + ".json"
        opener = urllib.request.build_opener(_NoRedirect())
        with opener.open(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=10) as response:
            if response.status != 200:
                raise ValueError("profile lookup failed")
            data = response.read(65537)
    profile = validate_profile(data, code)
    if metadata["mode"] == "manual":
        if type(manual_pin) is not str or not re.fullmatch(r"[0-9a-f]{64}", manual_pin) or len(profile["routes"]) != 1 or profile["routes"][0]["gate_public_key"] != manual_pin:
            raise ValueError("manual mode requires a separately verified full Gate public key")
    return profile


def _json_file(path: Path, limit: int) -> dict:
    value = json.loads(_private_file(path, limit).decode("utf-8"), object_pairs_hook=_pairs,
                       parse_float=_reject_float, parse_constant=_reject_float)
    if type(value) is not dict:
        raise ValueError("configuration must be an object")
    return value


def _server_public(config: dict) -> str:
    raw = config.get("private_key")
    if type(raw) is not str or not re.fullmatch(r"[0-9a-fA-F]{64}([0-9a-fA-F]{64})?", raw):
        raise ValueError("invalid Gate private key")
    material = bytes.fromhex(raw)
    key = Ed25519PrivateKey.from_private_bytes(material[:32])
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if len(material) == 64 and material[32:] != public:
        raise ValueError("inconsistent expanded Gate private key")
    return public.hex()


def _write_new(path: Path, data: bytes, mode=0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def provision(mode: str, tenant: str, broker_path: Path, gate_paths: list[str],
              output: Path, public_host: str, host: str | None = None, port: int | None = None,
              native_keys: list[str] | None = None, agents: list[str] | None = None) -> dict:
    """Produce reviewable config copies; activation remains an operator action."""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", tenant):
        raise ValueError("invalid tenant")
    if not gate_paths or len(gate_paths) > 12:
        raise ValueError("provide 1-12 distinct Core Gate configurations")
    address = ipaddress.ip_address(public_host)
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError("public Gate host must be reachable")
    if mode == "ipv4-https" and str(address) != host:
        raise ValueError("IPv4 HTTPS code and Gate host must agree")
    # Validate every input before creating any output file.
    from virtual_broker import load_config as load_broker
    loaded = load_broker(broker_path)
    if tenant not in loaded.tenants:
        raise ValueError("tenant is absent from Virtual Broker")
    broker = _json_file(broker_path, 262144)
    entry = next(item for item in broker["tenants"] if item["id"] == tenant)
    if len(entry["public_keys"]) >= 32:
        raise ValueError("Virtual Broker tenant key limit reached")
    gate_configs = {}
    routes = []
    key_map = {}
    for item in native_keys or []:
        core, separator, key = item.partition("=")
        if not separator or core not in CORE_NAMES or core in key_map or not re.fullmatch(r"[0-9a-f]{64}", key):
            raise ValueError("invalid or duplicate Core=native-Broker-key entry")
        key_map[core] = key
    agent_map = {}
    for item in agents or []:
        core, separator, identity = item.partition("=")
        agent_id, colon, public = identity.partition(":")
        if not separator or not colon or core not in CORE_NAMES or core in agent_map or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", agent_id) or not re.fullmatch(r"[0-9a-f]{64}", public):
            raise ValueError("invalid or duplicate Core=AgentID:AgentPub entry")
        agent_map[core] = (agent_id, public)
    for item in gate_paths:
        core, separator, filename = item.partition("=")
        if not separator or core not in CORE_NAMES or core in gate_configs:
            raise ValueError("invalid or duplicate Core=Gate-config entry")
        if (tenant, core) not in loaded.routes:
            raise ValueError("Virtual Broker lacks the matching tenant/Core route")
        if core not in key_map:
            raise ValueError("native Broker public key required for each Core")
        gate = _json_file(Path(filename), 1 << 20)
        if gate.get("version") != 1 or gate.get("role") != "server" or gate.get("enabled") is not True:
            raise ValueError("Gate server must be explicitly enabled")
        mtd = gate.get("mtd")
        if type(mtd) is not dict or mtd.get("enabled") is not False or type(mtd.get("min_port")) is not int or not 1024 <= mtd["min_port"] <= 65534:
            raise ValueError("public-node Gate must use a fixed, non-rotating port")
        if type(gate.get("peer_public_keys")) is not list or len(gate["peer_public_keys"]) >= 256:
            raise ValueError("Gate peer key limit reached")
        protocol = gate.get("protocol")
        if type(protocol) is not list:
            raise ValueError("invalid Gate protocol")
        carrier = "udp" if core in ("hare", "carp", "pony", "idris") else "tcp"
        if carrier not in protocol:
            raise ValueError("Gate does not enable the Core carrier")
        if carrier == "udp":
            if not any(port_number == int(gate["upstream"].rsplit(":", 1)[-1]) and route_tenant == tenant and route_core == core and not anonymous
                       for port_number, route_tenant, route_core, _, anonymous in loaded.datagram_listeners):
                raise ValueError("Gate UDP upstream must be a signed Virtual Broker datagram listener")
        elif gate.get("upstream") != f"{loaded.listen_host}:{loaded.listen_port}":
            raise ValueError("Gate TCP upstream must be the Virtual Broker listener")
        gate_configs[core] = gate
        routes.append({"core": core, "transport": carrier, "gate_host": str(address),
                       "gate_port": mtd["min_port"], "gate_public_key": _server_public(gate),
                       "native_broker_public_key": key_map[core],
                       "native_client_public_key": "",
                       "native_agent_public_key": "",
                       "default_agent_id": agent_map.get(core, ("", ""))[0],
                       "default_agent_public_key": agent_map.get(core, ("", ""))[1]})
    if set(key_map) != set(gate_configs) or set(agent_map) - set(gate_configs):
        raise ValueError("Core key or Agent catalog does not match Gate routes")
    code = issue(mode, host, port)
    admission = peer_public(code, "admission")
    gate_public = peer_public(code, "gate")
    entry["public_keys"].append(base64.b64encode(bytes.fromhex(admission)).decode())
    if entry["approval"] == "approval-required":
        for role in ("client", "agent"):
            broker["approvals"].append({"tenant": tenant, "client": "invite-" + profile_id(code) + "-" + role})
        if len(broker["approvals"]) > 4096:
            raise ValueError("Virtual Broker approval limit reached")
    for gate in gate_configs.values():
        gate["peer_public_keys"].append(gate_public)
    for route in routes:
        route["native_client_public_key"] = peer_public(code, f"core:{route['core']}:client")
        route["native_agent_public_key"] = peer_public(code, f"core:{route['core']}:agent")
    profile = {"schema": PROFILE_SCHEMA, "lookup_id": decode(code)["lookup_id"],
               "admission_public_key": admission,
               "tenant": tenant, "routes": sorted(routes, key=lambda route: route["core"])}
    validate_profile(json.dumps(profile).encode(), code)
    output.mkdir(mode=0o700)
    try:
        _write_new(output / "code.txt", (code + "\n").encode())
        authorizations = {"schema": "shadow6.public-node-native-keys.v1", "lookup_id": profile["lookup_id"],
                          "identities": [{"core": route["core"], "role": role,
                                          "id": "invite-" + profile_id(code) + "-" + role,
                                          "public_key": route[f"native_{role}_public_key"]}
                                         for route in routes for role in ("client", "agent")]}
        _write_new(output / "native-authorizations.json", (json.dumps(authorizations, sort_keys=True, separators=(",", ":")) + "\n").encode())
        _write_new(output / "virtual-broker.json", (json.dumps(broker, sort_keys=True, separators=(",", ":")) + "\n").encode())
        for core, gate in gate_configs.items():
            _write_new(output / f"gate-{core}.json", (json.dumps(gate, sort_keys=True, separators=(",", ":")) + "\n").encode())
        _write_new(output / f"{profile['lookup_id']}.json", (json.dumps(profile, sort_keys=True, separators=(",", ":")) + "\n").encode())
    except BaseException:
        for generated in output.iterdir():
            generated.unlink()
        output.rmdir()
        raise
    return {"output": str(output), "lookup_id": profile["lookup_id"], "cores": sorted(gate_configs),
            "code_file": str(output / "code.txt"), "profile_file": str(output / f"{profile['lookup_id']}.json")}


def profile_id(code: str) -> str:
    return decode(code)["lookup_id"][:16]


def install_peer(code: str, profile: dict, core: str, role: str, output: Path,
                 gate_port: int = 1086, peer_port: int = 1087) -> dict:
    validate_profile(json.dumps(profile, sort_keys=True, separators=(",", ":")).encode(), code)
    if role not in ("client", "agent"):
        raise ValueError("invalid Virtual Peer role")
    route = next((item for item in profile["routes"] if item["core"] == core), None)
    if route is None:
        raise ValueError("Core family is not offered by this node")
    if type(gate_port) is not int or type(peer_port) is not int or not 1024 <= gate_port <= 65535 or not 1024 <= peer_port <= 65535 or gate_port == peer_port:
        raise ValueError("invalid local port assignment")
    gate = {"version": 1, "enabled": True, "role": "client", "listen_host": "127.0.0.1",
            "listen_port": gate_port, "upstream": "127.0.0.1:4433", "upstreams": [],
            "remote_host": route["gate_host"], "remote_hosts": [], "load_balance": "round_robin",
            "private_key": peer_seed(code, "gate").hex(), "peer_public_keys": [route["gate_public_key"]],
            "protocol": [route["transport"]], "open_mode": "unconditional", "allowed_cidrs": [],
            "windows": [], "mtd": {"enabled": False, "period_seconds": 300,
                                    "min_port": route["gate_port"], "max_port": route["gate_port"] + 1,
                                    "grace_seconds": 15},
            "limits": {"max_connections": 64, "max_frame_bytes": 65507, "idle_seconds": 120}}
    peer = {"schema": "shadow6.virtual-peer.v1", "role": role, "core": core,
            "tenant": profile["tenant"], "identity": "invite-" + profile_id(code) + "-" + role,
            "private_key_file": str((output / "admission.seed").absolute()),
            "transport": route["transport"], "listen": {"host": "127.0.0.1", "port": peer_port},
            "gate": {"host": "127.0.0.1", "port": gate_port},
            "max_connections": 32, "idle_seconds": 120}
    output.mkdir(mode=0o700)
    try:
        _write_new(output / "admission.seed", peer_seed(code, "admission"))
        _write_new(output / "core.seed", peer_seed(code, f"core:{core}:{role}"))
        _write_new(output / "gate.json", (json.dumps(gate, sort_keys=True, separators=(",", ":")) + "\n").encode())
        _write_new(output / "virtual-peer.json", (json.dumps(peer, sort_keys=True, separators=(",", ":")) + "\n").encode())
    except BaseException:
        for generated in output.iterdir():
            generated.unlink()
        output.rmdir()
        raise
    return {"output": str(output), "core": core, "role": role,
            "gate_config": str(output / "gate.json"), "peer_config": str(output / "virtual-peer.json")}


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    issue_args = sub.add_parser("issue")
    issue_args.add_argument("--mode", choices=tuple(MODES.values()), required=True)
    issue_args.add_argument("--host")
    issue_args.add_argument("--port", type=int)
    inspect = sub.add_parser("inspect")
    inspect.add_argument("code")
    lookup = sub.add_parser("resolve")
    lookup.add_argument("code")
    lookup.add_argument("--directory")
    lookup.add_argument("--profile", type=Path)
    lookup.add_argument("--pin")
    setup = sub.add_parser("provision")
    setup.add_argument("--mode", choices=tuple(MODES.values()), required=True)
    setup.add_argument("--tenant", required=True)
    setup.add_argument("--broker-config", type=Path, required=True)
    setup.add_argument("--gate", action="append", required=True, metavar="CORE=FILE")
    setup.add_argument("--native-key", action="append", required=True, metavar="CORE=HEX")
    setup.add_argument("--agent", action="append", metavar="CORE=ID:HEX")
    setup.add_argument("--output-dir", type=Path, required=True)
    setup.add_argument("--public-host", required=True)
    setup.add_argument("--host")
    setup.add_argument("--port", type=int)
    install = sub.add_parser("install")
    install.add_argument("code")
    install.add_argument("--core", choices=sorted(CORE_NAMES), required=True)
    install.add_argument("--role", choices=("client", "agent"), required=True)
    install.add_argument("--directory")
    install.add_argument("--profile", type=Path)
    install.add_argument("--pin")
    install.add_argument("--output-dir", type=Path, required=True)
    install.add_argument("--gate-port", type=int, default=1086)
    install.add_argument("--peer-port", type=int, default=1087)
    args = parser.parse_args()
    try:
        if args.command == "issue":
            code = issue(args.mode, args.host, args.port)
            print(json.dumps({"code": code, "lookup_id": decode(code)["lookup_id"],
                              "gate_client_public_key": peer_public(code, "gate"),
                              "admission_public_key": peer_public(code, "admission")}, sort_keys=True))
        elif args.command == "inspect":
            print(json.dumps(decode(args.code), sort_keys=True))
        elif args.command == "resolve":
            print(json.dumps(resolve(args.code, args.directory, args.profile, args.pin), sort_keys=True))
        elif args.command == "provision":
            print(json.dumps(provision(args.mode, args.tenant, args.broker_config, args.gate,
                                       args.output_dir, args.public_host, args.host, args.port,
                                       args.native_key, args.agent), sort_keys=True))
        else:
            profile = resolve(args.code, args.directory, args.profile, args.pin)
            print(json.dumps(install_peer(args.code, profile, args.core, args.role,
                                          args.output_dir, args.gate_port, args.peer_port), sort_keys=True))
        return 0
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError, urllib.error.URLError) as exc:
        print(f"join code: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
