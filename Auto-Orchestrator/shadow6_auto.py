#!/usr/bin/env python3
"""
Shadow6-Auto Orchestrator
Description: Agentless Moving Target Defense (MTD) Orchestrator for Shadow6.
Provides Zero-Touch Provisioning, Cryptographic SPA Coordination, SNI Rotation, 
Plugin RPC with strict ACLs, and Multi-Init-System deployment.
"""

import os
import sys
import json
import secrets
import time
import hmac
import re
import shlex
import stat
import struct
import socket
import asyncio
import hashlib
import subprocess
import tempfile
import ipaddress
import urllib.request
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.error import URLError

# External Dependencies (Requires: pip install typer rich textual asyncssh pyyaml cryptography aiohttp)
try:
    import yaml
    import typer
    import asyncssh
    from aiohttp import web
    from rich.console import Console
    from rich.table import Table
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, Log, Static
    from textual.containers import Grid
except ImportError as e:
    print(f"Missing dependency: {e}. Please run: pip install typer rich textual asyncssh pyyaml cryptography aiohttp")
    sys.exit(1)

console = Console()
app_cli = typer.Typer(help="Shadow6 Orchestrator CLI")

# ------------------------------------------------------------------------------
# Security & Crypto Core
# ------------------------------------------------------------------------------

MODULE_DIR = Path(__file__).resolve().parent
SOURCE_ROOT = MODULE_DIR.parent
if (SOURCE_ROOT / "Makefile").is_file():
    PROJECT_ROOT = SOURCE_ROOT
    BINARY_DIR = None
    SERVICE_INIT_DIR = PROJECT_ROOT / "Service-Init"
elif MODULE_DIR.name == "bin":
    PROJECT_ROOT = MODULE_DIR.parent / "share" / "shadow6" / "tree"
    BINARY_DIR = MODULE_DIR
    SERVICE_INIT_DIR = MODULE_DIR.parent / "share" / "shadow6" / "modules"
else:
    # Installed Control Center imports this copy from share/shadow6/modules.
    install_prefix = MODULE_DIR.parents[2]
    PROJECT_ROOT = install_prefix / "share" / "shadow6" / "tree"
    BINARY_DIR = install_prefix / "bin"
    SERVICE_INIT_DIR = MODULE_DIR
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
VALID_ROLES = {"broker", "agent", "client"}
CORE_ENGINES = {"shadow6-go", "shadow6-rust", "shadow6-zig", "shadow6-ada", "shadow6-d", "shadow6-nim", "shadow6-cpp"}
CORE_TRANSPORTS = {"shadow6-go": "kcp", "shadow6-rust": "quic", "shadow6-zig": "enet", "shadow6-ada": "cell-relay", "shadow6-d": "rle-udp", "shadow6-nim": "webrtc", "shadow6-cpp": "sctp"}
OPTIONAL_COMPONENTS = {"shadow6-guard", "c11relay"}
ENGINE_BINARIES = {
    "shadow6-nim": (BINARY_DIR / "shadow6-nim" if BINARY_DIR else PROJECT_ROOT / "Core-Nim" / "shadow6-nim"),
    "shadow6-go": (BINARY_DIR / "shadow6-go" if BINARY_DIR else PROJECT_ROOT / "Core-Go" / "shadow6-go"),
    "shadow6-rust": (BINARY_DIR / "shadow6-rust" if BINARY_DIR else PROJECT_ROOT / "Core-Rust" / "shadow6-rust"),
    "shadow6-d": (BINARY_DIR / "shadow6-d" if BINARY_DIR else PROJECT_ROOT / "Core-D" / "shadow6-d"),
    "shadow6-zig": (BINARY_DIR / "shadow6-zig" if BINARY_DIR else PROJECT_ROOT / "Core-Zig" / "shadow6-zig"),
    "shadow6-ada": (BINARY_DIR / "shadow6-ada" if BINARY_DIR else PROJECT_ROOT / "Core-Ada" / "shadow6-ada"),
    "shadow6-cpp": (BINARY_DIR / "shadow6-cpp" if BINARY_DIR else PROJECT_ROOT / "Core-Cpp" / "shadow6-cpp"),
    "shadow6-guard": (BINARY_DIR / "shadow6-guard" if BINARY_DIR else PROJECT_ROOT / "Guard" / "shadow6-guard"),
    "c11relay": (BINARY_DIR / "shadow6-relay" if BINARY_DIR else PROJECT_ROOT / "C11Relay" / "bridge_relay"),
}
sys.path.insert(0, str(SERVICE_INIT_DIR))
from shadow6_init import INIT_ALIASES, INIT_SYSTEMS, generate_init_script, normalize_init_system, rc_variable  # noqa: E402

MAX_TOPOLOGY_BYTES = 1024 * 1024
MAX_NODES = 256


def strict_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


class TopologyLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("topology mapping keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def parse_topology(document: str) -> dict:
    # Reject aliases before construction: even a small YAML file can encode
    # cyclic or exponentially shared objects. Bound parser nesting as well.
    depth = 0
    try:
        for count, event in enumerate(yaml.parse(document)):
            if count > 50_000 or isinstance(event, yaml.AliasEvent):
                raise ValueError("topology aliases or excessive structure are not supported")
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
                if depth > 32:
                    raise ValueError("topology nesting exceeds 32")
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
        return validate_topology(yaml.load(document, Loader=TopologyLoader))
    except yaml.YAMLError as exc:
        raise ValueError("invalid topology YAML") from exc


def secure_file(filepath: str):
    """Enforce 0600 on an owner-controlled regular file without following links."""
    path = Path(filepath)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("sensitive path must be a regular, non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("sensitive file changed while it was being opened")
        if opened.st_uid != os.geteuid():
            raise PermissionError("sensitive file must be owned by the effective user")
        if opened.st_nlink != 1 or opened.st_size > MAX_TOPOLOGY_BYTES:
            raise ValueError("sensitive file must be singly linked and bounded")
        os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
    finally:
        os.close(descriptor)

def generate_ed25519_keypair() -> tuple[str, str]:
    """Generates Ed25519 keys returning (public_hex, private_hex)."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return pub_bytes.hex(), priv_bytes.hex()

def generate_spa_packet(secret: str, public_ip: str) -> bytes:
    """Generates cryptographic knock packet binding the source IP."""
    if len(secret.encode("utf-8")) < 32:
        raise ValueError("SPA secret must contain at least 32 bytes")
    public_ip = str(ipaddress.ip_address(public_ip))
    ts = int(time.time())
    ts_bytes = struct.pack(">Q", ts)
    mac = hmac.new(secret.encode(), digestmod=hashlib.sha256)
    mac.update(ts_bytes)
    mac.update(public_ip.encode())
    return ts_bytes + mac.digest()

def get_public_ip() -> str:
    """Fetches public IP for SPA binding via external STUN/HTTP."""
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            return str(ipaddress.ip_address(response.read(65).decode('utf-8').strip()))
    except (URLError, UnicodeError, ValueError) as exc:
        raise RuntimeError("cannot determine the public SPA source IP; pass --source-ip explicitly") from exc

# ------------------------------------------------------------------------------
# Plugin RPC & Strict ACL Engine
# ------------------------------------------------------------------------------

class PluginACL:
    """Strict ACL for Plugin RPC restricting access to IPs and Domains."""
    def __init__(self, allowed_ips: List[str], allowed_domains: List[str]):
        self.allowed_networks = tuple(ipaddress.ip_network(item, strict=False) for item in allowed_ips)
        domains = []
        for item in allowed_domains:
            normalized = item.lower().rstrip(".")
            if normalized.startswith("ipfs://"):
                if not re.fullmatch(r"ipfs://[a-z0-9._~-]{1,200}", normalized):
                    raise ValueError(f"invalid IPFS ACL target: {item!r}")
            elif len(normalized) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", normalized):
                raise ValueError(f"invalid ACL domain: {item!r}")
            domains.append(normalized)
        self.allowed_domains = tuple(domains)

    def is_allowed(self, target: str) -> bool:
        normalized = target.lower().rstrip(".")
        if normalized.startswith("ipfs://"):
            return normalized in self.allowed_domains

        # Check IP (v4, v6, E-Class)
        try:
            ip_obj = ipaddress.ip_address(normalized)
            # Identify E-Class (240.0.0.0/4)
            if ip_obj.version == 4 and ipaddress.ip_network('240.0.0.0/4').overlaps(ipaddress.ip_network(f"{ip_obj}/32")):
                console.print(f"[yellow]Notice: Routing Experimental E-Class IPv4: {target}[/yellow]")
            
            return any(ip_obj.version == network.version and ip_obj in network for network in self.allowed_networks)
        except ValueError:
            return any(normalized == domain or normalized.endswith(f".{domain}") for domain in self.allowed_domains)

class RPCServer:
    """Asyncio HTTP Server for Python/Node.js Plugins."""
    def __init__(self, host: str, port: int, acl: PluginACL, token: str):
        if not isinstance(token, str) or not token.isascii() or not 32 <= len(token) <= 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise ValueError("RPC bearer token must contain 32..4096 printable ASCII characters")
        if not is_loopback_host(host) or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("RPC requires a loopback host and valid port")
        self.host = host
        self.port = port
        self.acl = acl
        self.token = token
        self.app = web.Application(client_max_size=16_384)
        self.app.router.add_post('/rpc', self.handle_rpc)

    async def handle_rpc(self, request: web.Request) -> web.Response:
        supplied = request.headers.get("Authorization", "")
        expected = f"Bearer {self.token}"
        if not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
            return web.json_response({"error": "Unauthorized"}, status=401)
        if request.content_length is not None and request.content_length > 16_384:
            return web.json_response({"error": "Request too large"}, status=413)
        try:
            data = await asyncio.wait_for(request.json(loads=lambda value: json.loads(value, object_pairs_hook=strict_json_pairs)), timeout=5)
        except (ValueError, RecursionError, asyncio.TimeoutError):
            return web.json_response({"error": "Invalid JSON"}, status=400)
        if not isinstance(data, dict) or set(data) != {"target"}:
            return web.json_response({"error": "Invalid RPC schema"}, status=400)
        target = data.get("target", "")
        if not isinstance(target, str) or len(target) > 255:
            return web.json_response({"error": "Invalid target"}, status=400)
        if not self.acl.is_allowed(target):
            return web.json_response({"error": "ACL Denied"}, status=403)
        return web.json_response({"status": "Authorized", "target": target})

    async def start(self):
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()

# ------------------------------------------------------------------------------
# Deployment & Multi-Init-System Generators
# ------------------------------------------------------------------------------

async def deploy_to_node(node: Dict, config_json: str):
    """Cap the complete SSH/SFTP deployment, including command output waits."""
    await asyncio.wait_for(_deploy_to_node(node, config_json), timeout=120)


async def _deploy_to_node(node: Dict, config_json: str):
    """Agentless deployment via AsyncSSH."""
    try:
        deploy_root = str(node.get("deploy_root", "")).rstrip("/")

        def remote_path(path: str) -> str:
            return f"{deploy_root}{path}" if deploy_root else path

        connect_args = {
            "username": node["ssh_user"],
            "password": node.get("ssh_pass"),
            "port": int(node.get("ssh_port", 22)),
        }
        connect_args["known_hosts"] = str(Path(node["known_hosts"]).expanduser())
        async with asyncssh.connect(node["ssh_host"], **connect_args) as conn:
            # Upload config
            sftp = await conn.start_sftp()
            config_dir = remote_path("/etc/shadow6")
            await conn.run(f"install -d -m 700 {shlex.quote(config_dir)}", check=True)
            conf_path = remote_path(f"/etc/shadow6/{node['name']}.json")
            temporary_config = remote_path(f"/etc/shadow6/.{node['name']}.{secrets.token_hex(8)}.json")
            owner_flags = "" if deploy_root else "-o root -g root "
            try:
                async with sftp.open(temporary_config, 'x', attrs=asyncssh.SFTPAttrs(permissions=0o600)) as f:
                    await f.write(config_json)
                await conn.run(
                    f"install {owner_flags}-m 0600 {shlex.quote(temporary_config)} {shlex.quote(conf_path)}",
                    check=True,
                )
            finally:
                await conn.run(f"rm -f {shlex.quote(temporary_config)}", check=False)

            remote_binaries = {}
            for engine in node.get("engines", []):
                local_binary = ENGINE_BINARIES.get(engine)
                if local_binary is None:
                    continue
                if not local_binary.is_file():
                    raise FileNotFoundError(f"binary for {engine} is missing: {local_binary}")
                remote_binary = remote_path(f"/usr/local/bin/{engine}")
                remote_binaries[engine] = remote_binary
                temporary_binary = remote_path(
                    f"/etc/shadow6/.{engine}.{node['name']}.{secrets.token_hex(8)}.upload"
                )
                await conn.run(
                    f"install -d -m 0755 {shlex.quote(str(Path(remote_binary).parent))}",
                    check=True,
                )
                await sftp.put(str(local_binary), temporary_binary)
                await conn.run(
                    f"install {owner_flags}-m 0755 {shlex.quote(temporary_binary)} {shlex.quote(remote_binary)} && rm -f {shlex.quote(temporary_binary)}",
                    check=True,
                )

            core_engine = selected_core_engine(node)
            core_binary = remote_binaries[core_engine]
            await conn.run(
                f"{shlex.quote(core_binary)} --config {shlex.quote(conf_path)} --check-config",
                check=True,
            )

            init_sys = node.get("init_system", "auto")
            if init_sys == "none":
                return
            if init_sys == "auto":
                res = await conn.run("if [ -x /sbin/procd ]; then echo procd; elif [ \"$(uname -s)\" = Darwin ]; then echo launchd; elif [ \"$(uname -s)\" = FreeBSD ]; then echo rc.d; elif command -v systemctl >/dev/null 2>&1; then echo systemd; elif command -v rc-service >/dev/null 2>&1; then echo openrc; elif command -v herd >/dev/null 2>&1 && [ -d /gnu/store ]; then echo guix; else echo sysv; fi", check=True)
                init_sys = res.stdout.strip().split()[-1] if res.stdout else "sysv"
            init_sys = normalize_init_system(init_sys)
            s_n = f"shadow6-{node['name']}"
            s_c = generate_init_script(init_sys, s_n, core_binary, conf_path)
            service_paths = {
                "systemd": f"/etc/systemd/system/{s_n}.service",
                "openrc": f"/etc/init.d/{s_n}", "sysv": f"/etc/init.d/{s_n}",
                "procd": f"/etc/init.d/{s_n}", "rc.d": f"/usr/local/etc/rc.d/{s_n}",
                "launchd": f"/Library/LaunchDaemons/org.shadow6.{s_n}.plist",
                "runit": f"/etc/sv/{s_n}/run",
                "guix": f"/etc/shadow6/{s_n}-service.scm",
            }
            unit_path = remote_path(service_paths[init_sys])
            await conn.run(
                f"install -d -m 0755 {shlex.quote(str(Path(unit_path).parent))}", check=True,
            )
            temporary_unit = remote_path(f"/etc/shadow6/.{s_n}.{secrets.token_hex(8)}.service")
            async with sftp.open(temporary_unit, "w") as f:
                await f.write(s_c)
            mode = "0755" if init_sys in {"openrc", "sysv", "procd", "rc.d", "runit"} else "0644"
            await conn.run(
                f"install {owner_flags}-m {mode} {shlex.quote(temporary_unit)} {shlex.quote(unit_path)} && rm -f {shlex.quote(temporary_unit)}",
                check=True,
            )
            if init_sys == "systemd":
                await conn.run("systemctl daemon-reload", check=True)
            
            # Restart service
            if init_sys == "systemd":
                await conn.run(f"systemctl enable --now {shlex.quote(s_n)}", check=True)
            elif init_sys == "openrc":
                await conn.run(f"rc-update add {shlex.quote(s_n)} default", check=True)
                await conn.run(f"rc-service {shlex.quote(s_n)} restart", check=True)
            elif init_sys in {"sysv", "procd"}:
                if init_sys == "sysv":
                    await conn.run(f"update-rc.d {shlex.quote(s_n)} defaults", check=True)
                else:
                    await conn.run(f"/etc/init.d/{shlex.quote(s_n)} enable", check=True)
                await conn.run(f"/etc/init.d/{shlex.quote(s_n)} restart", check=True)
            elif init_sys == "rc.d":
                await conn.run(f"sysrc {shlex.quote(rc_variable(s_n) + '_enable')}=YES", check=True)
                await conn.run(f"service {shlex.quote(s_n)} restart", check=True)
            elif init_sys == "launchd":
                await conn.run(f"launchctl bootout system/{shlex.quote('org.shadow6.' + s_n)}", check=False)
                await conn.run(f"launchctl bootstrap system {shlex.quote(unit_path)}", check=True)
            elif init_sys == "guix":
                console.print(f"[yellow]Installed declarative Guix service fragment at {unit_path}; add it to operating-system services and reconfigure explicitly.[/yellow]")
            elif init_sys == "runit":
                console.print(f"[yellow]Installed runit service at {unit_path}; link it into the active service directory explicitly.[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Deployment failed for {node['name']}: {e}[/bold red]")
        raise

# ------------------------------------------------------------------------------
# Orchestration Logic
# ------------------------------------------------------------------------------

def parse_interval(interval_str: str) -> int:
    """Parse intervals like '24h', '60m' to seconds."""
    if not isinstance(interval_str, str) or len(interval_str) > 10 or not re.fullmatch(r"[1-9][0-9]*[hms]?", interval_str):
        raise ValueError(f"invalid interval: {interval_str!r}")
    unit = interval_str[-1] if interval_str[-1].isalpha() else "s"
    val = int(interval_str[:-1] if interval_str[-1].isalpha() else interval_str)
    if unit == 'h': return val * 3600
    if unit == 'm': return val * 60
    if unit == 's': return val
    raise ValueError(f"invalid interval unit: {unit}")


def is_loopback_host(value: str) -> bool:
    if value.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def format_host_port(host: str, port: int) -> str:
    """Format literal IPv6 and ordinary hosts for socket/URL authority use."""
    host = str(host).strip()
    if not host or any(character in host for character in "[]/%\r\n\x00"):
        raise ValueError(f"invalid host: {host!r}")
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        labels = host.rstrip(".").split(".")
        if len(host) > 253 or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise ValueError(f"invalid host: {host!r}")
        return f"{host}:{port}"
    return f"[{parsed}]:{port}" if parsed.version == 6 else f"{parsed}:{port}"


def load_topology_file(yaml_path: str) -> dict:
    path = Path(yaml_path).expanduser()
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("topology must be a regular, non-symlink file")
    if before.st_size > 1024 * 1024:
        raise ValueError("topology exceeds the 1 MiB size limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("topology changed while it was being opened")
        if opened.st_size > 1024 * 1024:
            raise ValueError("topology exceeds the 1 MiB size limit")
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as handle:
            document = handle.read(1024 * 1024 + 1)
        if len(document.encode("utf-8")) > 1024 * 1024:
            raise ValueError("topology exceeds the 1 MiB size limit")
        topology = parse_topology(document)
        final = os.fstat(descriptor)
        if final.st_uid != os.geteuid() or final.st_mode & 0o022:
            raise PermissionError("topology must be owner-controlled and not group/world writable")
        if any(node.get("ssh_pass") for node in topology["nodes"]):
            if stat.S_IMODE(final.st_mode) != 0o600 or final.st_nlink != 1:
                raise PermissionError("topology containing SSH secrets requires mode 0600 and one link")
        return topology
    finally:
        os.close(descriptor)


def selected_core_engine(node: Dict[str, Any]) -> str:
    engines = node.get("engines", [])
    selected = [engine for engine in engines if engine in CORE_ENGINES]
    if len(selected) != 1:
        raise ValueError(f"node {node.get('name', '<unknown>')} must select exactly one core engine")
    return selected[0]


def validate_topology(topo: Any) -> dict:
    """Validate untrusted topology input before paths, commands, or sockets use it."""
    if not isinstance(topo, dict):
        raise ValueError("topology must be a YAML mapping")
    if set(topo) - {"version", "global", "nodes"}:
        raise ValueError("unknown topology fields")
    if topo.get("version") != "1.0":
        raise ValueError("topology version must be '1.0'")
    global_cfg = topo.get("global", {})
    if not isinstance(global_cfg, dict):
        raise ValueError("global topology settings must be a mapping")
    if set(global_cfg) - {"stealth_mode", "broker_scheme", "broker_path", "output_dir", "mtd_rotation_interval"}:
        raise ValueError("unknown global topology fields")
    if "stealth_mode" in global_cfg and type(global_cfg["stealth_mode"]) is not bool:
        raise ValueError("stealth_mode must be boolean")
    for field in ("output_dir", "mtd_rotation_interval", "broker_scheme", "broker_path"):
        if field in global_cfg and (not isinstance(global_cfg[field], str) or not global_cfg[field] or len(global_cfg[field]) > 4096 or any(ord(c) < 32 for c in global_cfg[field])):
            raise ValueError(f"invalid global.{field}")
    broker_path = global_cfg.get("broker_path", "/ws")
    if not broker_path.startswith("/") or broker_path == "/" or any(c in broker_path for c in "?#\\ "):
        raise ValueError("global.broker_path must be a non-root absolute URL path")
    nodes = topo.get("nodes")
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_NODES:
        raise ValueError(f"topology must contain 1..{MAX_NODES} nodes")
    names = set()
    brokers = []
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            raise ValueError(f"node {index} must be a mapping")
        if set(node) - {"name", "type", "engines", "target_port", "listen_port", "ssh_port", "ssh_host", "ssh_user", "ssh_pass", "known_hosts", "deploy_root", "init_system", "advertise_host", "listen_host", "auto_close_after", "allow_local_discovery", "allowed_agents", "target_agent", "on_success", "domain"}:
            raise ValueError(f"node {index} contains unknown fields")
        if "domain" in node and (not isinstance(node["domain"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", node["domain"])):
            raise ValueError("domain must be a lowercase isolation label of 1..32 characters")
        for field in ("type", "ssh_host", "ssh_user", "ssh_pass", "known_hosts", "deploy_root", "init_system", "advertise_host", "listen_host", "target_agent", "on_success"):
            if field in node and (not isinstance(node[field], str) or len(node[field].encode("utf-8")) > 4096 or any(ord(c) < 32 for c in node[field])):
                raise ValueError(f"invalid node {field}")
        if "allow_local_discovery" in node and type(node["allow_local_discovery"]) is not bool:
            raise ValueError("allow_local_discovery must be boolean")
        if "auto_close_after" in node and (type(node["auto_close_after"]) is not int or not 1 <= node["auto_close_after"] <= 86400):
            raise ValueError("auto_close_after must be an integer in 1..86400")
        for field in ("ssh_host", "advertise_host", "listen_host"):
            if field in node:
                format_host_port(node[field], 4433)
        if "allowed_agents" in node and (not isinstance(node["allowed_agents"], list) or len(node["allowed_agents"]) > MAX_NODES or not all(isinstance(item, str) for item in node["allowed_agents"])):
            raise ValueError("allowed_agents must be a bounded list of names")
        name = node.get("name", "")
        role = node.get("type", "")
        if not isinstance(name, str) or not SAFE_NAME_RE.fullmatch(name):
            raise ValueError(f"node {index} has an unsafe name")
        if name in names:
            raise ValueError(f"duplicate node name: {name}")
        names.add(name)
        if role not in VALID_ROLES:
            raise ValueError(f"node {name} has invalid type: {role!r}")
        engines = node.get("engines", [])
        if not isinstance(engines, list) or not engines or not all(isinstance(e, str) for e in engines):
            raise ValueError(f"node {name} has invalid engines")
        unknown_engines = set(engines) - CORE_ENGINES - OPTIONAL_COMPONENTS
        if unknown_engines:
            raise ValueError(f"node {name} has unknown engines: {sorted(unknown_engines)}")
        selected_core_engine(node)
        if role == "broker":
            brokers.append(node)
        for port_key in ("target_port", "listen_port", "ssh_port"):
            if port_key in node:
                try:
                    if type(node[port_key]) is not int:
                        raise ValueError("port must be an integer")
                    port = node[port_key]
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"node {name} has invalid {port_key}") from exc
                if not 1 <= port <= 65535:
                    raise ValueError(f"node {name} has invalid {port_key}")
        ssh_host = node.get("ssh_host")
        deploy_root = node.get("deploy_root", "")
        if deploy_root:
            if not isinstance(deploy_root, str) or not Path(deploy_root).is_absolute() or deploy_root == "/" or ".." in Path(deploy_root).parts or any(character in deploy_root for character in "\r\n\x00"):
                raise ValueError(f"node {name} has an unsafe deploy_root")
            if not ssh_host or not is_loopback_host(str(ssh_host)):
                raise ValueError(f"node {name} deploy_root is restricted to loopback integration deployments")
            if node.get("init_system") != "none":
                raise ValueError(f"node {name} deploy_root requires init_system=none")
        if node.get("init_system", "auto") not in {"auto", "none", *INIT_SYSTEMS, *INIT_ALIASES}:
            raise ValueError(f"node {name} has an invalid init_system")
        if ssh_host and (not is_loopback_host(str(ssh_host)) or deploy_root) and not node.get("known_hosts"):
            raise ValueError(f"remote node {name} must set known_hosts for SSH host-key verification")
    if len(brokers) != 1:
        raise ValueError("topology must contain exactly one broker")
    agent_names = [node["name"] for node in nodes if node["type"] == "agent"]
    for node in nodes:
        if node["type"] == "client":
            allowed = node.get("allowed_agents", agent_names)
            target = node.get("target_agent", agent_names[0] if agent_names else "")
            if set(allowed) - set(agent_names) or target not in agent_names or target not in allowed:
                raise ValueError(f"client {node['name']} must target an existing allowed agent")
    core_engines = {selected_core_engine(node) for node in nodes}
    if len(core_engines) != 1:
        raise ValueError("all broker, agent, and client nodes must use the same core engine")
    broker = brokers[0]
    broker_host = str(broker.get("advertise_host", broker.get("ssh_host", "127.0.0.1")))
    scheme = global_cfg.get("broker_scheme", "wss")
    if scheme not in {"ws", "wss"}:
        raise ValueError("global.broker_scheme must be 'ws' or 'wss'")
    if scheme == "ws" and not is_loopback_host(broker_host):
        raise ValueError("plaintext ws:// control traffic is allowed only for a loopback broker")
    interval = parse_interval(str(global_cfg.get("mtd_rotation_interval", "24h")))
    if interval > 365 * 24 * 3600:
        raise ValueError("mtd_rotation_interval must not exceed 365 days")
    return topo


def _write_secure_json(path: Path, data: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_info = path.parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise ValueError(f"output directory must be a real directory: {path.parent}")
    if parent_info.st_uid != os.geteuid():
        raise PermissionError(f"output directory must be owned by the effective user: {path.parent}")
    os.chmod(path.parent, 0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    tmp_path = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

def generate_random_sni() -> str:
    """Generate a private-use SNI authenticated by the ephemeral certificate."""
    consonants = "bcdfghjklmnprstvwxz"
    vowels = "aeiou"
    return "".join(secrets.choice(consonants) + secrets.choice(vowels) for _ in range(secrets.randbelow(3) + 3)) + ".shadow6.invalid"

async def execute_mtd_rotation(topo: dict):
    """Perform Zero-Touch full-dimensional rotation and deploy."""
    topo = validate_topology(topo)
    console.print("[bold magenta][*] Initiating MTD Full-Dimensional Rotation...[/bold magenta]")
    
    # 1. Rotate Keys (Ed25519)
    broker_pub, broker_priv = generate_ed25519_keypair()
    
    agents_data = []
    clients_data = []
    has_c11_relay = False
    
    # Scan for C11 Relay in topology to warn clients
    for node in topo.get('nodes', []):
        engines = [e.lower() for e in node.get('engines', [])]
        if 'c11relay' in engines or 'c11-relay' in engines or 'c11' in node.get('name', '').lower():
            has_c11_relay = True
            
    agent_keys = {}
    client_keys = {}
    for node in topo.get('nodes', []):
        if node['type'] == 'agent':
            pub, priv = generate_ed25519_keypair()
            agent_keys[node['name']] = (pub, priv)
            agents_data.append({"id": node['name'], "pubkey": pub})
        elif node['type'] == 'client':
            pub, priv = generate_ed25519_keypair()
            client_keys[node['name']] = (pub, priv)
            agents_allow = node.get('allowed_agents', [a['name'] for a in topo.get('nodes', []) if a['type'] == 'agent'])
            clients_data.append({"id": node['name'], "pubkey": pub, "allowed_agents": agents_allow})

    for client in clients_data:
        unknown_agents = set(client["allowed_agents"]) - set(agent_keys)
        if unknown_agents:
            raise ValueError(f"client {client['id']} allows unknown agents: {sorted(unknown_agents)}")

    broker_node = next(node for node in topo["nodes"] if node["type"] == "broker")
    global_cfg = topo.get("global", {})
    core_engine = selected_core_engine(broker_node)
    broker_host = broker_node.get("advertise_host", broker_node.get("ssh_host", "127.0.0.1"))
    broker_port = int(broker_node.get("listen_port", 4433))
    broker_scheme = global_cfg.get("broker_scheme", "wss")
    broker_path = global_cfg.get("broker_path", "/ws")
    if not isinstance(broker_path, str) or not broker_path.startswith("/") or broker_path == "/" or any(char in broker_path for char in "?#\r\n"):
        raise ValueError("global.broker_path must be a non-root absolute URL path")
    broker_url = f"{broker_scheme}://{format_host_port(broker_host, broker_port)}{broker_path}"
    output_dir = Path(global_cfg.get("output_dir", "generated")).expanduser()
    if not output_dir.is_absolute():
        output_dir = Path.cwd() / output_dir
    agent_names = [node["name"] for node in topo["nodes"] if node["type"] == "agent"]

    tasks = []
    deployment_slots = asyncio.Semaphore(8)

    async def bounded_deploy(node, config):
        async with deployment_slots:
            await deploy_to_node(node, config)
    for node in topo.get('nodes', []):
        stealth = topo.get('global', {}).get('stealth_mode', True)
        config_data = {"role": node['type']}
        
        if node['type'] == 'broker':
            config_data['broker'] = {
                "listen_addr": format_host_port(node.get('listen_host', '0.0.0.0'), broker_port),
                "private_key": broker_priv,
                "agents": agents_data,
                "clients": clients_data,
                "webhook_url": "",
                "stealth_mode": stealth
            }
        elif node['type'] == 'agent':
            _, priv = agent_keys[node['name']]
            config_data['agent'] = {
                "id": node['name'],
                "broker_addrs": [broker_url],
                "broker_pubkey": broker_pub,
                "private_key": priv,
                "target_port": int(node.get("target_port", 22)),
                "auto_close_after": int(node.get("auto_close_after", 7200)),
                "allow_local_discovery": bool(node.get("allow_local_discovery", False)),
                "client_pubkeys": {name: keys[0] for name, keys in client_keys.items()},
            }
            if core_engine == "shadow6-rust":
                config_data['agent'].update({
                    "sni": generate_random_sni(),
                    "alpn": "shadow6/1",
                    "transport": "quic",
                })
            else:
                config_data['agent']["transport"] = CORE_TRANSPORTS[core_engine]
        elif node['type'] == 'client':
            _, priv = client_keys[node['name']]
            if has_c11_relay:
                console.print("[yellow]Warning: C11 relay enabled; transport metadata may be visible at the relay.[/yellow]")

            target_agent = node.get("target_agent", agent_names[0] if agent_names else "")
            if target_agent not in agent_keys:
                raise ValueError(f"client {node['name']} references unknown agent {target_agent!r}")
            
            config_data['client'] = {
                "id": node['name'],
                "broker_addrs": [broker_url],
                "broker_pubkey": broker_pub,
                "private_key": priv,
                "target_agent": target_agent,
                "agent_pubkey": agent_keys[target_agent][0],
                "on_success": node.get("on_success", ""),
                "allow_local_discovery": bool(node.get("allow_local_discovery", False)),
                "transport": CORE_TRANSPORTS[core_engine],
            }

        if core_engine == "shadow6-ada":
            domains = {item["name"]: item.get("domain", "default") for item in topo["nodes"]}
            config_data[node["type"]]["domain"] = domains[node["name"]]
            if node["type"] == "broker":
                for entry in agents_data + clients_data:
                    entry["domain"] = domains[entry["id"]]
            elif node["type"] == "agent":
                allowed = {entry["id"] for entry in clients_data if node["name"] in entry["allowed_agents"]}
                config_data["agent"]["client_pubkeys"] = {name: client_keys[name][0] for name in allowed}
                config_data["agent"]["client_domains"] = {name: domains[name] for name in allowed}
            else:
                config_data["client"]["target_domain"] = domains[target_agent]

        filename = output_dir / f"{node['name']}.json"
        _write_secure_json(filename, config_data)
        console.print(f"[green][+] Generated rotated config for {node['name']} -> {filename} (Perms 600)[/green]")
        
        # 4. Zero-Touch Provisioning
        if node.get('ssh_host') and (
            not is_loopback_host(str(node.get('ssh_host'))) or node.get("deploy_root")
        ):
            tasks.append((node, json.dumps(config_data)))
    
    if tasks:
        await asyncio.gather(*(bounded_deploy(node, config) for node, config in tasks))
    console.print("[bold cyan][+] MTD Epoch Rotation & Deployment Complete.[/bold cyan]")

async def mtd_daemon_loop(yaml_path: str):
    """Continuous MTD rotation daemon."""
    topo = load_topology_file(yaml_path)
    
    interval_str = topo.get('global', {}).get('mtd_rotation_interval', '24h')
    interval = parse_interval(interval_str)
    
    console.print(f"[bold yellow][*] Starting MTD Daemon. Epoch interval: {interval} seconds.[/bold yellow]")
    
    while True:
        await execute_mtd_rotation(topo)
        console.print(f"[dim]Sleeping for {interval} seconds until next epoch...[/dim]")
        await asyncio.sleep(interval)

def apply_topology(yaml_path: str):
    """Wrapper to run single rotation."""
    topo = load_topology_file(yaml_path)
    
    engines_found = set()
    for n in topo.get('nodes', []):
        engines_found.update(n.get('engines', []))
    
    if not (engines_found & CORE_ENGINES):
        console.print("[bold red]Error: Core engine missing. Aborting.[/bold red]")
        raise ValueError("topology does not select a core engine")
        
    asyncio.run(execute_mtd_rotation(topo))


def send_client_knock(
    target_ip: str,
    target_port: int,
    secret: str,
    source_ip: Optional[str] = None,
    client_config: Optional[str] = None,
    engine: str = "shadow6-rust",
) -> dict:
    """Send one bounded SPA packet and optionally launch one fixed Core client."""
    if isinstance(target_port, bool) or not isinstance(target_port, int) or not 1 <= target_port <= 65535:
        raise ValueError("target_port must be between 1 and 65535")
    try:
        parsed_ip = ipaddress.ip_address(target_ip)
    except ValueError as exc:
        raise ValueError("target_ip must be a literal IPv4 or IPv6 address") from exc
    if source_ip is None:
        source_ip = str(parsed_ip) if parsed_ip.is_loopback else get_public_ip()
    try:
        source_ip = str(ipaddress.ip_address(source_ip))
    except ValueError as exc:
        raise ValueError("source_ip must be a literal IPv4 or IPv6 address") from exc

    packet = generate_spa_packet(secret, source_ip)
    family = socket.AF_INET6 if parsed_ip.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.sendto(packet, (target_ip, target_port))

    launched = None
    if client_config:
        binary = ENGINE_BINARIES.get(engine)
        if binary is None or not binary.is_file():
            raise ValueError(f"engine binary is unavailable: {engine}")
        config_path = Path(client_config).expanduser().resolve(strict=True)
        process = subprocess.Popen([str(binary), "--config", str(config_path)], start_new_session=True)
        launched = {"engine": engine, "config": str(config_path), "pid": process.pid}
    return {
        "target_ip": str(parsed_ip),
        "target_port": target_port,
        "source_ip": source_ip,
        "packet_bytes": len(packet),
        "launched": launched,
    }

# ------------------------------------------------------------------------------
# CLI & TUI Interface
# ------------------------------------------------------------------------------
@app_cli.command()
def apply(file: str = typer.Option(..., "-f", help="Topology YAML file")):
    """Applies the declarative topology to the network."""
    apply_topology(file)

@app_cli.command()
def client_knock(
    target_ip: str,
    target_port: int,
    secret: str = typer.Option(..., "--secret", envvar="SHADOW6_SPA_SECRET", prompt=True, hide_input=True),
    source_ip: Optional[str] = typer.Option(None, "--source-ip"),
    client_config: Optional[str] = typer.Option(None, "--client-config"),
    engine: str = typer.Option("shadow6-rust", "--engine"),
):
    """Executes Cryptographic SPA Knocking and starts local client."""
    try:
        result = send_client_knock(
            target_ip, target_port, secret, source_ip, client_config, engine
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"[*] SPA source-IP binding: [cyan]{result['source_ip']}[/cyan]")
    console.print(f"[green][+] SPA Knock dispatched to {target_ip}:{target_port}; gateway acceptance is not acknowledged.[/green]")
    if result["launched"]:
        console.print(f"[*] Launched {engine} with {result['launched']['config']}")

class ShadowTUI(App):
    """Textual TUI for Dashboard visualization."""
    CSS = """
    Grid { grid-size: 2; grid-gutter: 1 2; }
    Log { border: solid green; height: 100%; }
    Static { border: solid cyan; content-align: center middle; height: 100%; }
    """
    def compose(self) -> ComposeResult:
        yield Header()
        yield Grid(
            Static("Telemetry: not configured\nUse detector/watch.py for live events", id="status"),
            Log(id="logs")
        )
        yield Footer()

    def on_mount(self) -> None:
        log = self.query_one(Log)
        log.write_line("[*] Shadow6-Auto TUI Initialized.")
        log.write_line("[*] This dashboard does not claim node status without a telemetry source.")

@app_cli.command()
def dashboard():
    """Launches the interactive TUI Dashboard."""
    app = ShadowTUI()
    app.run()

@app_cli.command()
def mtd_daemon(file: str = typer.Option(..., "-f", help="Topology YAML file")):
    """Starts the Moving Target Defense continuous rotation daemon."""
    asyncio.run(mtd_daemon_loop(file))


@app_cli.command("rpc-server")
def rpc_server(
    token: str = typer.Option(..., envvar="SHADOW6_RPC_TOKEN", prompt=True, hide_input=True),
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8765, min=1, max=65535),
    allowed_ip: List[str] = typer.Option([], "--allow-ip"),
    allowed_domain: List[str] = typer.Option([], "--allow-domain"),
):
    """Run the authenticated target-authorization API for local plugins."""
    if len(token.encode("utf-8")) < 32:
        raise typer.BadParameter("RPC token must contain at least 32 bytes")
    if not is_loopback_host(host):
        raise typer.BadParameter("RPC server is plaintext and may bind only to a loopback address")
    acl = PluginACL(allowed_ip, allowed_domain)
    server = RPCServer(host, port, acl, token)

    async def serve_forever():
        await server.start()
        console.print(f"[green]RPC server listening on http://{host}:{port}/rpc[/green]")
        await asyncio.Event().wait()

    asyncio.run(serve_forever())


if __name__ == "__main__":
    app_cli()
