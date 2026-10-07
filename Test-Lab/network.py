"""Bounded Linux netns/netem capability and scenario helpers."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

SCENARIOS = {
    "clean": {"kind": "local", "description": "No impairment; local native path."},
    "lan": {"kind": "simulated", "a_to_b": {"latency_ms": 1, "jitter_ms": 1},
            "b_to_a": {"latency_ms": 1, "jitter_ms": 1}},
    "good-wan": {"kind": "simulated", "a_to_b": {"latency_ms": 30, "jitter_ms": 5, "loss_percent": 0.2},
                 "b_to_a": {"latency_ms": 45, "jitter_ms": 8, "loss_percent": 0.3}},
    "mobile": {"kind": "simulated", "a_to_b": {"latency_ms": 55, "jitter_ms": 20, "loss_percent": 1.0},
               "b_to_a": {"latency_ms": 75, "jitter_ms": 28, "loss_percent": 1.5}},
    "long-haul": {"kind": "simulated", "a_to_b": {"latency_ms": 110, "jitter_ms": 15, "loss_percent": 0.5},
                  "b_to_a": {"latency_ms": 125, "jitter_ms": 18, "loss_percent": 0.6}},
    "lossy": {"kind": "simulated", "a_to_b": {"latency_ms": 40, "jitter_ms": 10, "loss_percent": 3.0},
              "b_to_a": {"latency_ms": 40, "jitter_ms": 10, "loss_percent": 3.0}},
    "high-jitter": {"kind": "simulated", "a_to_b": {"latency_ms": 40, "jitter_ms": 35},
                    "b_to_a": {"latency_ms": 55, "jitter_ms": 45}},
    "constrained": {"kind": "simulated", "a_to_b": {"latency_ms": 45, "jitter_ms": 8, "loss_percent": 1.0, "rate_kbit": 2048, "queue_limit": 100},
                    "b_to_a": {"latency_ms": 55, "jitter_ms": 10, "loss_percent": 1.0, "rate_kbit": 1024, "queue_limit": 100}},
    "failure-recovery": {"kind": "simulated-phased", "phases": [
        {"seconds": 1, "a_to_b": {"latency_ms": 25}, "b_to_a": {"latency_ms": 35}},
        {"seconds": 1, "a_to_b": {"latency_ms": 60}, "b_to_a": {"latency_ms": 80}},
        {"seconds": 1, "a_to_b": {"latency_ms": 25}, "b_to_a": {"latency_ms": 35}},
    ]},
}
_NAME = re.compile(r"s6tl-[a-f0-9]{10}\Z")


def system_tool(name):
    if name not in {'ip', 'tc'}:
        raise ValueError('unsupported network tool')
    found = shutil.which(name)
    if found:
        return found
    for directory in ('/usr/sbin', '/sbin', '/usr/bin', '/bin'):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _options(settings):
    if not isinstance(settings, dict) or set(settings) - {
            "latency_ms", "jitter_ms", "loss_percent", "duplicate_percent",
            "reorder_percent", "corruption_percent", "rate_kbit", "queue_limit"}:
        raise ValueError("unknown netem parameter")
    result = []
    bounds = {"latency_ms": (0, 1000), "jitter_ms": (0, 500),
              "loss_percent": (0, 30), "duplicate_percent": (0, 10),
              "reorder_percent": (0, 30), "corruption_percent": (0, 5),
              "rate_kbit": (16, 100_000), "queue_limit": (10, 10_000)}
    args = {"latency_ms": ("delay", "ms"), "jitter_ms": (None, "ms"),
            "loss_percent": ("loss", "%"), "duplicate_percent": ("duplicate", "%"),
            "reorder_percent": ("reorder", "%"), "corruption_percent": ("corrupt", "%"),
            "rate_kbit": ("rate", "kbit"), "queue_limit": ("limit", "")}
    for key, value in settings.items():
        low, high = bounds[key]
        if type(value) not in (int, float) or not low <= value <= high:
            raise ValueError(f"netem {key} outside supported bounds")
    latency = settings.get("latency_ms", 0)
    jitter = settings.get("jitter_ms", 0)
    if latency or jitter:
        result.extend(["delay", f"{latency:g}ms"])
        if jitter:
            result.append(f"{jitter:g}ms")
    for key in ("loss_percent", "duplicate_percent", "reorder_percent", "corruption_percent"):
        if settings.get(key, 0):
            result.extend([args[key][0], f"{settings[key]:g}%"])
    if settings.get("rate_kbit"):
        result.extend(["rate", f"{settings['rate_kbit']:g}kbit"])
    if settings.get("queue_limit"):
        result.extend(["limit", str(settings["queue_limit"])])
    return result


def netem_argv(settings):
    values = _options(settings)
    return ["tc", "qdisc", "replace", "dev", "lo", "root", "netem", *values] if values else [
        "tc", "qdisc", "del", "dev", "lo", "root"]


def netem_veth_argv(interface, settings):
    if interface not in {"s6tl-a", "s6tl-b"}:
        raise ValueError("unsupported test interface")
    values = _options(settings)
    return ["tc", "qdisc", "replace", "dev", interface, "root", "netem", *values] if values else [
        "tc", "qdisc", "del", "dev", interface, "root"]


def symmetric_loopback_settings(a_to_b, b_to_a):
    """Map directional intent to the conservative single-loopback qdisc.

    A single loopback egress qdisc cannot distinguish its two peers. Preserve
    the requested values and apply the stricter bound in both directions.
    NamespacePair.apply remains available for genuinely directional veth tests.
    """
    _options(a_to_b)
    _options(b_to_a)
    result = {}
    for key in ("latency_ms", "jitter_ms", "loss_percent", "duplicate_percent",
                "reorder_percent", "corruption_percent", "queue_limit"):
        values = [mapping[key] for mapping in (a_to_b, b_to_a) if key in mapping]
        if values:
            result[key] = min(values) if key == "queue_limit" else max(values)
    rates = [mapping["rate_kbit"] for mapping in (a_to_b, b_to_a) if mapping.get("rate_kbit")]
    if rates:
        result["rate_kbit"] = min(rates)
    return result


def capabilities():
    ip = system_tool("ip")
    tc = system_tool("tc")
    cap_net_admin = False
    cap_net_raw = False
    cap_sys_admin = False
    try:
        with open("/proc/self/status", encoding="ascii") as stream:
            for line in stream:
                if line.startswith("CapEff:"):
                    effective = int(line.split()[1], 16)
                    cap_net_admin = bool(effective & (1 << 12))
                    cap_net_raw = bool(effective & (1 << 13))
                    cap_sys_admin = bool(effective & (1 << 21))
                    break
    except (OSError, ValueError, IndexError):
        pass
    missing = []
    if not ip: missing.append('iproute2 ip')
    if not cap_net_admin: missing.append('CAP_NET_ADMIN')
    if not cap_sys_admin: missing.append('CAP_SYS_ADMIN for namespace creation/entry')
    namespace_ready = os.name == 'posix' and not missing
    if not tc: missing.append('iproute2 tc')
    return {"ip": ip, "tc": tc, "capNetAdmin": cap_net_admin,
            'capNetRaw': cap_net_raw, 'capSysAdmin': cap_sys_admin,
            'netns': bool(namespace_ready),
            "netnsNetem": bool(os.name == "posix" and not missing),
            'namespaceCapture': bool(namespace_ready and cap_net_raw and shutil.which('tcpdump')),
            'evidence': 'read-only-tool-and-effective-capability-check; namespace operation remains runtime-verified',
            "reason": '; '.join(missing) if missing else None}


class Namespace:
    """One isolated namespace with a loopback path for the shared local runner."""
    def __init__(self, timeout=8):
        self.timeout = timeout
        self.name = "s6tl-" + uuid.uuid4().hex[:10]
        self.ip = system_tool("ip")
        self.created = False

    def _run(self, argv, *, check=True):
        result = subprocess.run(argv, capture_output=True, timeout=self.timeout, check=False)
        if check and result.returncode:
            reason = result.stderr.decode("utf-8", "replace")[-500:]
            raise RuntimeError(f"{Path(argv[0]).name} failed ({result.returncode}): {reason}")
        return result

    def create(self):
        caps = capabilities()
        if not caps["netns"]:
            raise PermissionError(caps["reason"])
        self._run([self.ip, "netns", "add", self.name])
        self.created = True
        try:
            self._run([self.ip, "-n", self.name, "link", "set", "lo", "up"])
            # Native Go/Rust address discovery and Native WebRTC ICE require
            # a non-loopback source. This dummy link has no host peer or uplink.
            self._run([self.ip, '-n', self.name, 'link', 'add', 's6tl-local', 'type', 'dummy'])
            self._run([self.ip, '-n', self.name, 'addr', 'add', '198.18.7.1/32', 'dev', 's6tl-local'])
            self._run([self.ip, '-n', self.name, '-6', 'addr', 'add', 'fd06:6::1/128', 'dev', 's6tl-local', 'nodad'])
            self._run([self.ip, '-n', self.name, 'link', 'set', 's6tl-local', 'up'])
            self._run([self.ip, '-n', self.name, 'route', 'add', 'default', 'dev', 's6tl-local'])
            self._run([self.ip, '-n', self.name, '-6', 'route', 'add', 'default', 'dev', 's6tl-local'])
            return self
        except BaseException:
            self.close()
            raise

    def exec(self, argv):
        if not self.created:
            raise ValueError("test namespace is not active")
        return [self.ip, "netns", "exec", self.name, *argv]

    def apply(self, settings):
        tc = system_tool("tc")
        if not tc:
            raise PermissionError("tc not installed")
        self._run(self.exec([tc, "qdisc", "replace", "dev", "lo", "root", "netem", *_options(settings)]))

    def reset(self):
        tc = system_tool("tc")
        if tc:
            self._run(self.exec([tc, "qdisc", "del", "dev", "lo", "root"]), check=False)

    def close(self):
        if self.created and self.ip:
            self._run([self.ip, "netns", "del", self.name], check=False)
        self.created = False

    def __enter__(self):
        return self.create()

    def __exit__(self, *_):
        self.close()


class NamespacePair:
    """Two isolated Linux namespaces joined by a veth pair; never edits host routes."""
    def __init__(self, timeout=8):
        self.timeout = timeout
        self.prefix = "s6tl-" + uuid.uuid4().hex[:10]
        self.a = self.prefix + "a"
        self.b = self.prefix + "b"
        self.created = []
        self.ip = system_tool("ip")

    def _run(self, argv, *, check=True):
        result = subprocess.run(argv, capture_output=True, timeout=self.timeout, check=False)
        if check and result.returncode:
            reason = result.stderr.decode("utf-8", "replace")[-500:]
            raise RuntimeError(f"{Path(argv[0]).name} failed ({result.returncode}): {reason}")
        return result

    def create(self):
        caps = capabilities()
        if not caps["netns"]:
            raise PermissionError(caps["reason"])
        try:
            self._run([self.ip, "netns", "add", self.a]); self.created.append(self.a)
            self._run([self.ip, "netns", "add", self.b]); self.created.append(self.b)
            self._run([self.ip, "link", "add", "s6tl-a", "type", "veth", "peer", "name", "s6tl-b"])
            self._run([self.ip, "link", "set", "s6tl-a", "netns", self.a])
            self._run([self.ip, "link", "set", "s6tl-b", "netns", self.b])
            for namespace, iface, address in ((self.a, "s6tl-a", "198.18.6.1/30"),
                                               (self.b, "s6tl-b", "198.18.6.2/30")):
                self._run([self.ip, "-n", namespace, "link", "set", "lo", "up"])
                self._run([self.ip, "-n", namespace, "addr", "add", address, "dev", iface])
                self._run([self.ip, "-n", namespace, "link", "set", iface, "up"])
            return self
        except BaseException:
            self.close()
            raise

    def exec(self, namespace, argv):
        if namespace not in self.created:
            raise ValueError("namespace is not owned by this test run")
        return [self.ip, "netns", "exec", namespace, *argv]

    def apply(self, a_to_b, b_to_a):
        tc = system_tool("tc")
        if not tc:
            raise PermissionError("tc not installed")
        self._run(self.exec(self.a, [tc, *netem_veth_argv("s6tl-a", a_to_b)[1:]]))
        self._run(self.exec(self.b, [tc, *netem_veth_argv("s6tl-b", b_to_a)[1:]]))

    def close(self):
        if not self.ip:
            return
        for namespace in reversed(self.created):
            self._run([self.ip, "netns", "del", namespace], check=False)
        self.created.clear()

    def __enter__(self):
        return self.create()

    def __exit__(self, *_):
        self.close()
