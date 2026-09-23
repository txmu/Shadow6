#!/usr/bin/env python3
"""Loopback Virtual Client/Agent admission proxy for one native Core family."""
from __future__ import annotations

import argparse
import asyncio
import base64
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time

if __name__ == "__main__":
    _root = Path(__file__).resolve().parents[1]
    for _candidate in (_root / "Tools", _root / "share/shadow6/modules"):
        if (_candidate / "python_runtime.py").is_file():
            sys.path.insert(0, str(_candidate))
            from python_runtime import bootstrap
            bootstrap(_root, Path(__file__).absolute())
            break
    for candidate in (Path(__file__).resolve().parent, Path(__file__).resolve().parents[1] / "share/shadow6/modules"):
        if (candidate / "virtual_broker.py").is_file():
            sys.path.insert(0, str(candidate))
            break

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from virtual_broker import CORES, bounded_file, canonical, pairs, reject_float

SCHEMA = "shadow6.virtual-peer.v1"
ADMISSION_SCHEMA = "shadow6.virtual-broker-admission.v1"


def _endpoint(value):
    if type(value) is not dict or set(value) != {"host", "port"}:
        raise ValueError("endpoint requires host and port")
    if type(value["host"]) is not str or not ipaddress.ip_address(value["host"]).is_loopback:
        raise ValueError("Virtual Peer endpoints must use loopback IP addresses")
    if type(value["port"]) is not int or not 1 <= value["port"] <= 65535:
        raise ValueError("invalid endpoint port")
    return value["host"], value["port"]


def load_config(path: Path):
    value = json.loads(bounded_file(path, 16384).decode("utf-8"),
                       object_pairs_hook=pairs, parse_float=reject_float,
                       parse_constant=reject_float)
    expected = {"schema", "role", "core", "tenant", "identity", "private_key_file",
                "transport", "listen", "gate", "max_connections", "idle_seconds"}
    if type(value) is not dict or set(value) != expected or value["schema"] != SCHEMA:
        raise ValueError("unknown Virtual Peer schema or field")
    if type(value["role"]) is not str or value["role"] not in ("client", "agent") or type(value["core"]) is not str or value["core"] not in CORES:
        raise ValueError("invalid Virtual Peer role or Core family")
    for field, limit in (("tenant", 64), ("identity", 128)):
        item = value[field]
        if type(item) is not str or not 1 <= len(item) <= limit or not all(c.isascii() and (c.isalnum() or c in "._-") for c in item):
            raise ValueError(f"invalid {field}")
    if type(value["transport"]) is not str or value["transport"] not in ("tcp", "udp"):
        raise ValueError("invalid Virtual Peer transport")
    if type(value["max_connections"]) is not int or not 1 <= value["max_connections"] <= 1024:
        raise ValueError("invalid connection limit")
    if type(value["idle_seconds"]) is not int or not 5 <= value["idle_seconds"] <= 3600:
        raise ValueError("invalid idle deadline")
    listen, gate = _endpoint(value["listen"]), _endpoint(value["gate"])
    if listen == gate:
        raise ValueError("listen and Gate endpoints must differ")
    key_path = value["private_key_file"]
    if type(key_path) is not str or not Path(key_path).is_absolute():
        raise ValueError("private key path must be absolute")
    seed = bounded_file(Path(key_path), 32, secret=True)
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    return value, listen, gate, Ed25519PrivateKey.from_private_bytes(seed)


class VirtualPeer:
    def __init__(self, config, listen, gate, key):
        self.config, self.listen, self.gate, self.key = config, listen, gate, key
        self.active = 0
        self.public = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()

    def admission(self):
        now = int(time.time())
        request = {"schema": ADMISSION_SCHEMA, "tenant": self.config["tenant"],
                   "client": self.config["identity"], "core": self.config["core"],
                   "issued": now, "expires": now + 60,
                   "nonce": base64.b64encode(os.urandom(32)).decode(),
                   "public_key": self.public}
        request["signature"] = base64.b64encode(self.key.sign(canonical(request))).decode()
        return canonical(request)

    async def _copy(self, reader, writer):
        while True:
            async with asyncio.timeout(self.config["idle_seconds"]):
                chunk = await reader.read(65536)
            if not chunk:
                if writer.can_write_eof():
                    writer.write_eof()
                    await writer.drain()
                return
            writer.write(chunk)
            async with asyncio.timeout(self.config["idle_seconds"]):
                await writer.drain()

    async def handle_tcp(self, reader, writer):
        if self.active >= self.config["max_connections"]:
            writer.close()
            return
        self.active += 1
        upstream = None
        tasks = []
        try:
            async with asyncio.timeout(10):
                remote, upstream = await asyncio.open_connection(*self.gate, limit=65536)
            admission = self.admission()
            upstream.write(struct.pack("!I", len(admission)) + admission)
            await upstream.drain()
            tasks = [asyncio.create_task(self._copy(reader, upstream)),
                     asyncio.create_task(self._copy(remote, writer))]
            await asyncio.gather(*tasks)
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            for stream in (upstream, writer):
                if stream:
                    stream.close()
            self.active -= 1

    async def serve_udp(self):
        family = socket.AF_INET6 if ":" in self.listen[0] else socket.AF_INET
        listener = socket.socket(family, socket.SOCK_DGRAM)
        listener.setblocking(False)
        listener.bind(self.listen)
        loop = asyncio.get_running_loop()
        tasks = set()

        async def forward(source, payload):
            remote = socket.socket(family, socket.SOCK_DGRAM)
            remote.setblocking(False)
            try:
                await loop.sock_connect(remote, self.gate)
                admission = self.admission()
                frame = struct.pack("!H", len(admission)) + admission + payload
                if len(frame) > 65507:
                    return
                await loop.sock_sendall(remote, frame)
                async with asyncio.timeout(self.config["idle_seconds"]):
                    reply = await loop.sock_recv(remote, 65508)
                if 0 < len(reply) <= 65507:
                    await loop.sock_sendto(listener, reply, source)
            except (OSError, asyncio.TimeoutError):
                pass
            finally:
                remote.close()
                self.active -= 1

        try:
            while True:
                payload, source = await loop.sock_recvfrom(listener, 65508)
                if not payload or len(payload) > 65507 or self.active >= self.config["max_connections"]:
                    continue
                self.active += 1
                task = asyncio.create_task(forward(source, payload))
                tasks.add(task)
                task.add_done_callback(tasks.discard)
        finally:
            listener.close()
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def serve(self):
        if self.config["transport"] == "udp":
            await self.serve_udp()
        else:
            server = await asyncio.start_server(self.handle_tcp, *self.listen, limit=65536)
            async with server:
                await server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--role", choices=("client", "agent"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        config, listen, gate, key = load_config(args.config)
        if args.role is not None and config["role"] != args.role:
            raise ValueError("Virtual Peer role does not match command")
        peer = VirtualPeer(config, listen, gate, key)
        if args.check:
            print(json.dumps({"schema": SCHEMA, "role": config["role"], "core": config["core"],
                              "transport": config["transport"], "public_key": peer.public,
                              "listen": listen, "gate": gate}))
            return 0
        asyncio.run(peer.serve())
        return 0
    except (OSError, ValueError, PermissionError) as exc:
        print(f"virtual peer: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
