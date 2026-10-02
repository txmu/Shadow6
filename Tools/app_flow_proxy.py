#!/usr/bin/env python3
"""Bridge loopback TCP/UDP applications to a Core seqpacket ingress FD.

The proxy is deliberately bounded: it pauses socket reads while the inherited
seqpacket socket cannot accept another record. It never opens a public listener.
"""
from __future__ import annotations

import argparse
import os
import selectors
import socket
import sys


MAX_RECORD = 1172
MAX_PENDING = 64


def run(fd: int, host: str, port: int, protocol: str, max_record: int) -> int:
    if not 1 <= max_record <= MAX_RECORD:
        raise ValueError("max-record out of range")
    flow = socket.socket(fileno=fd)
    flow.setblocking(False)
    if flow.family != socket.AF_UNIX or flow.type != socket.SOCK_SEQPACKET:
        raise ValueError("fd must be an AF_UNIX SOCK_SEQPACKET socket")
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError("proxy listener must be loopback")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    if protocol == "tcp":
        listener.listen(8)
    listener.setblocking(False)
    selector = selectors.DefaultSelector()
    selector.register(listener, selectors.EVENT_READ, None)
    pending: list[tuple[bytes, socket.socket | None]] = []
    peers: set[socket.socket] = set()
    try:
        while True:
            if len(pending) >= MAX_PENDING and listener in [key.fileobj for key in selector.get_map().values()]:
                selector.unregister(listener)
            events = selector.select(1.0)
            for key, _ in events:
                sock = key.fileobj
                if sock is listener:
                    if len(pending) >= MAX_PENDING:
                        continue
                    if protocol == "udp":
                        data, _ = listener.recvfrom(max_record)
                        if len(data) <= max_record:
                            pending.append((data, None))
                    else:
                        conn, _ = listener.accept()
                        conn.setblocking(False); peers.add(conn)
                        selector.register(conn, selectors.EVENT_READ, conn)
                    continue
                conn = key.data
                try:
                    data = conn.recv(max_record)
                except BlockingIOError:
                    continue
                if not data:
                    selector.unregister(conn); peers.discard(conn); conn.close(); continue
                pending.append((data, conn))
            while pending:
                data, conn = pending[0]
                try:
                    flow.send(data)
                except (BlockingIOError, InterruptedError):
                    break
                pending.pop(0)
            if len(pending) < MAX_PENDING and listener not in [key.fileobj for key in selector.get_map().values()]:
                selector.register(listener, selectors.EVENT_READ, None)
    except KeyboardInterrupt:
        return 0
    finally:
        for peer in peers:
            peer.close()
        listener.close(); flow.close(); selector.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fd", type=int, required=True, help="inherited SOCK_SEQPACKET FD")
    parser.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--max-record", type=int, default=MAX_RECORD)
    args = parser.parse_args(argv)
    if not 0 < args.port < 65536:
        parser.error("port out of range")
    try:
        return run(args.fd, args.host, args.port, args.protocol, args.max_record)
    except (OSError, ValueError) as exc:
        print(f"app-flow-proxy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
