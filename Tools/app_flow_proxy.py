#!/usr/bin/env python3
"""Bridge loopback TCP/UDP applications to a Core seqpacket ingress FD.

The proxy is deliberately bounded: it pauses socket reads while the inherited
seqpacket socket cannot accept another record. It never opens a public listener.
"""
from __future__ import annotations

import argparse
import json
import os
import selectors
import socket
import sys


MAX_RECORD = 1172
MAX_PENDING = 64
LOW_WATER = 32
MAX_PEERS = 64


def run(fd: int, host: str, port: int, protocol: str, max_record: int,
        ready_fd: int | None = None) -> int:
    if not 1 <= max_record <= MAX_RECORD:
        raise ValueError("max-record out of range")
    if protocol not in ("tcp", "udp"):
        raise ValueError("protocol must be tcp or udp")
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError("proxy listener must be loopback")
    flow = socket.socket(fileno=fd)
    flow.setblocking(False)
    if flow.family != socket.AF_UNIX or flow.type != socket.SOCK_SEQPACKET:
        raise ValueError("fd must be an AF_UNIX SOCK_SEQPACKET socket")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    if protocol == "tcp":
        listener.listen(8)
    listener.setblocking(False)
    if ready_fd is not None:
        try:
            event = {"event": "shadow6.app-flow-proxy.ready", "schema": 1,
                     "protocol": protocol, "host": host, "port": listener.getsockname()[1]}
            os.write(ready_fd, (json.dumps(event, separators=(",", ":")) + "\n").encode())
        finally:
            os.close(ready_fd)
    selector = selectors.DefaultSelector()
    selector.register(listener, selectors.EVENT_READ, None)
    pending: list[tuple[bytes, socket.socket | None]] = []
    peers: set[socket.socket] = set()
    paused_peers: set[socket.socket] = set()
    reads_paused = False

    def registered(sock: socket.socket) -> bool:
        try:
            selector.get_key(sock)
            return True
        except KeyError:
            return False

    def sync_listener() -> None:
        allowed = (not reads_paused and len(pending) < MAX_PENDING
                   and (protocol == "udp" or len(peers) < MAX_PEERS))
        if allowed and not registered(listener):
            selector.register(listener, selectors.EVENT_READ, None)
        elif not allowed and registered(listener):
            selector.unregister(listener)

    def pause_peer_reads() -> None:
        nonlocal reads_paused
        if reads_paused:
            return
        reads_paused = True
        if registered(listener):
            selector.unregister(listener)
        if protocol == "tcp":
            for peer in tuple(peers):
                if registered(peer):
                    selector.unregister(peer)
                    paused_peers.add(peer)

    def resume_peer_reads() -> None:
        nonlocal reads_paused
        if not reads_paused or len(pending) > LOW_WATER:
            return
        reads_paused = False
        for peer in tuple(paused_peers):
            paused_peers.discard(peer)
            if peer in peers:
                selector.register(peer, selectors.EVENT_READ, peer)
        sync_listener()

    try:
        while True:
            events = selector.select(1.0)
            for key, _ in events:
                sock = key.fileobj
                if sock is flow:
                    continue
                # select() may have returned a batch just before the high-water
                # transition. Never let stale peer events exceed MAX_PENDING.
                if len(pending) >= MAX_PENDING:
                    pause_peer_reads()
                    continue
                if sock is listener:
                    if len(pending) >= MAX_PENDING or (protocol == "tcp" and len(peers) >= MAX_PEERS):
                        continue
                    if protocol == "udp":
                        data, _ = listener.recvfrom(max_record + 1)
                        if len(data) <= max_record:
                            pending.append((data, None))
                    else:
                        conn, _ = listener.accept()
                        conn.setblocking(False)
                        if len(peers) >= MAX_PEERS:
                            conn.close()
                            continue
                        peers.add(conn)
                        selector.register(conn, selectors.EVENT_READ, conn)
                        sync_listener()
                    continue
                conn = key.data
                if reads_paused or conn in paused_peers:
                    continue
                try:
                    data = conn.recv(max_record)
                except BlockingIOError:
                    continue
                if not data:
                    if registered(conn):
                        selector.unregister(conn)
                    peers.discard(conn)
                    paused_peers.discard(conn)
                    conn.close()
                    sync_listener()
                    continue
                pending.append((data, conn))
                if len(pending) >= MAX_PENDING:
                    pause_peer_reads()
            while pending:
                data, conn = pending[0]
                try:
                    flow.send(data)
                except (BlockingIOError, InterruptedError):
                    if not registered(flow):
                        selector.register(flow, selectors.EVENT_WRITE, "flow-write")
                    break
                pending.pop(0)
            if not pending and registered(flow):
                selector.unregister(flow)
            resume_peer_reads()
            sync_listener()
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
    parser.add_argument("--ready-fd", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if not 0 < args.port < 65536:
        parser.error("port out of range")
    try:
        return run(args.fd, args.host, args.port, args.protocol, args.max_record, args.ready_fd)
    except (OSError, ValueError) as exc:
        print(f"app-flow-proxy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
