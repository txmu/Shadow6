#!/usr/bin/env python3
"""Loopback-only integration test for the real C11 UDP relay path."""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else "./c11relay_test"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as echo:
        echo.bind(("127.0.0.1", 0))
        echo.settimeout(0.2)
        echo_port = int(echo.getsockname()[1])
        relay_port = free_udp_port()
        stopped = threading.Event()

        def echo_loop() -> None:
            while not stopped.is_set():
                try:
                    packet, address = echo.recvfrom(65535)
                except socket.timeout:
                    continue
                echo.sendto(b"echo:" + packet, address)

        worker = threading.Thread(target=echo_loop, daemon=True)
        worker.start()
        process = subprocess.Popen(
            [
                binary,
                "--bind",
                "127.0.0.1",
                "--port",
                str(relay_port),
                "--dest",
                f"127.0.0.1:{echo_port}",
                "--max-peers",
                "8",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for client_number in range(2):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(0.2)
                    payload = f"client-{client_number}".encode()
                    deadline = time.monotonic() + 5
                    while True:
                        client.sendto(payload, ("127.0.0.1", relay_port))
                        try:
                            response, _ = client.recvfrom(65535)
                        except socket.timeout:
                            if time.monotonic() >= deadline:
                                raise AssertionError("relay did not return an echo response")
                            continue
                        if response != b"echo:" + payload:
                            raise AssertionError(f"unexpected response: {response!r}")
                        break
        finally:
            stopped.set()
            process.terminate()
            stdout, stderr = process.communicate(timeout=5)
            worker.join(timeout=1)
        if process.returncode != 0:
            raise AssertionError(f"relay exited with {process.returncode}: {stdout}\n{stderr}")

    invalid = subprocess.run([binary, "--port", "0"], capture_output=True, text=True, check=False)
    if invalid.returncode == 0:
        raise AssertionError("invalid port was accepted")
    print("[PASS] C11 relay bidirectional multi-client loopback integration")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
