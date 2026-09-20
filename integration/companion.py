"""Equal Python/Node library isolation and S6NA carrier adapters for stack_test."""
import json
import queue
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
BACKENDS = ("native", "python", "node")


class Adapter:
    def __init__(self, backend, core, key_path, side):
        executable = sys.executable if backend == "python" else shutil.which("node")
        if not executable:
            raise FileNotFoundError("Node.js companion runtime unavailable")
        script = HERE / ("companion_worker.py" if backend == "python" else "companion_worker.mjs")
        self.errors = tempfile.TemporaryFile()
        self.process = subprocess.Popen([executable, str(script), core, str(key_path), str(side)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.errors)
        self.lines = queue.Queue(maxsize=1)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        while True:
            line = self.process.stdout.readline(32769)
            self.lines.put(line)
            if not line or len(line) > 32768:
                break

    def call(self, op, data=b""):
        self.process.stdin.write(json.dumps({"op": op, "data": data.hex()}).encode() + b"\n")
        self.process.stdin.flush()
        try:
            line = self.lines.get(timeout=10)
        except queue.Empty:
            raise TimeoutError("companion library deadline") from None
        if not line or len(line) > 32768:
            self.errors.seek(0)
            raise RuntimeError("companion library failed or exceeded output bound: " + self.errors.read(4096).decode(errors="replace"))
        result = json.loads(line)
        if set(result) != {"frames", "messages"}:
            raise ValueError("invalid companion result")
        return [bytes.fromhex(f) for f in result["frames"]], [bytes.fromhex(m) for m in result["messages"]]

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill(); self.process.wait(timeout=3)
        self.reader.join(1)
        self.process.stdin.close(); self.process.stdout.close()
        self.errors.close()


class Channel:
    def __init__(self, connection, datagram, peer=None):
        self.connection, self.datagram, self.peer = connection, datagram, peer
        self.buffer = bytearray()

    def send(self, frames):
        for frame in frames:
            if self.peer is None:
                self.connection.sendall(frame)
            else:
                self.connection.sendto(frame, self.peer)

    def receive(self):
        if self.datagram:
            frame, peer = self.connection.recvfrom(4097)
            if self.peer is not None and peer != self.peer:
                raise ValueError("unexpected native application peer")
            return frame
        while True:
            if len(self.buffer) >= 32:
                size = struct.unpack_from("!I", self.buffer, 28)[0] + 48
                if self.buffer[:4] != b"S6NA" or not 48 <= size <= 4096:
                    raise ValueError("invalid S6NA carrier frame")
                if len(self.buffer) >= size:
                    frame = bytes(self.buffer[:size]); del self.buffer[:size]
                    return frame
            data = self.connection.recv(4096)
            if not data:
                raise EOFError("native stream closed")
            self.buffer.extend(data)


def exchange(adapter, channel, payload):
    frames, messages = adapter.call("send", payload)
    channel.send(frames)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            frame = channel.receive()
        except socket.timeout:
            frames, messages = adapter.call("tick")
        else:
            frames, messages = adapter.call("receive", frame)
        channel.send(frames)
        if messages:
            if len(messages) != 1:
                raise ValueError("unexpected companion application message count")
            return messages[0]
    raise TimeoutError("companion application round trip deadline")
