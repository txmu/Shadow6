"""Isolated library driver; IPC stays local, only S6NA/1 enters Core sockets."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Tools"))
from python_runtime import bootstrap
if __name__ == "__main__":
    bootstrap(Path(__file__).resolve().parents[1], Path(__file__).absolute())
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Network-Adapter"))
from shadow6_network import ReliableAdapter, load_key


def main():
    core, key_path, side = sys.argv[1:]
    adapter = ReliableAdapter(core, load_key(Path(key_path)), int(side))
    for _ in range(1000000):
        line = sys.stdin.buffer.readline(16385)
        if not line:
            return
        if len(line) > 16384 or not line.endswith(b"\n"):
            raise ValueError("oversized library request")
        request = json.loads(line)
        if set(request) != {"op", "data"}:
            raise ValueError("unknown library request fields")
        op, raw = request["op"], bytes.fromhex(request["data"])
        if len(raw) > 4096:
            raise ValueError("oversized library input")
        messages = []
        if op == "send":
            frames = adapter.send(0, raw)
        elif op == "receive":
            frames, messages, events = adapter.receive(raw)
            if events:
                raise ValueError("unexpected extension")
            frames += adapter.outbound()
        elif op == "tick" and not raw:
            frames = adapter.retransmit()
        else:
            raise ValueError("unknown library operation")
        print(json.dumps({"frames": [f.hex() for f in frames],
                          "messages": [data.hex() for stream, data in messages]}), flush=True)


if __name__ == "__main__":
    main()
