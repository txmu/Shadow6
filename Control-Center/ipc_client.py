"""Fixed Node bridge for all tool transports; endpoint selection is operator-owned."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys

def invoke(root: Path, action: str, request: dict) -> dict:
    if action not in {"catalog", "call", "raw-send"}:
        raise ValueError("unknown IPC action")
    script = root / "Node-IPC/cli.mjs"
    if not script.is_file():
        script = Path(__file__).resolve().parent.parent / "bin/shadow6-ipc"
    if not script.is_file() or script.is_symlink():
        raise ValueError("Node IPC component unavailable")
    argv = ["node", str(script), action]
    if action != "catalog":
        # Never take a configuration/key path from an AI or transport caller.
        config = Path(os.environ.get("SHADOW6_IPC_CONFIG", root / "Node-IPC/local.json"))
        from shadow6_security import secure_read
        secure_read(config, 65536, secret=True)
        argv += ["--config", str(config), "--json-stdin"]
    completed = subprocess.run(argv, input=json.dumps(request, ensure_ascii=True, allow_nan=False),
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=15, check=False, env={**os.environ, "SHADOW6_PYTHON": sys.executable})
    if completed.returncode or len(completed.stdout.encode()) > 1048576:
        raise ValueError("IPC call rejected or unavailable")
    from shadow6_security import strict_json_loads
    return strict_json_loads(completed.stdout, limit=1048576)
