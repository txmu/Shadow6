#!/usr/bin/env python3
"""Bounded, fixed-command benchmark runner for Shadow6 cores.

Configuration is JSON and commands are assembled from validated argument lists;
shell interpretation is deliberately never used.
"""
from __future__ import annotations
import argparse, json, os, resource, subprocess, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE_PATHS = {
    "go": "Core-Go/shadow6-go", "rust": "Core-Rust/shadow6-rust",
    "zig": "Core-Zig/shadow6-zig", "ada": "Core-Ada/shadow6-ada",
    "d": "Core-D/shadow6-d", "nim": "Core-Nim/shadow6-nim",
    "cpp": "Core-Cpp/shadow6-cpp", "pony": "Core-Pony/shadow6-pony",
    "hare": "Core-Hare/shadow6-hare", "carp": "Core-Carp/shadow6-carp",
    "gleam": "Core-Gleam/shadow6-gleam", "idris": "Core-Idris/shadow6-idris",
}
ROLES = {"feature-report": ["--feature-report"], "version": ["--version"], "loopback": ["--loopback-test"]}

def _load_config(path: str | None) -> dict:
    if not path: return {"cores": list(CORE_PATHS), "roles": ["feature-report"], "repeats": 1, "args": {}}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) - {"cores", "roles", "repeats", "args"}: raise ValueError("unknown benchmark fields")
    repeats = data.get("repeats", 1)
    if not isinstance(repeats, int) or not 1 <= repeats <= 1000: raise ValueError("repeats must be 1..1000")
    cores = data.get("cores", list(CORE_PATHS)); roles = data.get("roles", ["feature-report"])
    if not isinstance(cores, list) or not all(isinstance(x, str) and x in CORE_PATHS for x in cores): raise ValueError("unknown core")
    if not isinstance(roles, list) or not all(isinstance(x, str) and x in ROLES for x in roles): raise ValueError("unknown role")
    args = data.get("args", {})
    if not isinstance(args, dict) or any(not isinstance(k, str) or not isinstance(v, list) or not all(isinstance(a, str) for a in v) for k,v in args.items()): raise ValueError("args must map core/role to string arrays")
    return {"cores": cores, "roles": roles, "repeats": repeats, "args": args}

def run(config: dict) -> dict:
    rows = []
    for core in config["cores"]:
        exe = (ROOT / CORE_PATHS[core]).resolve()
        if not exe.is_file() or not os.access(exe, os.X_OK):
            rows.append({"core": core, "status": "unavailable", "path": str(exe)}); continue
        for role in config["roles"]:
            extra = config["args"].get(core, []) + config["args"].get(role, [])
            command = [str(exe), *ROLES[role], *extra]
            for repeat in range(config["repeats"]):
                before = resource.getrusage(resource.RUSAGE_CHILDREN)
                start = time.perf_counter_ns()
                p = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120, check=False)
                elapsed = (time.perf_counter_ns() - start) / 1e9
                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                native = None
                try:
                    native = json.loads(p.stdout) if p.stdout.strip().startswith("{") else None
                except json.JSONDecodeError: pass
                rows.append({"core": core, "role": role, "repeat": repeat + 1, "status": "ok" if p.returncode == 0 else "failed", "returncode": p.returncode, "elapsed_seconds": elapsed, "user_seconds": after.ru_utime-before.ru_utime, "system_seconds": after.ru_stime-before.ru_stime, "max_rss_kib": max(0, after.ru_maxrss), "native": native, "stderr": p.stderr[-2048:]})
    return {"schema": "shadow6.benchmark.v1", "config": config, "results": rows}

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--config"); ap.add_argument("--role", choices=sorted(ROLES)); ap.add_argument("--output", default="-")
    ns = ap.parse_args()
    try:
        config = _load_config(ns.config)
        if ns.role: config["roles"] = [ns.role]
        result = run(config)
    except (OSError, ValueError, json.JSONDecodeError) as exc: ap.error(str(exc))
    payload = json.dumps(result, sort_keys=True, ensure_ascii=True)
    if ns.output == "-": print(payload)
    else: Path(ns.output).write_text(payload + "\n", encoding="utf-8")
    return 0
if __name__ == "__main__": raise SystemExit(main())
