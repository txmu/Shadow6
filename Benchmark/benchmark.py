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
ROLES = {"feature-report": ["--feature-report"], "version": ["--version"], "loopback": ["--loopback-test"], "integration": []}

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
        # A native executable with unresolved shared libraries is unavailable on
        # this host; keep that distinct from an executed test failure.
        if core == "nim":
            deps = subprocess.run(["/usr/bin/ldd", str(exe)], capture_output=True, text=True, check=False)
            if "not found" in deps.stdout:
                rows.append({"core": core, "status": "unavailable", "path": str(exe), "reason": "native dependency missing"}); continue
        for role in config["roles"]:
            extra = config["args"].get(core, []) + config["args"].get(role, [])
            if role == "integration":
                runner = os.environ.get("PYTHON") or (str(ROOT / ".venv/bin/python") if (ROOT / ".venv/bin/python").is_file() else "python3")
                command = [runner, str(ROOT / "integration/stack_test.py"), "--engine", "shadow6-" + core]
            else:
                command = [str(exe), *ROLES[role], *extra]
            for repeat in range(config["repeats"]):
                before = resource.getrusage(resource.RUSAGE_CHILDREN)
                start = time.perf_counter_ns()
                p = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=240 if role == "integration" else 120, check=False)
                elapsed = (time.perf_counter_ns() - start) / 1e9
                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                native = None
                try:
                    native = json.loads(p.stdout) if p.stdout.strip().startswith("{") else None
                except json.JSONDecodeError: pass
                metrics = {"payload_bytes": None, "messages": None, "bytes_sent": None, "bytes_received": None,
                           "packets_sent": None, "packets_received": None, "throughput_bps": None,
                           "packets_per_second": None, "latency_avg_seconds": None, "latency_p50_seconds": None,
                           "latency_p95_seconds": None, "latency_p99_seconds": None, "latency_min_seconds": None,
                           "latency_max_seconds": None, "loss_rate": None, "retransmissions": None,
                           "concurrency": None, "duration_seconds": elapsed, "context_switches": None,
                           "io_read_bytes": None, "io_write_bytes": None}
                # Native integration tests may emit a metrics object without
                # changing the wire protocol; preserve only known numeric fields.
                if isinstance(native, dict):
                    candidate = native.get("metrics", native)
                    if isinstance(candidate, dict):
                        for key in metrics:
                            if key in candidate and (candidate[key] is None or isinstance(candidate[key], (int, float))):
                                metrics[key] = candidate[key]
                rows.append({"core": core, "role": role, "repeat": repeat + 1, "status": "ok" if p.returncode == 0 else "failed", "returncode": p.returncode, "elapsed_seconds": elapsed, "user_seconds": after.ru_utime-before.ru_utime, "system_seconds": after.ru_stime-before.ru_stime, "max_rss_kib": max(0, after.ru_maxrss), "native": native, "metrics": metrics, "stderr": p.stderr[-2048:]})
    return {"schema": "shadow6.benchmark.v1", "config": config, "results": rows}

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--config"); ap.add_argument("--role", choices=sorted(ROLES)); ap.add_argument("--repeats", type=int); ap.add_argument("--output", default="-"); ap.add_argument("--format", choices=("json", "txt"), default="json")
    ns = ap.parse_args()
    try:
        config = _load_config(ns.config)
        if ns.role: config["roles"] = [ns.role]
        if ns.repeats is not None:
            if not 1 <= ns.repeats <= 1000: raise ValueError("repeats must be 1..1000")
            config["repeats"] = ns.repeats
        result = run(config)
    except (OSError, ValueError, json.JSONDecodeError) as exc: ap.error(str(exc))
    payload = json.dumps(result, sort_keys=True, ensure_ascii=True)
    text_payload = "Shadow6 Benchmark schema=shadow6.benchmark.v1\n" + "core\trole\trepeat\tstatus\telapsed_seconds\tcpu_seconds\tmax_rss_kib\tthroughput_bps\tlatency_p95_seconds\tloss_rate\treturncode\n"
    text_payload += "\n".join("{c}\t{r}\t{n}\t{s}\t{e:.6f}\t{u:.6f}\t{m}\t{t}\t{l}\t{o}\t{x}".format(c=row["core"], r=row.get("role", "-"), n=row.get("repeat", "-"), s=row["status"], e=row.get("elapsed_seconds", 0), u=row.get("user_seconds", 0)+row.get("system_seconds", 0), m=row.get("max_rss_kib", "-"), t=row.get("metrics", {}).get("throughput_bps", "-"), l=row.get("metrics", {}).get("latency_p95_seconds", "-"), o=row.get("metrics", {}).get("loss_rate", "-"), x=row.get("returncode", "-")) for row in result["results"]) + "\n"
    output_payload = payload if ns.format == "json" else text_payload
    if ns.output == "-": print(output_payload, end="" if output_payload.endswith("\n") else "\n")
    else:
        Path(ns.output).write_text(output_payload + ("" if output_payload.endswith("\n") else "\n"), encoding="utf-8")
        report = Path(ns.output).with_suffix(".md")
        lines = ["# Shadow6 Benchmark Report", "", "真实原生进程实测结果；`unavailable`/`failed` 未被转换为成功。", "", "| Core | Role | Repeat | Status | Seconds | CPU s | Peak RSS KiB |", "|---|---|---:|---|---:|---:|---:|"]
        for row in result["results"]:
            lines.append("| {core} | {role} | {repeat} | {status} | {elapsed:.6f} | {cpu:.6f} | {rss} |".format(core=row["core"], role=row.get("role", "-"), repeat=row.get("repeat", "-"), status=row["status"], elapsed=row.get("elapsed_seconds", 0), cpu=row.get("user_seconds", 0)+row.get("system_seconds", 0), rss=row.get("max_rss_kib", "-")))
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0
if __name__ == "__main__": raise SystemExit(main())
