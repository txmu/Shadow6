#!/usr/bin/env python3
"""Summarize every performance report.json in the CI artifact."""
from __future__ import annotations
import json, re, sys
from pathlib import Path

def num(v, digits=2):
    return "-" if v is None else f"{float(v):.{digits}f}"

def main(root: Path, out: Path) -> None:
    lines = ["# Shadow6 performance-all | source: GitHub Actions artifact | fmt: Core Proto Dir(F/R) Base? Gbps Loss/Retrans CPU(s) Mem(MB) Errors"]
    reports = sorted(root.rglob("shadow6-linux-iperf-chain/report.json"))
    for path in reports:
        data = json.loads(path.read_text())
        env = data.get("environment", {})
        platform = env.get("platform", data.get("platform", "unknown"))
        arch = env.get("machine", "unknown")
        logical = data.get("logical_cpus", "?")
        title = path.parent.name
        if "linux-iperf-chain" not in str(path):
            continue
        for row in data.get("results", []):
            core = row.get("core") or re.sub(r"^(shadow6-iperf3-|shadow6-)|(-network-benchmark.*|-iperf-chain)$", "", title)
            proto = row.get("protocol", "?")
            direction = "F" if str(row.get("direction", "")).lower().startswith("f") else "R"
            base = bool(row.get("baseline", False))
            bps = row.get("receiver_bps", row.get("throughput_bps"))
            if bps is None: bps = row.get("interval_bps", [None])[-1]
            gbps = None if bps is None else float(bps) / 1e9
            rec = row.get("receiver", {})
            loss = rec.get("lost_percent") if rec else None
            if loss is None and proto == "udp":
                loss = row.get("lost_percent")
            retrans = row.get("retransmits")
            cpu = (row.get("cpu_percent") or {}).get("host_total") if isinstance(row.get("cpu_percent"), dict) else None
            mem = None
            if row.get("roles_after"):
                mem = max((x.get("rss_bytes", 0) for x in row["roles_after"]), default=0) / 1048576
                cpu_values = [x.get("cpu_seconds", 0) for x in row["roles_after"]]
                cpu = sum(cpu_values)
            errors = []
            if row.get("status") not in (None, "ok"): errors.append(str(row.get("status")))
            if row.get("exit_code") not in (None, 0): errors.append(f"exit={row['exit_code']}")
            errors.extend(str(x) for x in row.get("fixture_errors", []))
            lines.append(f"{core} {proto} {direction} {'base' if base else 'node'} {num(gbps)} {num(loss,1) + '%' if loss is not None else '-'} {num(retrans,0)} {num(cpu)} {num(mem)} {','.join(errors) if errors else '-'}")
    out.write_text("\n".join(lines) + "\n")
    print(f"processed {len(reports)} report.json files -> {out}")

if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
