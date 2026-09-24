#!/usr/bin/env python3
"""Bounded, loopback-only iperf3 TCP/UDP pressure matrix for CI runners."""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import shutil
import socket
import subprocess
import time
from pathlib import Path

SCHEMA = "shadow6.iperf3-matrix.v1"
TCP_STREAMS = (1, 2, 4, 8, 12)
UDP_STREAMS = (1, 4, 12)
DIRECTIONS = ("forward", "reverse")
MAX_OUTPUT = 2_000_000


def specs(max_streams: int, families: tuple[int, ...]) -> list[dict]:
    if type(max_streams) is not int or not 1 <= max_streams <= 12:
        raise ValueError("max_streams must be 1..12")
    if not families or any(family not in (4, 6) for family in families):
        raise ValueError("families must contain IPv4 or IPv6")
    return [dict(family=family, direction=direction, protocol=protocol, streams=streams)
            for family in families for direction in DIRECTIONS
            for protocol, choices in (("tcp", TCP_STREAMS), ("udp", UDP_STREAMS))
            for streams in choices if streams <= max_streams]


def loopback(family: int) -> tuple[int, str]:
    return (socket.AF_INET, "127.0.0.1") if family == 4 else (socket.AF_INET6, "::1")


def family_available(family: int) -> bool:
    af, host = loopback(family)
    try:
        with socket.socket(af, socket.SOCK_STREAM) as sock:
            sock.bind((host, 0))
        return True
    except OSError:
        return False


def free_port(family: int) -> int:
    af, host = loopback(family)
    with socket.socket(af, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def iperf_family_available(binary: str, family: int) -> tuple[bool, str]:
    if not family_available(family):
        return False, "OS loopback address family unavailable"
    if family == 4:
        return True, ""
    _, host = loopback(family)
    try:
        probe = subprocess.Popen([binary, "-s", "-6", "-B", host, "-p",
                                  str(free_port(family)), "-1"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    except OSError as error:
        return False, f"iperf3 IPv6 listener unavailable: {error}"
    try:
        time.sleep(0.5)
        if probe.poll() is not None:
            _, stderr = probe.communicate(timeout=3)
            return False, f"iperf3 IPv6 listener unavailable: {stderr[-300:]}"
        return True, ""
    finally:
        if probe.poll() is None:
            probe.terminate()
            try:
                probe.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                probe.kill()
                probe.communicate(timeout=3)


def metric(document: dict, protocol: str) -> dict:
    end = document.get("end", {})
    if protocol == "tcp":
        received = end.get("sum_received", {})
        sent = end.get("sum_sent", {})
        value = received.get("bits_per_second")
        extra = {"retransmits": sent.get("retransmits")}
    else:
        received = end.get("sum", end.get("sum_received", {}))
        value = received.get("bits_per_second")
        extra = {"lost_percent": received.get("lost_percent"),
                 "jitter_ms": received.get("jitter_ms")}
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError("missing or invalid received throughput")
    intervals = [part.get("sum", {}).get("bits_per_second") for part in document.get("intervals", [])]
    intervals = [value for value in intervals if type(value) in (int, float) and math.isfinite(value)]
    return {"throughput_bps": value, "bytes_received": received.get("bytes"),
            "interval_bps": intervals, "cpu_percent": end.get("cpu_utilization_percent", {}), **extra}


def run_case(binary: str, spec: dict, duration: int, udp_aggregate_bps: int | None,
             raw_dir: Path) -> dict:
    row = dict(spec)
    _, host = loopback(spec["family"])
    port = free_port(spec["family"])
    server: subprocess.Popen[str] | None = None
    family_flag = "-4" if spec["family"] == 4 else "-6"
    command = [binary, family_flag, "-c", host, "-p", str(port), "-P", str(spec["streams"]),
               "-t", str(duration), "--json"]
    if spec["direction"] == "reverse":
        command.append("-R")
    if spec["protocol"] == "udp":
        assert udp_aggregate_bps is not None
        rate = max(1, udp_aggregate_bps // spec["streams"])
        command.extend(("-u", "-b", str(rate)))
        row["udp_target_aggregate_bps"] = rate * spec["streams"]
    row["command"] = command
    row["duration_requested_seconds"] = duration
    started = time.monotonic()
    try:
        server = subprocess.Popen([binary, "-s", family_flag, "-B", host, "-p", str(port), "-1"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        time.sleep(0.5)
        if server.poll() is not None:
            raise RuntimeError("iperf3 server exited before client started")
        client = subprocess.run(command, capture_output=True, text=True,
                                timeout=duration + 30, check=False)
        if len(client.stdout) > MAX_OUTPUT or len(client.stderr) > MAX_OUTPUT:
            raise ValueError("iperf3 output exceeded 2 MB limit")
        row["exit_code"] = client.returncode
        if client.returncode:
            raise RuntimeError(client.stderr[-1200:] or client.stdout[-1200:])
        document = json.loads(client.stdout)
        if "error" in document:
            raise RuntimeError(str(document["error"])[:1200])
        name = f"{spec['protocol']}-ipv{spec['family']}-{spec['direction']}-p{spec['streams']}"
        (raw_dir / f"{name}.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                                               encoding="utf-8")
        row.update(metric(document, spec["protocol"]))
        row["raw_file"] = f"raw/{name}.json"
        row["status"] = "ok"
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        row.update(status="failed", reason=str(error)[-1200:])
    finally:
        row["elapsed_seconds"] = time.monotonic() - started
        if server is not None:
            if server.poll() is None:
                server.terminate()
            try:
                _, stderr = server.communicate(timeout=3)
                row["server_exit_code"] = server.returncode
                if row["status"] != "ok" and stderr:
                    row["server_stderr"] = stderr[-1200:]
            except subprocess.TimeoutExpired:
                server.kill()
                server.communicate(timeout=3)
                row.update(status="failed", reason="iperf3 server did not exit")
    return row


def udp_rate(tcp_rows: list[dict], family: int, direction: str, cap_mbps: int) -> int:
    valid = [row["throughput_bps"] for row in tcp_rows
             if row["family"] == family and row["direction"] == direction
             and row["protocol"] == "tcp" and row["status"] == "ok"]
    # At most half of the observed TCP loopback rate, capped to avoid UDP
    # packet storms on small hosted runners. A missing TCP result is a gate
    # failure; use a modest bounded rate to preserve UDP diagnostics.
    return int(min(max(valid) * 0.5 if valid else 100_000_000, cap_mbps * 1_000_000))


def render(report: dict) -> str:
    lines = ["# iperf3 local loopback matrix", "",
             f"- Platform: {report['environment']['platform']}",
             f"- iperf3: {report['environment']['iperf3_version']}",
             f"- Logical CPUs: {report['environment']['logical_cpus']}",
             f"- Cases: {len(report['results'])}; status: {report['status']}",
             "- All listeners bind to 127.0.0.1 or ::1. Results exclude Shadow6 and external NICs.",
             "- A stream count is a TCP/UDP connection count, not a CPU core count.", "",
             "| IP | Protocol | Direction | Streams | Status | Gbit/s | Retransmits / UDP loss % | Raw JSON |",
             "| --- | --- | --- | ---: | --- | ---: | ---: | --- |"]
    for row in report["results"]:
        rate = f"{row['throughput_bps'] / 1e9:.3f}" if row["status"] == "ok" else "—"
        reliability = row.get("retransmits") if row["protocol"] == "tcp" else row.get("lost_percent")
        detail = str(reliability) if reliability is not None else "—"
        raw = f"[{row['raw_file']}]({row['raw_file']})" if row.get("raw_file") else "—"
        lines.append(f"| IPv{row['family']} | {row['protocol'].upper()} | {row['direction']} | "
                     f"{row['streams']} | {row['status']} | {rate} | {detail} | {raw} |")
    failures = [row for row in report["results"] if row["status"] != "ok"]
    if failures:
        lines.extend(("", "## Incomplete cases", ""))
        for row in failures:
            lines.append(f"- IPv{row['family']} {row['protocol']} {row['direction']} "
                         f"P{row['streams']}: {row.get('reason', row['status'])}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--duration", type=int, default=6)
    parser.add_argument("--max-streams", type=int, default=12)
    parser.add_argument("--udp-cap-mbps", type=int, default=2000)
    parser.add_argument("--families", choices=("4", "6", "both"), default="both")
    parser.add_argument("--allow-missing", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.duration <= 15 or not 1 <= args.max_streams <= 12 or not 10 <= args.udp_cap_mbps <= 4000:
        parser.error("duration, streams, or UDP rate exceeds bounded limits")
    families = (4, 6) if args.families == "both" else (int(args.families),)
    cases = specs(args.max_streams, families)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    raw_dir = output / "raw"
    raw_dir.mkdir(exist_ok=True)
    binary = shutil.which("iperf3")
    if binary:
        version_result = subprocess.run([binary, "--version"], capture_output=True, text=True,
                                        timeout=5, check=False)
        version_lines = (version_result.stdout or version_result.stderr).splitlines()
        version = version_lines[0][:160] if version_lines else "unknown"
    else:
        version = "unavailable"
    report = {"schema": SCHEMA, "status": "incomplete", "expected_rows": len(cases),
              "complete": False,
              "environment": {"platform": platform.platform(), "machine": platform.machine(),
                              "logical_cpus": os.cpu_count(), "iperf3_version": version,
                              "commit": os.environ.get("GITHUB_SHA"),
                              "run_id": os.environ.get("GITHUB_RUN_ID"),
                              "runner": os.environ.get("RUNNER_NAME")},
              "parameters": {"duration_seconds": args.duration, "max_streams": args.max_streams,
                             "udp_cap_mbps": args.udp_cap_mbps, "families": families},
              "results": []}
    available = {family: iperf_family_available(binary, family) if binary
                 else (family_available(family), "iperf3 executable not installed")
                 for family in families}
    for spec in cases:
        if not binary:
            row = dict(spec, status="unavailable", reason="iperf3 executable not installed")
        elif not available[spec["family"]][0]:
            row = dict(spec, status="not_applicable", reason=available[spec["family"]][1])
        else:
            target = udp_rate(report["results"], spec["family"], spec["direction"],
                              args.udp_cap_mbps) if spec["protocol"] == "udp" else None
            row = run_case(binary, spec, args.duration, target, raw_dir)
        report["results"].append(row)
        print(f"IPv{row['family']} {row['protocol']} {row['direction']} P{row['streams']}: {row['status']}", flush=True)
        (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (output / "report.md").write_text(render(report), encoding="utf-8")
    statuses = {row["status"] for row in report["results"]}
    report["status"] = "failed" if "failed" in statuses else "unavailable" if "unavailable" in statuses else "ok"
    report["complete"] = True
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "report.md").write_text(render(report), encoding="utf-8")
    if report["status"] == "unavailable" and args.allow_missing:
        return 0
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
