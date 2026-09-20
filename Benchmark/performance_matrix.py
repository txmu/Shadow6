#!/usr/bin/env python3
"""Bounded throughput/long-flow matrix, separate from the 4-byte CI gate."""
from __future__ import annotations
import argparse, json, os, platform, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINES = ("go", "rust", "zig", "ada", "d", "nim", "cpp", "pony", "hare", "carp", "gleam", "idris")
PAYLOADS = (4096, 65536, 1048576)
CONDITIONS = ((0, 0), (20, 0), (80, 1), (150, 3))
STREAM_BYTES = 16 * 1024 * 1024
BASELINE_ONLY = frozenset(("carp", "gleam"))
FIXED_PAYLOADS = {"d": 4, "pony": 1024, "hare": 978, "idris": 1024}

def cases(stream_bytes: int = STREAM_BYTES):
    if type(stream_bytes) is not int or not 1048576 <= stream_bytes <= 1073741824:
        raise ValueError("stream_bytes must be 1 MiB..1 GiB")
    for payload in PAYLOADS:
        requests = max(1, stream_bytes // payload)
        for rtt_ms, loss_percent in CONDITIONS:
            yield {"payload_bytes": payload, "requests": requests,
                   "stream_bytes": payload * requests, "rtt_ms": rtt_ms,
                   "loss_percent": loss_percent}

def run(engines, stream_bytes=STREAM_BYTES, targets=None):
    unknown = set(engines) - set(ENGINES)
    if unknown or not engines or len(engines) != len(set(engines)):
        raise ValueError("unknown, empty, or duplicate engine selection")
    rows=[]; python=os.environ.get("PYTHON") or sys.executable
    selected = targets or [{"name":"local-"+engine,"core":engine} for engine in engines]
    if len(selected)>32 or (targets is not None and any(not isinstance(item,dict) or set(item)!={"name","core","endpoint"} for item in selected)):
        raise ValueError("invalid or excessive external targets")
    for target in selected:
        engine=target["core"]
        if engine not in ENGINES or not isinstance(target["name"],str) or not 1<=len(target["name"])<=64:
            raise ValueError("invalid external target")
        if engine in FIXED_PAYLOADS:
            payload = FIXED_PAYLOADS[engine]
            requests = min(100000, max(1, stream_bytes // payload))
            engine_cases = ({"payload_bytes":payload,"requests":requests,"stream_bytes":payload*requests,"rtt_ms":0,"loss_percent":0},)
        else:
            engine_cases = cases(stream_bytes)
        for case in engine_cases:
            unsupported = None
            if engine in BASELINE_ONLY and (case["rtt_ms"] or case["loss_percent"]):
                unsupported = "native path does not expose the userspace impairment hook"
            if unsupported:
                rows.append({"target":target["name"],"engine":"shadow6-"+engine,**case,
                             "status":"not_applicable","reason":unsupported})
                continue
            command=[python, str(ROOT/"integration/stack_test.py"), "--engine", "shadow6-"+engine,
                     "--benchmark", "--payload-bytes", str(case["payload_bytes"]),
                     "--requests", str(case["requests"]), "--concurrency", "1",
                     "--rtt-ms", str(case["rtt_ms"]), "--loss-percent", str(case["loss_percent"])]
            if "endpoint" in target:
                if case["rtt_ms"] or case["loss_percent"]: continue
                command += ["--external-proxy", target["endpoint"]]
            started=time.perf_counter()
            completed=subprocess.run(command,cwd=ROOT,text=True,capture_output=True,timeout=1800,check=False)
            row={"target":target["name"],"engine":"shadow6-"+engine,**case,"status":"ok" if completed.returncode==0 else "failed",
                 "elapsed_seconds":time.perf_counter()-started,"stderr":completed.stderr[-2048:]}
            if completed.returncode==0:
                try:
                    suite=json.loads(completed.stdout.splitlines()[-1])
                    row["network"]=suite["results"]["shadow6-"+engine]
                except (ValueError,KeyError,IndexError) as error:
                    row.update(status="failed",reason=f"invalid metrics: {error}")
            else: row["stdout"]=completed.stdout[-2048:]
            rows.append(row)
    return {"schema":"shadow6.performance-matrix.v1",
            "environment":{"platform":platform.platform(),"model":"bounded-userspace-response-v1",
             "note":"RTT/loss recovery are deterministic userspace impairments; no qdisc or route is changed."},
            "stream_bytes":stream_bytes,"results":rows}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--core",action="append",choices=ENGINES)
    parser.add_argument("--stream-bytes",type=int,default=STREAM_BYTES)
    parser.add_argument("--output",default="performance-matrix.json")
    parser.add_argument("--external-config")
    args=parser.parse_args(); targets=None
    if args.external_config:
        document=json.loads(Path(args.external_config).read_text(encoding="utf-8"))
        if not isinstance(document,dict) or set(document)!={"version","targets"} or document["version"]!=1 or not isinstance(document["targets"],list):
            parser.error("invalid external config")
        targets=document["targets"]
    result=run(args.core or list(ENGINES),args.stream_bytes,targets)
    data=json.dumps(result,sort_keys=True,indent=2)+"\n"
    if args.output=="-": print(data,end="")
    else: Path(args.output).write_text(data,encoding="utf-8")
    return 0 if all(row["status"] in {"ok","not_applicable"} for row in result["results"]) else 1

if __name__=="__main__": raise SystemExit(main())
