#!/usr/bin/env python3
"""Bounded throughput/long-flow matrix, separate from the 4-byte CI gate."""
from __future__ import annotations
import argparse, json, os, platform, subprocess, sys, time
from pathlib import Path
from benchmark import BACKENDS, execute, network_result

ROOT = Path(__file__).resolve().parents[1]
ENGINES = ("go", "rust", "zig", "ada", "d", "nim", "cpp", "pony", "hare", "carp", "gleam", "idris")
PAYLOADS = (4096, 65536, 1048576)
CONDITIONS = ((0, 0), (20, 0), (80, 1), (150, 3))
STREAM_BYTES = 16 * 1024 * 1024

def cases(stream_bytes: int = STREAM_BYTES):
    if type(stream_bytes) is not int or not 1048576 <= stream_bytes <= 1073741824:
        raise ValueError("stream_bytes must be 1 MiB..1 GiB")
    for payload in PAYLOADS:
        for rtt_ms, loss_percent in CONDITIONS:
            requests = min(100000,max(1, stream_bytes // payload))
            # Same effective byte budget for every engine/backend; keep the
            # artificial pacing below 30 s and native sessions below 300 s.
            if rtt_ms: requests=min(requests,max(1,int(30000/(rtt_ms*(1+loss_percent/100)))))
            yield {"payload_bytes": payload, "requests": requests,
                   "stream_bytes": payload * requests, "rtt_ms": rtt_ms,
                   "loss_percent": loss_percent}

def run(engines, stream_bytes=STREAM_BYTES, targets=None, backends=BACKENDS, concurrency=(1,4,8)):
    unknown = set(engines) - set(ENGINES)
    if unknown or not engines or len(engines) != len(set(engines)):
        raise ValueError("unknown, empty, or duplicate engine selection")
    if not backends or len(set(backends)) != len(backends) or set(backends)-set(BACKENDS):
        raise ValueError("invalid backend selection")
    if not concurrency or any(type(n) is not int or not 1<=n<=8 for n in concurrency) or len(set(concurrency))!=len(concurrency):
        raise ValueError("invalid concurrency selection")
    workloads = list(cases(stream_bytes))
    rows=[]; python=os.environ.get("PYTHON") or sys.executable
    selected = targets if targets is not None else [{"name":"local-"+engine,"core":engine} for engine in engines]
    if not selected or len(selected)>32 or (targets is not None and any(not isinstance(item,dict) or set(item)!={"name","core","endpoint"} for item in selected)):
        raise ValueError("invalid or excessive external targets")
    for target in selected:
        engine=target["core"]
        if engine not in engines or not isinstance(target["name"],str) or not 1<=len(target["name"])<=64:
            raise ValueError("invalid external target")
        for backend in backends:
            for workers in concurrency:
                for case in workloads:
                    row={"target":target["name"],"engine":"shadow6-"+engine,"backend":backend,
                         "concurrency":workers,"concurrency_scope":"independent-native-trios",**case}
                    row["aggregate_stream_bytes"]=case["stream_bytes"]*workers
                    if "endpoint" in target and (backend!="native" or workers!=1 or case["rtt_ms"] or case["loss_percent"]):
                        row.update(status="not_applicable",reason="external endpoints support native backend, concurrency 1, and no local pacing only")
                        rows.append(row); continue
                    command=[python,str(ROOT/"integration/stack_test.py"),"--engine","shadow6-"+engine,
                             "--backend",backend,"--benchmark","--payload-bytes",str(case["payload_bytes"]),
                             "--requests",str(case["requests"]),"--concurrency",str(workers),
                             "--rtt-ms",str(case["rtt_ms"]),"--loss-percent",str(case["loss_percent"])]
                    if "endpoint" in target:
                        command += ["--external-proxy",target["endpoint"]]
                    started=time.perf_counter()
                    try:
                        code,out,err,usage=execute(command,240)
                        row.update(status="ok" if code==0 else "failed",returncode=code,process=usage,
                                   elapsed_seconds=time.perf_counter()-started,stderr=err[-2048:])
                        if code==0:
                            row["network"]=network_result(out,engine,backend,{**case,"concurrency":workers})
                        else:
                            row["stdout"]=out[-2048:]
                    except (OSError,ValueError,KeyError,IndexError) as error:
                        row.update(status="failed",reason=str(error))
                    rows.append(row)
    return {"schema":"shadow6.performance-matrix.v1",
            "environment":{"platform":platform.platform(),"model":"application-response-pacing-v2", "packet_loss_injected":False,
             "commit":os.environ.get("GITHUB_SHA"),"runner":os.environ.get("RUNNER_NAME"),
             "note":"Identical payload/request/condition/concurrency cases for all 12 x 3 paths. Disabled deployment settings do not suppress tests. Local library IPC is included for both companions; no qdisc or route changes."},
            "stream_bytes":stream_bytes,"expected_rows":len(selected)*len(backends)*len(concurrency)*len(workloads),"results":rows}
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--core",action="append",choices=ENGINES)
    parser.add_argument("--stream-bytes",type=int,default=STREAM_BYTES)
    parser.add_argument("--output",default="performance-matrix.json")
    parser.add_argument("--external-config")
    parser.add_argument("--backend",action="append",choices=BACKENDS)
    parser.add_argument("--concurrency",action="append",type=int)
    args=parser.parse_args(); targets=None
    if args.external_config:
        document=json.loads(Path(args.external_config).read_text(encoding="utf-8"))
        if not isinstance(document,dict) or set(document)!={"version","targets"} or document["version"]!=1 or not isinstance(document["targets"],list):
            parser.error("invalid external config")
        targets=document["targets"]
    result=run(args.core or list(ENGINES),args.stream_bytes,targets,args.backend or BACKENDS,args.concurrency or (1,4,8))
    data=json.dumps(result,sort_keys=True,indent=2)+"\n"
    if args.output=="-": print(data,end="")
    else: Path(args.output).write_text(data,encoding="utf-8")
    return 0 if all(row["status"] in {"ok","not_applicable"} for row in result["results"]) else 1

if __name__=="__main__": raise SystemExit(main())
