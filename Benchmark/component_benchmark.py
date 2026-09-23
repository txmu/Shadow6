#!/usr/bin/env python3
"""Comparable, bounded component workloads; separate from native Core rankings."""
from __future__ import annotations
import argparse
import asyncio
import base64
import heapq
import json
import math
import os
from pathlib import Path
import platform
import shutil
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/"Network-Adapter"),str(ROOT/"Public6"),str(ROOT/"Tools")]
from python_runtime import runtime_report
from benchmark import CORE_PATHS, execute
from shadow6_network import ReliableAdapter
from virtual_broker import Broker, Config, Tenant, canonical
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def workloads(payloads=(4096,65536,1048576),concurrency=(1,4,8),flow_bytes=1048576):
    if type(flow_bytes) is not int or not 1024<=flow_bytes<=16777216: raise ValueError("flow outside 1 KiB..16 MiB")
    if not payloads or not concurrency or len(set(payloads))!=len(payloads) or len(set(concurrency))!=len(concurrency): raise ValueError("empty or duplicate workload")
    for size in payloads:
        if type(size) is not int or not 1<=size<=1048576: raise ValueError("invalid payload")
        for workers in concurrency:
            if type(workers) is not int or not 1<=workers<=8: raise ValueError("invalid concurrency")
            requests=max(1,math.ceil(flow_bytes/(size*workers)))
            if requests>4096: raise ValueError("too many requests")
            yield dict(payload_bytes=size,concurrency=workers,requests=requests,
                       useful_bytes=size*workers*requests)


def adapter_case(spec):
    now=[0.0]; clock=lambda:now[0]
    left=ReliableAdapter(spec["core"],bytes(32),0,clock=clock)
    right=ReliableAdapter(spec["core"],bytes(32),1,clock=clock)
    payload=b"a"*spec["payload_bytes"]
    delivered=transmissions=retransmissions=dropped=0
    started=time.perf_counter()
    for _ in range(spec["requests"]):
        queue=[]; seen=set(); received=set(); ordinal=0
        for stream in range(spec["concurrency"]): queue.extend(left.send(stream,payload))
        turns=0
        while len(received)<spec["concurrency"] or left.buffered:
            turns+=1
            if turns>1000000: raise RuntimeError("bounded transfer did not finish")
            if spec["reorder"]: queue.reverse()
            for wire in queue:
                transmissions+=1; identity=wire[8:28]
                if identity not in seen:
                    seen.add(identity); ordinal+=1
                    if spec["loss_percent"] and ordinal%math.ceil(100/spec["loss_percent"])==1:
                        dropped+=1; continue
                else: retransmissions+=1
                acks,messages,_=right.receive(wire)
                for ack in acks: left.receive(ack)
                for stream,value in messages:
                    if stream in received or value!=payload: raise RuntimeError("duplicate or corrupt application message")
                    received.add(stream); delivered+=len(value)
            queue=left.outbound()
            if not queue and left.buffered:
                now[0]+=1; queue=left.retransmit()
    duration=time.perf_counter()-started
    return dict(duration_seconds=duration,throughput_bps=delivered*8/duration,bytes_received=delivered,
                transmissions=transmissions,retransmissions=retransmissions,dropped=dropped,success_rate=1)


def fixture(target,workers=8):
    key=Ed25519PrivateKey.generate()
    public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    tenant=Tenant("benchmark",(public,),"default-approved",workers,1<<30,1<<30)
    config=Config("127.0.0.1",0,os.urandom(32),{"go":target},{tenant.tenant_id:tenant},
                  {(tenant.tenant_id,"go"):target},True,True,None,frozenset(),65536,5,10)
    return Broker(config),key


def admission(key):
    now=int(time.time())
    request=dict(schema="shadow6.virtual-broker-admission.v1",tenant="benchmark",client="benchmark",
                 core="go",issued=now,expires=now+120,nonce=base64.b64encode(os.urandom(32)).decode(),
                 public_key=base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode())
    request["signature"]=base64.b64encode(key.sign(canonical(request))).decode()
    return canonical(request)


async def virtual_case(spec,path):
    tasks=set()
    async def echo(reader,writer):
        try:
            while data:=await reader.read(65536):
                writer.write(data); await writer.drain()
        finally:
            writer.close(); await writer.wait_closed()
    def tracked(handler):
        def start(reader,writer):
            task=asyncio.create_task(handler(reader,writer)); tasks.add(task); task.add_done_callback(tasks.discard)
        return start
    target=await asyncio.start_server(tracked(echo),"127.0.0.1",0,limit=65536)
    endpoint=target.sockets[0].getsockname()[:2]
    broker,key=fixture(endpoint,spec["concurrency"])
    relay=await asyncio.start_server(tracked(broker.handle),"127.0.0.1",0,limit=65536)
    address=endpoint if path=="direct" else relay.sockets[0].getsockname()[:2]
    barrier=asyncio.Barrier(spec["concurrency"])
    payload=b"a"*spec["payload_bytes"]
    async def lane():
        reader,writer=await asyncio.open_connection(*address)
        try:
            if path=="virtual-broker":
                request=admission(key); writer.write(len(request).to_bytes(4,"big")+request)
            writer.write(b"w"); await writer.drain()
            if await reader.readexactly(1)!=b"w": raise RuntimeError("warmup mismatch")
            await barrier.wait()
            started=time.perf_counter(); latencies=[]
            for _ in range(spec["requests"]):
                before=time.perf_counter(); writer.write(payload); await writer.drain()
                if await reader.readexactly(len(payload))!=payload: raise RuntimeError("relay byte mismatch")
                latencies.append(time.perf_counter()-before)
            return started,time.perf_counter(),latencies
        finally:
            writer.close(); await writer.wait_closed()
    lanes=[]
    try:
        async with asyncio.timeout(60):
            lanes=[asyncio.create_task(lane()) for _ in range(spec["concurrency"])]
            results=await asyncio.gather(*lanes)
        duration=max(r[1] for r in results)-min(r[0] for r in results)
        latencies=sorted(value for r in results for value in r[2])
        return dict(duration_seconds=duration,throughput_bps=spec["useful_bytes"]*8/duration,
                    bytes_received=spec["useful_bytes"],success_rate=1,
                    latency_p95_seconds=latencies[math.ceil(len(latencies)*.95)-1])
    finally:
        for task in lanes: task.cancel()
        await asyncio.gather(*lanes,return_exceptions=True)
        relay.close(); target.close(); await relay.wait_closed(); await target.wait_closed()
        pending=list(tasks)
        for task in pending: task.cancel()
        await asyncio.gather(*pending,return_exceptions=True)


def admission_case(occupancy):
    broker,key=fixture(("127.0.0.1",9))
    expires=int(time.time())+120
    broker.nonces={("benchmark",i.to_bytes(32,"big")):expires for i in range(occupancy)}
    broker.nonce_expiry=[(expires,nonce) for nonce in broker.nonces]; heapq.heapify(broker.nonce_expiry)
    requests=[admission(key) for _ in range(256)]
    started=time.perf_counter()
    for request in requests: broker.admit(request)
    duration=time.perf_counter()-started
    return dict(duration_seconds=duration,admissions_per_second=len(requests)/duration,admissions=len(requests))


def run(components=("adapter","virtual-broker"),cores=tuple(CORE_PATHS),payloads=(4096,65536,1048576),concurrency=(1,4,8),flow_bytes=1048576):
    if set(components)-{"adapter","virtual-broker"} or not components or not cores or set(cores)-set(CORE_PATHS) or len(set(components))!=len(components) or len(set(cores))!=len(cores): raise ValueError("unknown or duplicate component or Core profile")
    loads=list(workloads(payloads,concurrency,flow_bytes)); rows=[]
    def record(row,operation):
        try:
            metrics=operation()
            if row.get("useful_bytes") and metrics.get("bytes_received")!=row["useful_bytes"]: raise ValueError("incomplete workload")
            if not math.isfinite(metrics["duration_seconds"]) or metrics["duration_seconds"]<=0: raise ValueError("invalid duration")
            row.update(status="ok",metrics=metrics)
        except Exception as exc: row.update(status="failed",reason=str(exc))
        rows.append(row)
    if "adapter" in components:
        for core in cores:
            for load in loads:
                for loss,reorder in ((0,False),(0,True),(1,True),(3,True)):
                    spec=dict(core=core,**load,loss_percent=loss,reorder=reorder)
                    for backend in ("python","node"):
                        row=dict(component="adapter",backend=backend,measurement="library-codec-and-recovery",**spec)
                        def operation(backend=backend,spec=spec):
                            if backend=="python": return adapter_case(spec)
                            node=shutil.which("node")
                            if not node: raise RuntimeError("Node.js unavailable")
                            code,out,err,usage=execute([node,str(ROOT/"Benchmark/adapter_worker.mjs"),json.dumps(spec)],60)
                            if code: raise RuntimeError(err[-2048:] or f"worker exit {code}")
                            return json.loads(out)
                        record(row,operation)
    if "virtual-broker" in components:
        for load in loads:
            for path in ("direct","virtual-broker"):
                record(dict(component="virtual-broker",path=path,measurement="tcp-relay",**load),lambda load=load,path=path:asyncio.run(virtual_case(load,path)))
        for occupancy in (0,32768):
            record(dict(component="virtual-broker",measurement="signed-admission",replay_entries=occupancy),lambda occupancy=occupancy:admission_case(occupancy))
    return dict(schema="shadow6.component-benchmark.v1",environment=dict(platform=platform.platform(),python=platform.python_version(),python_runtime=runtime_report(),
                commit=os.environ.get("GITHUB_SHA"),runner=os.environ.get("RUNNER_NAME")),
                scope={"adapter":"same direct-library algorithm; real AEAD and discarded frames; virtual retry clock excludes network wait; no native Core throughput",
                       "virtual-broker":"shared actual Broker TCP relay versus direct loopback echo; signed admission; no Guard/Gate/Core transport performance implied"},
                expected_rows=(len(cores)*len(loads)*8 if "adapter" in components else 0)+(len(loads)*2+2 if "virtual-broker" in components else 0),results=rows)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--component",action="append",choices=("adapter","virtual-broker"))
    parser.add_argument("--core",action="append",choices=tuple(CORE_PATHS))
    parser.add_argument("--payload-bytes",type=int,action="append")
    parser.add_argument("--concurrency",type=int,action="append")
    parser.add_argument("--flow-bytes",type=int,default=1048576)
    parser.add_argument("--output",default="component-benchmark.json")
    args=parser.parse_args()
    result=run(args.component or ("adapter","virtual-broker"),args.core or tuple(CORE_PATHS),args.payload_bytes or (4096,65536,1048576),args.concurrency or (1,4,8),args.flow_bytes)
    data=json.dumps(result,indent=2,sort_keys=True)+"\n"
    if args.output=="-": print(data,end="")
    else: Path(args.output).write_text(data,encoding="utf-8")
    return 0 if all(row["status"]=="ok" for row in result["results"]) else 1


if __name__=="__main__": raise SystemExit(main())
