#!/usr/bin/env python3
"""Bounded loopback Virtual Broker UDP relay benchmark; no native Core is implied."""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import math
import os
import socket
import struct
import sys
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"Public6"))
from virtual_broker import Broker, Config, Tenant, canonical  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402


async def measure(core,carrier,anonymous,requests,payload_bytes):
    loop=asyncio.get_running_loop()
    class Echo(asyncio.DatagramProtocol):
        def connection_made(self,transport): self.transport=transport
        def datagram_received(self,data,source): self.transport.sendto(data,source)
    upstream,_=await loop.create_datagram_endpoint(Echo,local_addr=("127.0.0.1",0))
    target=("127.0.0.1",upstream.get_extra_info("sockname")[1])
    key=Ed25519PrivateKey.generate()
    public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    tenant=Tenant("bench",(public,),"default-approved",2,1<<30,1<<30)
    config=Config("127.0.0.1",1,os.urandom(32),{core:target},{"bench":tenant},{("bench",core):target},
                  True,True,None,frozenset(),4096,5,5)
    broker=Broker(config)
    ready=loop.create_future()
    listener=asyncio.create_task(broker.serve_datagrams(0,"bench",core,carrier,anonymous,ready))
    client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); client.setblocking(False)
    payload=b"x"*payload_bytes
    latencies=[]
    try:
        port=await asyncio.wait_for(ready,2)
        started=time.perf_counter()
        for _ in range(requests):
            if anonymous:
                wire=payload
            else:
                now=int(time.time())
                admission={"schema":"shadow6.virtual-broker-admission.v1","tenant":"bench","client":"bench",
                    "core":core,"issued":now,"expires":now+60,"nonce":base64.b64encode(os.urandom(32)).decode(),
                    "public_key":base64.b64encode(public).decode()}
                admission["signature"]=base64.b64encode(key.sign(canonical(admission))).decode()
                encoded=canonical(admission)
                wire=struct.pack("!H",len(encoded))+encoded+payload
            before=time.perf_counter()
            await loop.sock_sendto(client,wire,("127.0.0.1",port))
            reply=await asyncio.wait_for(loop.sock_recv(client,4097),5)
            if reply!=payload: raise RuntimeError("datagram payload mismatch")
            latencies.append(time.perf_counter()-before)
        elapsed=time.perf_counter()-started
        return {"core":core,"carrier":carrier,"anonymous":anonymous,"requests":requests,
                "payload_bytes":payload_bytes,"duration_seconds":elapsed,
                "throughput_bps":requests*payload_bytes*8/elapsed,
                "latency_p95_seconds":sorted(latencies)[math.ceil(requests*.95)-1],"status":"ok"}
    finally:
        listener.cancel(); await asyncio.gather(listener,return_exceptions=True)
        client.close(); upstream.close()


async def run(requests,payload_bytes):
    rows=[]
    for core in ("hare","carp","pony","idris"):
        for carrier in ("gate","s6na"):
            for anonymous in (False,True):
                rows.append(await measure(core,carrier,anonymous,requests,payload_bytes))
    return {"schema":"shadow6.virtual-broker-datagram-benchmark.v1",
            "scope":"loopback Virtual Broker UDP relay to echo target; carrier and Core binaries are not exercised",
            "expected_rows":16,"results":rows}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--requests",type=int,default=32)
    parser.add_argument("--payload-bytes",type=int,default=256)
    parser.add_argument("--output",default="-")
    args=parser.parse_args()
    if not 1<=args.requests<=1024 or not 1<=args.payload_bytes<=2048:
        parser.error("requests must be 1..1024 and payload bytes 1..2048")
    report=asyncio.run(run(args.requests,args.payload_bytes))
    data=json.dumps(report,indent=2,sort_keys=True)+"\n"
    if args.output=="-": print(data,end="")
    else: Path(args.output).write_text(data,encoding="utf-8")


if __name__=="__main__": main()
