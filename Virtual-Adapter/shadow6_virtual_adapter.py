#!/usr/bin/env python3
"""Small fail-closed TUN/TAP carrier; interface provisioning stays external."""
from __future__ import annotations
import argparse, json, os, selectors, socket, stat, sys, time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'Network-Adapter'))
from shadow6_network import DatagramEndpoint, load_key, load_limits, _bounded_owned_text, _reject_float, _unique_pairs

@dataclass(frozen=True)
class Config:
    mode:str; core:str; interface_fd:int; bind_host:str; bind_port:int
    peer_host:str; peer_port:int; key_file:Path; limits_file:Path|None
    mtu:int=1400; max_packets_per_tick:int=64
    side:int=0

def load_config(path:Path)->Config:
    value=json.loads(_bounded_owned_text(path,32768),object_pairs_hook=_unique_pairs,
                     parse_float=_reject_float,parse_constant=_reject_float)
    required={"schema","mode","core","interface_fd","bind_host","bind_port","peer_host","peer_port","key_file"}
    optional={"limits_file","mtu","max_packets_per_tick","side"}
    if type(value) is not dict or set(value)-required-optional or not required<=set(value) or value["schema"]!="shadow6.virtual-adapter.v1": raise ValueError("unknown virtual-adapter field")
    mode=value["mode"]
    if mode not in ("tun","tap"): raise ValueError("mode must be tun or tap")
    for name in ("bind_host","peer_host"):
        if type(value[name]) is not str or not value[name] or len(value[name])>253: raise ValueError(f"invalid {name}")
        socket.getaddrinfo(value[name],None,0,socket.SOCK_DGRAM,0,socket.AI_NUMERICHOST)
    for name,low,high in (("interface_fd",0,1<<20),("bind_port",0,65535),("peer_port",1,65535),("mtu",576,9000),("max_packets_per_tick",1,256),("side",0,1)):
        item=value.get(name,Config.__dataclass_fields__[name].default)
        if type(item) is not int or not low<=item<=high: raise ValueError(f"invalid {name}")
    key=Path(value["key_file"]); limits=Path(value["limits_file"]) if value.get("limits_file") else None
    if not key.is_absolute() or (limits and not limits.is_absolute()): raise ValueError("secret and limits paths must be absolute")
    return Config(mode,value["core"],value["interface_fd"],value["bind_host"],value["bind_port"],
                  value["peer_host"],value["peer_port"],key,limits,value.get("mtu",1400),value.get("max_packets_per_tick",64),value.get("side",0))

def validate_packet(mode:str,packet:bytes,mtu:int)->None:
    if not packet or len(packet)>mtu+18: raise ValueError("packet outside configured MTU")
    if mode=="tun" and packet[0]>>4 not in (4,6): raise ValueError("TUN packet is not IPv4 or IPv6")
    if mode=="tap" and len(packet)<14: raise ValueError("truncated Ethernet frame")

def run(config:Config)->None:
    os.fstat(config.interface_fd)
    endpoint=DatagramEndpoint(config.core,load_key(config.key_file),(config.bind_host,config.bind_port),
                              (config.peer_host,config.peer_port),side=config.side,limits=load_limits(config.limits_file))
    selector=selectors.DefaultSelector()
    selector.register(endpoint.socket,selectors.EVENT_READ,"carrier")
    blocking=os.get_blocking(config.interface_fd)
    os.set_blocking(config.interface_fd,False)
    pending=None; received=deque(); registered=False
    try:
        while True:
            mask=(selectors.EVENT_READ if pending is None else 0) | (selectors.EVENT_WRITE if received else 0)
            if mask:
                if registered: selector.modify(config.interface_fd,mask,"interface")
                else: selector.register(config.interface_fd,mask,"interface"); registered=True
            elif registered:
                selector.unregister(config.interface_fd); registered=False
            for key,events in selector.select(.05):
                if key.data != "interface": continue
                if events & selectors.EVENT_READ:
                    for _ in range(config.max_packets_per_tick):
                        try: packet=os.read(config.interface_fd,config.mtu+19)
                        except BlockingIOError: break
                        if not packet: raise EOFError("virtual interface closed")
                        validate_packet(config.mode,packet,config.mtu)
                        try: endpoint.send(0,packet)
                        except BufferError: pending=packet; break
                if events & selectors.EVENT_WRITE:
                    for _ in range(min(len(received),config.max_packets_per_tick)):
                        try: count=os.write(config.interface_fd,received[0])
                        except BlockingIOError: break
                        if count != len(received[0]): raise OSError("partial virtual-interface packet write")
                        received.popleft()
            # poll returns (completed packets, extension events), not packets
            # directly. Carrier readiness wakes this loop without a 50 ms wait.
            completed,_events=endpoint.poll(0)
            for stream,packet in completed:
                if stream!=0: raise ValueError("virtual adapter received a non-packet stream")
                validate_packet(config.mode,packet,config.mtu)
                if len(received)>=256: raise BufferError("virtual-interface receive queue exhausted")
                received.append(packet)
            if pending is not None:
                try: endpoint.send(0,pending); pending=None
                except BufferError: pass
    finally:
        endpoint.close(); selector.close(); os.set_blocking(config.interface_fd,blocking)

def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("--config",type=Path,required=True); args=parser.parse_args()
    try: run(load_config(args.config)); return 0
    except (OSError,ValueError,PermissionError,TimeoutError,BufferError,EOFError) as exc: print(f"virtual adapter: {exc}",file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
