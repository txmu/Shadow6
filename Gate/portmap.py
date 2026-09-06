#!/usr/bin/env python3
"""Bounded one-address-per-port logical E-class Gate maps."""
import argparse,ipaddress,json
from pathlib import Path
MAX=4096;NETWORK=ipaddress.IPv4Network("240.0.0.0/4")
def generate(ports,start="240.0.0.1"):
 if not ports or len(ports)>MAX or len(set(ports))!=len(ports) or any(isinstance(p,bool) or not 1<=p<=65535 for p in ports):raise ValueError("ports must be 1-4096 unique integers")
 first=int(ipaddress.IPv4Address(start));entries=[{"address":str(ipaddress.IPv4Address(first+i)),"port":p} for i,p in enumerate(sorted(ports))]
 return validate({"schema":"shadow6-gate-portmap-v1","entries":entries})
def validate(doc):
 if set(doc)!={"schema","entries"} or doc["schema"]!="shadow6-gate-portmap-v1" or not isinstance(doc["entries"],list) or len(doc["entries"])>MAX:raise ValueError("invalid port map")
 addresses=set();ports=set()
 for item in doc["entries"]:
  if set(item)!={"address","port"}:raise ValueError("invalid map entry")
  ip=ipaddress.IPv4Address(item["address"]);port=item["port"]
  if ip not in NETWORK or not isinstance(port,int) or isinstance(port,bool) or not 1<=port<=65535 or ip in addresses or port in ports:raise ValueError("map must be one-to-one within E-class")
  addresses.add(ip);ports.add(port)
 return doc
def main():
 p=argparse.ArgumentParser();s=p.add_subparsers(dest="command",required=True);g=s.add_parser("generate");g.add_argument("--port",type=int,action="append",required=True);g.add_argument("--start",default="240.0.0.1");g.add_argument("--output",type=Path);v=s.add_parser("validate");v.add_argument("path",type=Path);r=s.add_parser("resolve");r.add_argument("path",type=Path);r.add_argument("value")
 a=p.parse_args();doc=generate(a.port,a.start) if a.command=="generate" else validate(json.loads(a.path.read_text()))
 if a.command=="resolve":
  found=[x for x in doc["entries"] if str(x["port"])==a.value or x["address"]==a.value]
  if len(found)!=1:raise ValueError("mapping not found")
  doc=found[0]
 data=json.dumps(doc,ensure_ascii=False,indent=2)+"\n"
 if getattr(a,"output",None):a.output.write_text(data,encoding="utf-8")
 else:print(data,end="")
if __name__=="__main__":main()
