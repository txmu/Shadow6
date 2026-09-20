#!/usr/bin/env python3
import json,os,subprocess,time
from pathlib import Path
from shadow6_network import ReliableAdapter

def python_rows():
 rows=[]
 for payload in (4096,65536,1048576):
  for requested in (1,16,64):
   streams=min(requested,(16*1024*1024)//payload);key=os.urandom(32);left=ReliableAdapter('idris',key,0);right=ReliableAdapter('idris',key,1);queue=[];received=0;started=time.perf_counter()
   for stream in range(streams):queue.extend(left.send(stream,os.urandom(payload)))
   while queue:
    acks,messages,_=right.receive(queue.pop());received+=sum(len(item[1]) for item in messages)
    for ack in acks:left.receive(ack)
    queue.extend(left.outbound())
   seconds=time.perf_counter()-started;rows.append({'backend':'python','payload_bytes':payload,'requested_streams':requested,'active_streams':streams,'bytes':received,'seconds':seconds,'throughput_bps':received*8/seconds})
 return rows

def main():
 here=Path(__file__).resolve().parent; node=subprocess.run(['node',str(here/'benchmark_node.mjs')],capture_output=True,text=True,timeout=120,check=True)
 result={'schema':'shadow6.network-adapter-benchmark.v1','scope':'codec-loop; not end-to-end network throughput','rows':python_rows()+json.loads(node.stdout)['rows']}
 print(json.dumps(result,sort_keys=True,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
