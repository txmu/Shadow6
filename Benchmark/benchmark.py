#!/usr/bin/env python3
"""Fixed-command benchmark runner; process and network measurements differ."""
from __future__ import annotations
import argparse,json,os,subprocess,sys,tempfile,time
from pathlib import Path
try: import resource
except ModuleNotFoundError: resource=None
ROOT=Path(__file__).resolve().parents[1]
CORE_PATHS={"go":"Core-Go/shadow6-go","rust":"Core-Rust/shadow6-rust","zig":"Core-Zig/shadow6-zig","ada":"Core-Ada/shadow6-ada","d":"Core-D/shadow6-d","nim":"Core-Nim/shadow6-nim","cpp":"Core-Cpp/shadow6-cpp","pony":"Core-Pony/shadow6-pony","hare":"Core-Hare/shadow6-hare","carp":"Core-Carp/shadow6-carp","gleam":"Core-Gleam/shadow6-gleam","idris":"Core-Idris/shadow6-idris"}
FALLBACK={"zig":"Core-Zig/zig-out/bin/shadow6-zig"}; ROLES={"feature-report":["--feature-report"],"version":["--version"],"network-chain":[]}; NETWORK={"go","rust"}
def binary(p):
 try: m=p.read_bytes()[:4]
 except OSError:return False
 return (sys.platform=="win32" and m[:2]==b"MZ") or (sys.platform=="darwin" and m in (b"\xfe\xed\xfa\xce",b"\xce\xfa\xed\xfe",b"\xfe\xed\xfa\xcf",b"\xcf\xfa\xed\xfe",b"\xca\xfe\xba\xbe")) or (os.name=="posix" and sys.platform!="darwin" and m==b"\x7fELF")
def metrics(u,reason=None):
 fields=("user_seconds","system_seconds","peak_rss_kib","context_switches","io_read_operations","io_write_operations")
 if u is None:return {k:{"value":None,"state":"collection_failed","reason":reason or "collector unavailable"} for k in fields}
 rss=u.ru_maxrss/(1024 if sys.platform=="darwin" else 1); values={"user_seconds":u.ru_utime,"system_seconds":u.ru_stime,"peak_rss_kib":int(rss),"context_switches":u.ru_nvcsw+u.ru_nivcsw,"io_read_operations":u.ru_inblock,"io_write_operations":u.ru_oublock}
 return {k:{"value":max(0,v),"state":"valid"} for k,v in values.items()}
def execute(command,timeout):
 with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
  p=subprocess.Popen(command,cwd=ROOT,stdout=out,stderr=err)
  try:
   if os.name=="posix" and hasattr(os,"wait4"):
    _,s,u=os.wait4(p.pid,0);p.returncode=os.waitstatus_to_exitcode(s);data=metrics(u)
   else:
    p.wait(timeout);data=metrics(None,"Windows process counters require the native collector")
  except subprocess.TimeoutExpired:p.kill();p.wait();p.returncode=124;data=metrics(None,"timed out")
  out.seek(0);err.seek(0);return p.returncode,out.read().decode("utf-8","replace"),err.read().decode("utf-8","replace"),data
def _load_config(path):
 d={"cores":list(CORE_PATHS),"roles":["feature-report","network-chain"],"repeats":1,"args":{},"network":{"payload_bytes":4,"requests":32,"concurrency":1}}
 if path:
  x=json.loads(Path(path).read_text());
  if not isinstance(x,dict) or set(x)-set(d):raise ValueError("unknown benchmark fields")
  d.update(x)
 if not isinstance(d["repeats"],int) or not 1<=d["repeats"]<=1000:raise ValueError("repeats must be 1..1000")
 if not isinstance(d["cores"],list) or not all(x in CORE_PATHS for x in d["cores"]):raise ValueError("unknown core")
 if not isinstance(d["roles"],list) or not all(x in ROLES for x in d["roles"]):raise ValueError("unknown role")
 return d
def run(c):
 rows=[]
 for core in c["cores"]:
  exe=(ROOT/CORE_PATHS[core]).resolve()
  if not exe.is_file() or not os.access(exe,os.X_OK) or not binary(exe):exe=(ROOT/FALLBACK.get(core,CORE_PATHS[core])).resolve()
  if not exe.is_file() or not os.access(exe,os.X_OK) or not binary(exe):rows.append({"core":core,"measurement":"process-start","status":"unavailable","path":str(exe),"reason":"missing, non-executable, or foreign-host binary"});continue
  for role in c["roles"]:
   for repeat in range(1,c["repeats"]+1):
    if role=="network-chain" and core not in NETWORK:rows.append({"core":core,"measurement":"network-chain","repeat":repeat,"status":"not_applicable","reason":"no standardized client-proxy-target adapter"});continue
    if role=="network-chain":
     runner=os.environ.get("PYTHON") or (str(ROOT/".venv/bin/python") if (ROOT/".venv/bin/python").is_file() else sys.executable);cmd=[runner,str(ROOT/"integration/stack_test.py"),"--engine","shadow6-"+core,"--benchmark",*sum((["--"+k.replace("_","-"),str(v)] for k,v in c["network"].items()),[])]; timeout=240;kind="network-chain"
    else:cmd=[str(exe),*ROLES[role],*c["args"].get(core,[]),*c["args"].get(role,[])];timeout=120;kind="process-start"
    started=time.perf_counter();code,out,err,process=execute(cmd,timeout);row={"core":core,"measurement":kind,"role":role,"repeat":repeat,"status":"ok" if code==0 else "failed","returncode":code,"elapsed_seconds":time.perf_counter()-started,"process":process,"stderr":err[-2048:]}
    try:row["network" if kind=="network-chain" else "native"]=json.loads(out.splitlines()[-1] if kind=="network-chain" else out)
    except json.JSONDecodeError:pass
    rows.append(row)
 return {"schema":"shadow6.benchmark.v2","config":c,"results":rows}
def write(result,base):
 base=Path(base);base.with_suffix(".json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 lines=["Shadow6 Benchmark schema=shadow6.benchmark.v2","core\tmeasurement\trepeat\tstatus\telapsed_seconds\tpeak_rss_kib\tthroughput_bps\tlatency_p95_seconds\tsuccess_rate"]
 for r in result["results"]:
  n=r.get("network",{});rss=r.get("process",{}).get("peak_rss_kib",{}).get("value","-");lines.append(f"{r['core']}\t{r['measurement']}\t{r.get('repeat','-')}\t{r['status']}\t{r.get('elapsed_seconds',0):.6f}\t{rss}\t{n.get('throughput_bps','-')}\t{n.get('latency_p95_seconds','-')}\t{n.get('success_rate','-')}")
 base.with_suffix(".txt").write_text("\n".join(lines)+"\n")
 base.with_suffix(".md").write_text("# Shadow6 Benchmark Report\n\nNetwork rows are real client → proxy → target results; process-start values are not network rankings.\n\n```\n"+"\n".join(lines)+"\n```\n")
def main():
 p=argparse.ArgumentParser();p.add_argument("--config");p.add_argument("--core",action="append",choices=sorted(CORE_PATHS));p.add_argument("--role",choices=sorted(ROLES));p.add_argument("--repeats",type=int);p.add_argument("--output",default="benchmark");p.add_argument("--format",action="append") ;a=p.parse_args();c=_load_config(a.config)
 if a.core:c["cores"]=a.core
 if a.role:c["roles"]=[a.role]
 if a.repeats is not None:c["repeats"]=a.repeats
 r=run(c)
 if a.output=="-":print(json.dumps(r,sort_keys=True,indent=2))
 else:write(r,a.output)
 return 0 if all(x["status"] in {"ok","not_applicable"} for x in r["results"]) else 1
if __name__=="__main__":raise SystemExit(main())
