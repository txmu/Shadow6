#!/usr/bin/env python3
"""Fixed-command benchmark runner; process and network measurements differ."""
from __future__ import annotations
import argparse,errno,json,math,os,platform,signal,socket,subprocess,sys,tempfile,time
from pathlib import Path
try: import resource
except ModuleNotFoundError: resource=None
ROOT=Path(__file__).resolve().parents[1]
CORE_PATHS={"go":"Core-Go/shadow6-go","rust":"Core-Rust/shadow6-rust","zig":"Core-Zig/shadow6-zig","ada":"Core-Ada/shadow6-ada","d":"Core-D/shadow6-d","nim":"Core-Nim/shadow6-nim","cpp":"Core-Cpp/shadow6-cpp","pony":"Core-Pony/shadow6-pony","hare":"Core-Hare/shadow6-hare","carp":"Core-Carp/shadow6-carp","gleam":"Core-Gleam/shadow6-gleam","idris":"Core-Idris/shadow6-idris"}
FALLBACK={"zig":"Core-Zig/zig-out/bin/shadow6-zig"}; ROLES={"feature-report":["--feature-report"],"version":["--version"],"network-chain":[]}
def binary(p):
 try:
  with p.open('rb') as stream: m=stream.read(4)
 except OSError:return False
 return (sys.platform=="win32" and m[:2]==b"MZ") or (sys.platform=="darwin" and m in (b"\xfe\xed\xfa\xce",b"\xce\xfa\xed\xfe",b"\xfe\xed\xfa\xcf",b"\xcf\xfa\xed\xfe",b"\xca\xfe\xba\xbe")) or (os.name=="posix" and sys.platform!="darwin" and m==b"\x7fELF")
def metrics(u,reason=None):
 fields=("user_seconds","system_seconds","peak_rss_kib","context_switches","io_read_operations","io_write_operations")
 if u is None:return {k:{"value":None,"state":"collection_failed","reason":reason or "collector unavailable"} for k in fields}
 rss=u.ru_maxrss/(1024 if sys.platform=="darwin" else 1); values={"user_seconds":u.ru_utime,"system_seconds":u.ru_stime,"peak_rss_kib":int(rss),"context_switches":u.ru_nvcsw+u.ru_nivcsw,"io_read_operations":u.ru_inblock,"io_write_operations":u.ru_oublock}
 return {k:{"value":max(0,v),"state":"valid"} for k,v in values.items()}
def execute(command,timeout):
 with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
  p=subprocess.Popen(command,cwd=ROOT,stdout=out,stderr=err,start_new_session=os.name=='posix')
  try:
   # Polling keeps the hard timeout effective on POSIX as well as Windows.
   # wait4(..., 0) can otherwise block forever in a stuck network harness.
   deadline=time.monotonic()+timeout
   usage=None
   while True:
    if hasattr(os,"wait4"):
     pid,status,usage=os.wait4(p.pid,os.WNOHANG)
     if pid:
      p.returncode=os.waitstatus_to_exitcode(status)
      break
    elif p.poll() is not None:break
    if time.monotonic() >= deadline:
     raise subprocess.TimeoutExpired(command,timeout)
    time.sleep(0.02)
   data=metrics(usage,"native process counters unavailable on this platform")
  except subprocess.TimeoutExpired:
   if os.name=='posix': os.killpg(p.pid,signal.SIGKILL)
   else: p.kill()
   p.wait();p.returncode=124;data=metrics(None,"timed out")
  out.seek(0);err.seek(0);return p.returncode,out.read().decode("utf-8","replace"),err.read().decode("utf-8","replace"),data
def network_unavailable(core):
 if core != "cpp":return None
 try:
  with socket.socket(socket.AF_INET,socket.SOCK_STREAM,132) as probe:
   probe.bind(("127.0.0.1",0));probe.listen(1)
 except OSError as error:
  if error.errno in (errno.EPROTONOSUPPORT,errno.EAFNOSUPPORT,errno.EPROTOTYPE,errno.EOPNOTSUPP):
   return f"kernel SCTP unavailable: {error}"
  raise
 return None
def validate_config(d):
 if type(d["repeats"]) is not int or not 1<=d["repeats"]<=100:raise ValueError("repeats must be 1..100")
 if not isinstance(d["cores"],list) or not d["cores"] or len(d['cores'])!=len(set(d['cores'])) or not all(x in CORE_PATHS for x in d["cores"]):raise ValueError("unknown or duplicate core")
 if not isinstance(d["roles"],list) or not d["roles"] or not all(x in ROLES for x in d["roles"]):raise ValueError("unknown role")
 network=d['network']
 if not isinstance(network,dict) or set(network)!={'payload_bytes','requests','concurrency'}:raise ValueError('unknown network fields')
 for field,maximum in [('payload_bytes',1048576),('requests',10000),('concurrency',1)]:
  if type(network[field]) is not int or not 1<=network[field]<=maximum:raise ValueError(f'{field} outside 1..{maximum}')
 if not isinstance(d['args'],dict) or d['args']:raise ValueError('benchmark commands do not accept extra component arguments')
 if type(d['require_network']) is not bool:raise ValueError('require_network must be boolean')
 return d

def _load_config(path):
 d={"cores":list(CORE_PATHS),"roles":["feature-report","network-chain"],"repeats":1,"args":{},"network":{"payload_bytes":4,"requests":32,"concurrency":1},"require_network":False}
 if path:
  x=json.loads(Path(path).read_text());
  if not isinstance(x,dict) or set(x)-set(d):raise ValueError("unknown benchmark fields")
  d.update(x)
 return validate_config(d)

def available(exe,core):
 if not exe.is_file() or not os.access(exe,os.X_OK):return False
 # Idris is a Chez launcher, not an ELF/Mach-O executable. Its compiled app
 # travels with the same-commit artifact and is exercised by the subprocess.
 if core=='idris':
  with exe.open('rb') as stream:return stream.read(2)==b'#!'
 return binary(exe)

def network_result(out,core):
 result=json.loads(out.splitlines()[-1])
 if result.get('schema')=='shadow6.network-suite.v1':result=result['results']['shadow6-'+core]
 for field in ['throughput_bps','duration_seconds','latency_p95_seconds','success_rate']:
  value=result[field]
  if type(value) not in (int,float) or not math.isfinite(value) or value<0:raise ValueError('invalid network metric '+field)
 if result['duration_seconds']<=0 or result['success_rate']!=1.0:raise ValueError('network exchange incomplete')
 # Old native emitters count round-trip bytes, whereas throughput is useful
 # one-direction application goodput throughout this report.
 if 'bytes_transferred' in result:
  result['throughput_bps']=result['bytes_transferred']*4/result['duration_seconds']
 return result

PATHS={
 **{core:'client -> broker -> agent -> TCP echo target' for core in ('go','rust','zig','ada','nim','cpp')},
 'pony':'UDP application -> authenticated client -> agent -> UDP echo target',
 'hare':'IPv6 UDP application -> authenticated client -> agent -> UDP echo target',
 'carp':'two authenticated native UDP channels, forward and reverse',
 'd':'native packet codec over TCP/UDP relay sockets (in-process driver)',
 'gleam':'native crypto over TCP/UDP relay sockets (in-process driver)',
 'idris':'authenticated native loopback self-test; includes process startup',
}
def run(c):
 defaults=_load_config(None);defaults.update(c);c=validate_config(defaults)
 rows=[]
 for core in c["cores"]:
  exe=(ROOT/CORE_PATHS[core]).resolve()
  if not available(exe,core):exe=(ROOT/FALLBACK.get(core,CORE_PATHS[core])).resolve()
  if not available(exe,core):rows.append({"core":core,"measurement":"availability","status":"failed","path":str(exe),"reason":"missing, non-executable, or foreign-host binary"});continue
  for role in c["roles"]:
   reason=network_unavailable(core) if role=="network-chain" else None
   if reason:
    rows.append({"core":core,"measurement":"network-chain","role":role,"status":"failed" if c['require_network'] else "not_applicable","reason":reason})
    print(f"[NOT APPLICABLE] {core} {role}: {reason}",file=sys.stderr)
    continue
   for repeat in range(1,c["repeats"]+1):
    if role=="network-chain":
     if core == "d":
      cmd=[str(exe),"--benchmark-loopback",str(c["network"]["payload_bytes"]),str(c["network"]["requests"])]
      timeout=60; kind="network-chain"
     else:
      runner=os.environ.get("PYTHON") or (str(ROOT/".venv/bin/python") if (ROOT/".venv/bin/python").is_file() else sys.executable);cmd=[runner,str(ROOT/"integration/stack_test.py"),"--engine","shadow6-"+core,"--benchmark",*sum((["--"+k.replace("_","-"),str(v)] for k,v in c["network"].items()),[])]; timeout=240;kind="network-chain"
    else:cmd=[str(exe),*ROLES[role],*c["args"].get(core,[]),*c["args"].get(role,[])];timeout=120;kind="process-start"
    started=time.perf_counter();code,out,err,process=execute(cmd,timeout);row={"core":core,"measurement":kind,"role":role,"repeat":repeat,"status":"ok" if code==0 else "failed","returncode":code,"elapsed_seconds":time.perf_counter()-started,"process":process,"stderr":err[-2048:]}
    if kind=='network-chain':row['path']=PATHS[core]
    try:row["network" if kind=="network-chain" else "native"]=network_result(out,core) if kind=='network-chain' else json.loads(out)
    except (ValueError,TypeError,KeyError,IndexError) as error:
     if kind=='network-chain' and not code:
      row['status']='failed';row['reason']='missing or invalid network metrics: '+str(error)
    if code:
     row["stdout"]=out[-2048:]
     print(f"[FAIL] {core} {role} repeat={repeat} exit={code}\n{err[-2048:]}\n{out[-2048:]}",file=sys.stderr)
    rows.append(row)
 return {"schema":"shadow6.benchmark.v2","config":c,"environment":{"platform":platform.platform(),'machine':platform.machine(),'python':platform.python_version(),'commit':os.environ.get('GITHUB_SHA'),'runner':os.environ.get('RUNNER_NAME'),'run_id':os.environ.get('GITHUB_RUN_ID'),'network':'loopback; no WAN emulation','throughput':'one-direction useful application bits / exchange duration'},"results":rows}
def write(result,base):
 base=Path(base);base.parent.mkdir(parents=True,exist_ok=True);base.with_suffix(".json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
 lines=["Shadow6 Benchmark schema=shadow6.benchmark.v2","core\tmeasurement\trepeat\tstatus\telapsed_seconds\tpeak_rss_kib\tthroughput_bps\tlatency_p95_seconds\tsuccess_rate"]
 for r in result["results"]:
  n=r.get("network",{});rss=r.get("process",{}).get("peak_rss_kib",{}).get("value","-");lines.append(f"{r['core']}\t{r['measurement']}\t{r.get('repeat','-')}\t{r['status']}\t{r.get('elapsed_seconds',0):.6f}\t{rss}\t{n.get('throughput_bps','-')}\t{n.get('latency_p95_seconds','-')}\t{n.get('success_rate','-')}")
  if r.get('reason'):lines.append('  reason: '+r['reason'])
  if r.get('path'):lines.append('  path: '+r['path'])
 base.with_suffix(".txt").write_text("\n".join(lines)+"\n",encoding="utf-8")
 base.with_suffix(".md").write_text("# Shadow6 Benchmark Report\n\nLoopback request/response goodput, not WAN or saturation capacity. Paths are stated per core; native codec/self-test rows do not establish daemon throughput. Process-start values are not network rankings.\n\nEnvironment: "+json.dumps(result.get('environment',{}),sort_keys=True)+"\n\n```\n"+"\n".join(lines)+"\n```\n",encoding="utf-8")
def main():
 p=argparse.ArgumentParser();p.add_argument("--config");p.add_argument("--core",action="append",choices=sorted(CORE_PATHS));p.add_argument("--role",choices=sorted(ROLES));p.add_argument("--repeats",type=int);p.add_argument("--require-network",action='store_true');p.add_argument("--output",default="benchmark");p.add_argument("--format",action="append") ;a=p.parse_args();c=_load_config(a.config)
 if a.core:c["cores"]=a.core
 if a.role:c["roles"]=[a.role]
 if a.repeats is not None:c["repeats"]=a.repeats
 if a.require_network:c['require_network']=True
 validate_config(c)
 r=run(c)
 if a.output=="-":print(json.dumps(r,sort_keys=True,indent=2))
 else:write(r,a.output)
 return 0 if all(x["status"] in {"ok","not_applicable"} for x in r["results"]) else 1
if __name__=="__main__":raise SystemExit(main())
