#!/usr/bin/env python3
"""Portable unified Shadow6 command router; invokes only fixed components."""
from __future__ import annotations
import argparse,json,os,subprocess,sys
from pathlib import Path
_HERE = Path(__file__).resolve().parent
if (_HERE.parent / "Deployment").is_dir():
    sys.path.insert(0, str(_HERE.parent / "Deployment"))
for _candidate in (_HERE, _HERE.parent / "Crosed", _HERE.parent / "share" / "shadow6" / "modules", _HERE.parent / "modules"):
    if (_candidate / "install_layout.py").is_file():
        sys.path.insert(0, str(_candidate))
        break
else:
    pass
for _deployment in (_HERE.parent / "Deployment", _HERE.parent / "share" / "shadow6" / "deployment"):
    if _deployment.is_dir():
        sys.path.insert(0, str(_deployment))
try:
 from install_layout import tree_root  # noqa: E402
 ROOT=tree_root(__file__)
except ImportError:
 ROOT=_HERE.parent
COMPONENTS={"repo":ROOT/"Online-Repository/shadow6_repo.py","portmap":ROOT/"Gate/portmap.py","go":ROOT/"Core-Go/shadow6-go","rust":ROOT/"Core-Rust/shadow6-rust","zig":ROOT/"Core-Zig/shadow6-zig","ada":ROOT/"Core-Ada/shadow6-ada","d":ROOT/"Core-D/shadow6-d","nim":ROOT/"Core-Nim/shadow6-nim","cpp":ROOT/"Core-Cpp/shadow6-cpp","pony":ROOT/"Core-Pony/shadow6-pony","hare":ROOT/"Core-Hare/shadow6-hare","carp":ROOT/"Core-Carp/shadow6-carp","gleam":ROOT/"Core-Gleam/shadow6-gleam","idris":ROOT/"Core-Idris/shadow6-idris","network":ROOT/"Network-Adapter/shadow6_network.py","network-node":ROOT/"Network-Adapter/shadow6_network.mjs","gate":ROOT/"Gate/shadow6-gate","relay":ROOT/"C11Relay/bridge_relay","guard":ROOT/"Guard/shadow6-guard","control":ROOT/"Control-Center/shadow6_control.py","plugins":ROOT/"Plugin-System/shadow6_plugins.py","sign-plugin":ROOT/"Plugin-System/sign_plugin.py","migrate":ROOT/"Migration/shadow6_migrate.py","auto":ROOT/"Auto-Orchestrator/shadow6_auto.py","detector":ROOT/"Detector/shadow6_detector.py","counterstrike":ROOT/"Detector/counterstrike.py","watch":ROOT/"Detector/watch.py","security":ROOT/"Security-Assistants/shadow6_security.py","infra":ROOT/"Infrastructure-Assistants/shadow6_infra.py","slots":ROOT/"Slot-System/shadow6_slots.py","packages":ROOT/"Package-Manager/shadow6_pkg.py","public6":ROOT/"Public6/shadow6_public.py","init":ROOT/"Service-Init/shadow6_init.py"}
COMPONENTS["virtual-broker"]=ROOT/"Public6/virtual_broker.py"
COMPONENTS["virtual-client"]=ROOT/"Public6/virtual_peer.py"
COMPONENTS["virtual-agent"]=ROOT/"Public6/virtual_peer.py"
COMPONENTS["join-code"]=ROOT/"Public6/join_code.py"
COMPONENTS.update({
 "crosed": ROOT/"Crosed/crosedctl.py", "ppb": ROOT/"Paranoid-Proxy-Benchmark/paranoid_proxy_benchmark.py",
 "connect": ROOT/"CLI/shadow6_connect.py", "native-config": ROOT/"CLI/native_config.py",
 "native-key": ROOT/"CLI/native_key.py", "paranoid-proxy-benchmark": ROOT/"Paranoid-Proxy-Benchmark/paranoid_proxy_benchmark.py",
 "easybuild": ROOT/"EasyBuild/shadow6_easybuild.py", "extensions": ROOT/"Extension-System/shadow6_extensions.py",
 "detector-neo": ROOT/"Detector/shadow6_detector_neo.py", "virtual-adapter": ROOT/"Virtual-Adapter/shadow6_virtual_adapter.py",
 "interface": ROOT/"Virtual-Adapter/setup_interface.py", "guard-ctl": ROOT/"Guard/shadow6-guard-ctl.sh",
 "iperf": ROOT/"Tools/iperf3_matrix.py", "iperf-chain": ROOT/"Benchmark/iperf_chain.py",
 "audit": ROOT/"shadow6_audit.py", "python-runtime": ROOT/"Tools/python_runtime.py",
 "performance": ROOT/"Benchmark/component_benchmark.py", "collect-performance": ROOT/"Tools/collect_performance.py",
 "ipc": ROOT/"Node-IPC/cli.mjs",
 "deployment": ROOT/"Deployment/shadow6_deployment.py",
 "acceptance": ROOT/"Deployment/shadow6_acceptance.py",

})
try:
 from core_catalog import CoreCatalog, CORE_IDS
 from service_registry import ServiceRegistry
except ImportError:
 CoreCatalog = ServiceRegistry = None
if not (ROOT/"Makefile").is_file():
 bin_dir=Path(sys.argv[0]).resolve().parent
 COMPONENTS={name:bin_dir/("shadow6-"+name) for name in COMPONENTS}
 COMPONENTS.update({"crosed":bin_dir/"crosedctl","ppb":bin_dir/"paranoid-proxy-benchmark","counterstrike":bin_dir/"shadow6-counterstrike","watch":bin_dir/"shadow6-watch","go":bin_dir/"shadow6-go","rust":bin_dir/"shadow6-rust","control":bin_dir/"shadow6-control","sign-plugin":bin_dir/"shadow6-sign-plugin","packages":bin_dir/"shadow6-pkg","repo":bin_dir/"shadow6-repo","portmap":bin_dir/"shadow6-portmap"})
TRANSPORTS={"schema","rpc","mcp","lsp","openai-tools","openai-rpc","serve","call","privacy"}
STANDALONE=("guard","gate","detector","counterstrike","watch","security")
def command_for(name,args):
 path=COMPONENTS.get(name)
 if path is None or not path.is_file():raise SystemExit(f"component unavailable: {name}")
 return ([sys.executable,str(path)] if path.suffix==".py" else (["node",str(path)] if path.suffix==".mjs" else [str(path)]))+args
def run(name,args,events=False):
 if events:print(json.dumps({"event":"process.started","component":name,"argument_count":len(args)}),file=sys.stderr,flush=True)
 if args==["--version"] and name in {"go","rust","zig","ada","d","nim","cpp","pony","hare","carp","gleam","idris"}:
  from shadow6_vcore import _binary,_run,strict_json_loads,validate_feature_report
  path=COMPONENTS[name]
  with _binary(path) as (fd,_,__):
   result=_run(path,fd,["--feature-report"],5)
  if result.returncode==0:
   report=validate_feature_report(strict_json_loads(result.stdout),"shadow6-"+name)
   print(report["core"]+" "+report["version"])
  return result.returncode
 result=subprocess.run(command_for(name,args),check=False)
 if events:print(json.dumps({"event":"process.finished","component":name,"exit_code":result.returncode}),file=sys.stderr,flush=True)
 return result.returncode

def add_hands_parser(sub):
 """Expose fixed signed runbooks without forwarding arbitrary host commands."""
 parser=sub.add_parser("hands",help="generate keys, sign, verify and execute fixed runbook plans")
 commands=parser.add_subparsers(dest="hands_command",required=True)
 for name in ("keygen","plan","verify","execute"):
  q=commands.add_parser(name,aliases=["sign"] if name=="plan" else [])
  q.add_argument("--interactive",action="store_true",help="prompt for missing values on a terminal")
  if name in {"keygen","plan"}:q.add_argument("--private-key",type=Path)
  if name in {"keygen","verify","execute"}:q.add_argument("--public-key",type=Path)
  if name!="keygen":q.add_argument("--root",type=Path,default=ROOT)
  if name=="plan":
   q.add_argument("--action",help="fixed runbook action (use --interactive to see choices)")
   q.add_argument("--output",type=Path,help="new signed plan file")
   q.add_argument("--ttl",type=int,default=300,help="validity in seconds, 30..300")
  if name in {"verify","execute"}:q.add_argument("--plan",type=Path)
  if name=="execute":q.add_argument("--state-dir",type=Path)

def run_hands(args):
 # Both the source tree and make-install layout supply the same implementations.
 base=Path(__file__).resolve().parents[1]
 for directory in (ROOT/"Security-Assistants",ROOT/"Infrastructure-Assistants",
                   base/"share/shadow6/assistants",base/"share/shadow6/modules"):
  if directory.is_dir():sys.path.insert(0,str(directory))
 from shadow6_security import SecurityError,atomic_write,canonical,generate_ledger_key,secure_read,strict_json_loads
 from shadow6_infra import RUNBOOKS,create_plan,execute_plan,verify_plan

 def value(name,description,*,path=True):
  result=getattr(args,name,None)
  if result is None:
   if not sys.stdin.isatty():raise ValueError(f"--{name.replace('_','-')} is required without an interactive terminal")
   result=input(description+": ").strip()
   if not result:raise ValueError(f"{description} cannot be empty")
  return Path(result).expanduser().absolute() if path else result

 try:
  if args.interactive and not sys.stdin.isatty():raise ValueError("--interactive requires a terminal; provide command-line parameters in scripts")
  operation=args.hands_command
  if operation=="keygen":
   private=value("private_key","Private key output path")
   public=value("public_key","Public key output path")
   if private==public:raise ValueError("private and public key paths must differ")
   result=generate_ledger_key(private,public)
  elif operation in {"plan","sign"}:
   private=value("private_key","Private key path")
   action=value("action","Action ("+", ".join(sorted(RUNBOOKS))+")",path=False)
   output=value("output","Signed plan output path")
   # A mistaken output path must not overwrite a signing key or old approval.
   if output.exists() or output.is_symlink():raise ValueError("plan output already exists; choose a new file")
   result=create_plan(args.root.expanduser(),action,private,args.ttl)
   atomic_write(output,canonical(result)+b"\n",0o600)
   result={"action":action,"plan":str(output),"key_id":result["key_id"],"expires_at":result["expires_at"]}
  else:
   plan=value("plan","Signed plan path")
   public=value("public_key","Public key path")
   if operation=="verify":
    document=strict_json_loads(secure_read(plan,65536,secret=True),limit=65536)
    verified=verify_plan(document,public,args.root.expanduser())
    result={"valid":True,"action":verified["action"],"root":verified["root"],"expires_at":verified["expires_at"]}
   else:
    state=value("state_dir","Replay state directory (reuse it for all executions with this key)")
    result=execute_plan(plan,public,args.root.expanduser(),state)
  print(json.dumps(result,ensure_ascii=False,indent=2))
  return 0 if result.get("status","pass")=="pass" else 1
 except (SecurityError,OSError,ValueError,EOFError,subprocess.TimeoutExpired) as error:
  print(f"error: {error}",file=sys.stderr)
  return 2

def main():
 raw=sys.argv[1:]
 events=bool(raw and raw[0]=="--json-events")
 if events:raw=raw[1:]
 if raw and raw[0] in COMPONENTS and raw[0] not in {"virtual-broker","virtual-client","virtual-agent","deployment","acceptance"}:
  args=raw[1:];return run(raw[0],args[1:] if args[:1]==["--"] else args,events)
 p=argparse.ArgumentParser(prog="shadow6");p.add_argument("--json-events",action="store_true");sub=p.add_subparsers(dest="command",required=True)
 q=sub.add_parser("tools",help="list all fixed tool routes and availability")
 q=sub.add_parser("guide",help="read a friendly getting-started guide / 查看中英文入门指引");q.add_argument("--lang",choices=("en","zh"),default="en")
 c=sub.add_parser("component");c.add_argument("name",choices=sorted(COMPONENTS));c.add_argument("args",nargs=argparse.REMAINDER)
 c=sub.add_parser("standalone",help="run a fixed security component without any Core");c.add_argument("name",choices=STANDALONE);c.add_argument("args",nargs=argparse.REMAINDER)
 for name in sorted(TRANSPORTS):q=sub.add_parser(name);q.add_argument("args",nargs=argparse.REMAINDER)
 for name in sorted(COMPONENTS):
  if name in {"virtual-broker","virtual-client","virtual-agent","deployment","acceptance"}:continue
  q=sub.add_parser(name);q.add_argument("args",nargs=argparse.REMAINDER)
 q=sub.add_parser("virtual-broker",help="run or validate a configured Virtual Broker")
 q.add_argument("--config",type=Path,required=True)
 q.add_argument("--check",action="store_true")
 for name in ("virtual-client","virtual-agent"):
  q=sub.add_parser(name,help="run or validate a configured Virtual Peer")
  q.add_argument("--config",type=Path)
  q.add_argument("--init",action="store_true"); q.add_argument("--core")
  q.add_argument("--output",type=Path); q.add_argument("--private-key-output",type=Path)
  q.add_argument("--tenant",default="default"); q.add_argument("--identity",default="peer-01")
  q.add_argument("--listen",default="127.0.0.1:1087"); q.add_argument("--gate",default="127.0.0.1:1086")
  q.add_argument("--transport",choices=("tcp","udp"),default="tcp")
  q.add_argument("--max-connections",type=int,default=32); q.add_argument("--idle-seconds",type=int,default=120)
  q.add_argument("--check",action="store_true")
 add_hands_parser(sub)
 q=sub.add_parser("features");q.add_argument("--component",action="append",default=[]);q.add_argument("--format",choices=("json","lines"),default="json")
 q=sub.add_parser("vcore",help="discover installed cores and capability intersection");q.add_argument("args",nargs=argparse.REMAINDER)
 q=sub.add_parser("benchmark",help="run real native benchmarks for selected cores")
 q.add_argument("--core",dest="cores",action="append")
 q.add_argument("--all",action="store_true",help="benchmark all twelve cores and all three backend paths (default)")
 q.add_argument("--backend",dest="backends",action="append",choices=("native","python","node"))
 q.add_argument("--payload-bytes",type=int,default=4096)
 q.add_argument("--requests",type=int,default=32)
 q.add_argument("--concurrency",type=int,default=1)
 q.add_argument("--role",action="append",choices=("feature-report","version","network-chain","loopback","integration"),default=[])
 q.add_argument("--repeats",type=int,default=1)
 q.add_argument("--output",type=Path,default=Path("benchmark.json"))
 q.add_argument("--format",choices=("json","txt"),default="json")
 q=sub.add_parser("sign");ss=q.add_subparsers(dest="kind",required=True);sp=ss.add_parser("plugin");sp.add_argument("manifest");sp.add_argument("--private-key",required=True);sp.add_argument("--signer",required=True)
 q=sub.add_parser("workflow");q.add_argument("stage",choices=("build","test","check","audit","crosed-variants","android-apk","package","release"));q.add_argument("args",nargs=argparse.REMAINDER)
 q=sub.add_parser("deployment",help="validate, lock and plan a Core-neutral deployment manifest")
 q.add_argument("action",choices=("validate","lock","plan"));q.add_argument("manifest",type=Path)
 q=sub.add_parser("acceptance",help="run the single source/artifact acceptance gate")
 q.add_argument("--manifest",required=True,type=Path);q.add_argument("--artifact-dir",type=Path);q.add_argument("--output",type=Path,default=Path("acceptance"));q.add_argument("--source-only",action="store_true")
 q=sub.add_parser("abi",help="inspect the Core-neutral S6ABI/1 contract")
 q.add_argument("action",choices=("catalog",))
 q=sub.add_parser("core",help="inspect and validate explicit Core descriptors")
 core_sub=q.add_subparsers(dest="core_action",required=True)
 core_sub.add_parser("list")
 for action in ("inspect","config-schema"):
  x=core_sub.add_parser(action); x.add_argument("core")
 x=core_sub.add_parser("validate-config"); x.add_argument("core"); x.add_argument("config",type=Path)
 x=core_sub.add_parser("import"); x.add_argument("descriptor",type=Path)
 q=sub.add_parser("service",help="manage named explicitly-bound services")
 ss=q.add_subparsers(dest="service_action",required=True); ss.add_parser("list")
 x=ss.add_parser("inspect"); x.add_argument("name")
 x=ss.add_parser("create"); x.add_argument("name"); x.add_argument("--core"); x.add_argument("--config",type=Path)
 x=ss.add_parser("configure"); x.add_argument("name"); x.add_argument("--core",required=True); x.add_argument("--config",type=Path,required=True)
 for action in ("run","connect"):
  x=ss.add_parser(action); x.add_argument("name")
 a=p.parse_args();tail=lambda v:v[1:] if v[:1]==["--"] else v
 if a.command=="tools":
  print(json.dumps({"schema":"shadow6.tools.v1","tools":[{"name":n,"path":str(path),"available":path.is_file()} for n,path in sorted(COMPONENTS.items())]},indent=2));return 0
 if a.command=="guide":return run("control",["guide","--lang",a.lang],a.json_events)
 if a.command=="hands":return run_hands(a)
 if a.command=="deployment":
  deployment_dir = ROOT / "Deployment" if (ROOT / "Deployment").is_dir() else ROOT / "share" / "shadow6" / "deployment"
  sys.path.insert(0, str(deployment_dir))
  from shadow6_deployment import load_manifest, manifest_lock, plan_manifest
  manifest = load_manifest(a.manifest)
  result = manifest if a.action == "validate" else manifest_lock(manifest) if a.action == "lock" else plan_manifest(manifest)
  print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2)); return 0
 if a.command=="core":
  catalog=CoreCatalog(ROOT)
  if a.core_action=="list": result={"schema":"shadow6.core-catalog.v1","cores":catalog.list()}
  elif a.core_action=="inspect": result=catalog.inspect(a.core)
  elif a.core_action=="config-schema": result=catalog.inspect(a.core)["configurationSchema"]
  elif a.core_action=="validate-config": result={"valid":True,"core":a.core,"config":catalog.binding(a.core,json.loads(a.config.read_text()))["config"]}
  else: result=catalog.import_file(a.descriptor)
  print(json.dumps(result,ensure_ascii=True,sort_keys=True,indent=2)); return 0
 if a.command=="service":
  registry=ServiceRegistry()
  if a.service_action=="list": result={"schema":"shadow6.service-registry.v1","services":registry.list()}
  elif a.service_action=="inspect": result=registry.inspect(a.name)
  elif a.service_action in {"create","configure"}:
   config=json.loads(a.config.read_text()) if a.config else None
   result=(registry.create(a.name,core=a.core,config=config) if a.service_action=="create" else registry.configure(a.name,core=a.core,config=config))
  else: result={"service":a.name,"coreBinding":registry.require_binding(a.name),"state":"ready"}
  print(json.dumps(result,ensure_ascii=True,sort_keys=True,indent=2)); return 0
 if a.command=="acceptance":
  deployment_dir = ROOT / "Deployment" if (ROOT / "Deployment").is_dir() else ROOT / "share" / "shadow6" / "deployment"
  sys.path.insert(0, str(deployment_dir))
  from shadow6_acceptance import run_acceptance
  result = run_acceptance(a.manifest, artifact_dir=a.artifact_dir, output=a.output, source_only=a.source_only)
  print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2)); return 0 if result["status"] == "pass" else 1
 if a.command=="abi":
  sys.path.insert(0, str(ROOT / "Deployment" if (ROOT / "Deployment").is_dir() else ROOT / "share" / "shadow6" / "deployment"))
  from shadow6_abi import ABI_VERSION, METHODS, STATES, MAX_CONTROL, MAX_DATA
  print(json.dumps({"schema":"shadow6.abi-catalog.v1","abi":ABI_VERSION,"methods":sorted(METHODS),"states":sorted(STATES),"maxControl":MAX_CONTROL,"maxData":MAX_DATA,"transports":["unix-stream","named-pipe","loopback-tcp"]}, indent=2)); return 0
 if a.command=="component":return run(a.name,tail(a.args),a.json_events)
 if a.command=="standalone":return run(a.name,tail(a.args),a.json_events)
 if a.command=="virtual-broker":return run("virtual-broker",["--config",str(a.config)]+(["--check"] if a.check else []),a.json_events)
 if a.command in ("virtual-client","virtual-agent"):
  args=["--role",a.command.removeprefix("virtual-")]
  if a.init:
   args += ["--init","--core",a.core,"--output",str(a.output),"--private-key-output",str(a.private_key_output),
            "--tenant",a.tenant,"--identity",a.identity,"--listen",a.listen,"--gate",a.gate,
            "--transport",a.transport,"--max-connections",str(a.max_connections),"--idle-seconds",str(a.idle_seconds)]
  else: args += ["--config",str(a.config)] + (["--check"] if a.check else [])
  return run(a.command,args,a.json_events)
 if a.command in COMPONENTS:return run(a.command,tail(a.args),a.json_events)
 if a.command in TRANSPORTS:return run("control",[a.command]+tail(a.args),a.json_events)
 if a.command=="features":
  names=a.component or ["go","rust","gate"]
  if a.format=="lines":return max(run(n,["--feature-report"],a.json_events) for n in names)
  reports=[]
  for name in names:
   if a.json_events:print(json.dumps({"event":"process.started","component":name,"argument_count":1}),file=sys.stderr,flush=True)
   result=subprocess.run(command_for(name,["--feature-report"]),capture_output=True,text=True,timeout=10,check=False)
   if a.json_events:print(json.dumps({"event":"process.finished","component":name,"exit_code":result.returncode}),file=sys.stderr,flush=True)
   if result.returncode:raise SystemExit(result.returncode)
   try: report=json.loads(result.stdout)
   except json.JSONDecodeError as error:raise SystemExit(f"{name}: invalid feature report JSON: {error}") from error
   if not isinstance(report,dict) or report.get("core")!="shadow6-"+name:raise SystemExit(f"{name}: unexpected feature report")
   reports.append(report)
  print(json.dumps({"schema":"shadow6.features.v1","components":reports},ensure_ascii=False,separators=(",",":")))
  return 0
 if a.command=="vcore":
  import shadow6_vcore
  return subprocess.run([sys.executable, shadow6_vcore.__file__]+tail(a.args), check=False).returncode
 if a.command=="benchmark":
  sys.path.insert(0, str(ROOT / "Benchmark"))
  from benchmark import run as benchmark_run, write as benchmark_write
  core_names = {"go","rust","zig","ada","d","nim","cpp","pony","hare","carp","gleam","idris"}
  core_names.add("gleam-mux")
  cores = [*CORE_IDS,"gleam-mux"] if a.all or not a.cores else a.cores
  cores = [c for c in cores if c in core_names]
  if not cores: raise SystemExit("benchmark requires --core or --all")
  if not 1 <= a.repeats <= 100: raise SystemExit("--repeats must be 1..100")
  roles = ['network-chain' if role in ('loopback','integration') else role for role in (a.role or ['feature-report','network-chain'])]
  result = benchmark_run({"cores": cores, "backends": a.backends or ['native','python','node'], "roles": roles,
                          "repeats": a.repeats, "args": {}, "network": {"payload_bytes":a.payload_bytes,
                          "requests":a.requests,"concurrency":a.concurrency}})
  benchmark_write(result,a.output)
  print(json.dumps({"output": str(a.output), "results": len(result["results"])}, ensure_ascii=True))
  return 0 if all(r["status"] == "ok" for r in result["results"]) else 1
 if a.command=="sign":return run("sign-plugin",[a.manifest,"--private-key",a.private_key,"--signer",a.signer],a.json_events)
 stages=[a.stage] if a.stage!="release" else ["build","crosed-variants","test","check","audit","android-apk","package"]
 for stage in stages:
  result=subprocess.run(["make",stage]+a.args,cwd=ROOT,check=False)
  if result.returncode:return result.returncode
 return 0
if __name__=="__main__":raise SystemExit(main())
