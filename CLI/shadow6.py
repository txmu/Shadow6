#!/usr/bin/env python3
"""Portable unified Shadow6 command router; invokes only fixed components."""
from __future__ import annotations
import argparse,json,os,subprocess,sys
from pathlib import Path
_HERE = Path(__file__).resolve().parent
if (_HERE.parent / "Deployment").is_dir():
    sys.path.insert(0, str(_HERE.parent / "Deployment"))
if (_HERE.parent / "Control-Center").is_dir():
    sys.path.insert(0, str(_HERE.parent / "Control-Center"))
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
sys.path.insert(0, str(ROOT / "Control-Center"))
from native_profiles import profiles, bind_profile
COMPONENTS={"repo":ROOT/"Online-Repository/shadow6_repo.py","portmap":ROOT/"Gate/portmap.py","network":ROOT/"Network-Adapter/shadow6_network.py","network-node":ROOT/"Network-Adapter/shadow6_network.mjs","gate":ROOT/"Gate/shadow6-gate","relay":ROOT/"C11Relay/bridge_relay","guard":ROOT/"Guard/shadow6-guard","control":ROOT/"Control-Center/shadow6_control.py","plugins":ROOT/"Plugin-System/shadow6_plugins.py","sign-plugin":ROOT/"Plugin-System/sign_plugin.py","migrate":ROOT/"Migration/shadow6_migrate.py","auto":ROOT/"Auto-Orchestrator/shadow6_auto.py","detector":ROOT/"Detector/shadow6_detector.py","counterstrike":ROOT/"Detector/counterstrike.py","watch":ROOT/"Detector/watch.py","security":ROOT/"Security-Assistants/shadow6_security.py","infra":ROOT/"Infrastructure-Assistants/shadow6_infra.py","slots":ROOT/"Slot-System/shadow6_slots.py","packages":ROOT/"Package-Manager/shadow6_pkg.py","public6":ROOT/"Public6/shadow6_public.py","init":ROOT/"Service-Init/shadow6_init.py"}
COMPONENTS.update({p['core']: ROOT / p['artifact'] for p in profiles() if p['primary']})
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
except ImportError:
 CoreCatalog = None
 CORE_IDS = tuple(p["core"] for p in profiles() if p["primary"])
try:
 from service_registry import ServiceRegistry
except ImportError:
 ServiceRegistry = None
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
 if args==["--version"] and name in CORE_IDS:
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

def add_service_options(parser):
 parser.add_argument("--protocol-envelope",help="S6P1 portable logical/admission context")
 parser.add_argument("--protocol-file",type=Path,help="owner-only S6P1 token file")
 parser.add_argument("--gate-config",type=Path)
 parser.add_argument("--guard-config",type=Path)
 parser.add_argument("--credited-config",type=Path,help="lock an owner-only S6NA credited companion attachment")
 parser.add_argument("--privacy",choices=("native","envelope"),default="native")
 parser.add_argument("--envelope-config",type=Path)
 parser.add_argument("--metrics",type=Path)
 parser.add_argument("--ttl",type=int,default=3600)
 parser.add_argument("--limits-mode",choices=("safe","elastic","custom"),default="safe")
 parser.add_argument("--limits-overrides",type=Path,help="private JSON object with positive finite resource limits")

def service_spec(args):
 from limits import validate_policy
 from service_storage import private_read, strict_json
 overrides = strict_json(private_read(args.limits_overrides)) if args.limits_overrides else {}
 result={"ttl":args.ttl,"limits":validate_policy({"mode":args.limits_mode,"operator_overrides":overrides})}
 for component in ("gate","guard","credited"):
  path=getattr(args,component+"_config")
  if path: result[component+"_config"]=str(path.absolute())
 if args.envelope_config: result["envelope_config"]=str(args.envelope_config.absolute())
 if args.metrics: result["metrics_path"]=str(args.metrics.absolute())
 return result

def service_context(args):
 from protocol_context import validate_context, minimal_context
 if args.protocol_envelope and args.protocol_file: raise ValueError("choose one S6P1 source")
 if args.protocol_file:
  from service_storage import private_read
  return validate_context(private_read(args.protocol_file).decode().strip())
 return validate_context(args.protocol_envelope) if args.protocol_envelope else minimal_context(args.core)

def load_service_config(path):
 from service_storage import private_read, strict_json
 config=strict_json(private_read(path))
 if isinstance(config,dict) and isinstance(config.get("config_path"),str):
  native=Path(config["config_path"]).expanduser()
  if not native.is_absolute(): config={**config,"config_path":str((path.absolute().parent/native).absolute())}
 return config

def recovery_hint(error, name="NAME"):
 """Offer fixed operator steps without executing or guessing a Core."""
 text=str(error)
 if "CoreSelectionRequired" in text:
  return "Choose explicitly: shadow6 core profiles --installed; then shadow6 setup NAME --core CORE --profile PROFILE --config /absolute/path/binding.json --run"
 if "0600" in text or "owner" in text or "symlink" in text:
  return "Use a regular file owned by your account with mode 0600; inspect its path and permissions before retrying."
 if "No such file" in text or "config_path" in text:
  return "Prepare the selected Core's native configuration and an owner-only binding.json containing its absolute config_path; see shadow6 setup --help."
 if "drift" in text.lower() or "lock" in text.lower():
  return f"Inspect with shadow6 doctor {name}; stop the service and review changes before shadow6 relock {name}, shadow6 apply {name}, and shadow6 run {name}."
 if "unknown service" in text.lower() or "not found" in text.lower():
  return "List registered services with shadow6 service list; prepare a new service with shadow6 setup --help."
 return f"Run shadow6 doctor (environment) or shadow6 doctor {name} (service); use shadow6 setup --help for the first-run path."


def lifecycle_output(result, *, human=False, stage=None, name=None, error=False):
 stream=sys.stderr if error else sys.stdout
 if not human:
  print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2),file=stream)
  return
 if error:
  print("Error: "+str(result.get("error","unknown error")),file=stream)
  for issue in result.get("diagnostics",[]): print(f"{issue['code']}: {issue['message']} Next: {issue['action']}",file=stream)
 else:
  print("Shadow6 "+str(stage or result.get("stage","diagnostic"))+(" · "+name if name else ""),file=stream)
  for key in ("core","profile","state","healthy","verified","materialValid","lockValid","featureReportValid","available","availableProfiles","removed","prefix","exit_code"):
   if key in result: print(f"{key}: {result[key]}",file=stream)
  binding=result.get("coreBinding") or {}
  if binding: print("Core: "+str(binding.get("core")),file=stream)
  if result.get("services") == []: print("No Named Services yet. Next: shadow6 doctor --human; shadow6 setup --help (choose Core/Profile explicitly).",file=stream)
  for service in result.get("services",[]):
   print(f"{service['name']}: Core={(service.get('coreBinding') or {}).get('core')} Profile={(service.get('profileBinding') or {}).get('profile')} state={service.get('state')}",file=stream)
  profile_binding=result.get("profileBinding") or {}
  if profile_binding: print("Profile: "+str(profile_binding.get("profile")),file=stream)
  observation=result.get("runtimeObservation") or result.get("runtime") or {}
  for key in ("readiness","applicationReadiness","transportReadiness","endpoint"):
   if key in observation: print(f"{key}: {json.dumps(observation[key],ensure_ascii=False)}",file=stream)
  if result.get("privacyTelemetry"):
   privacy=result["privacyTelemetry"]
   print(f"S6EPE Carrier: {privacy.get('carrier','raw/unknown')} · observation: {privacy.get('observation','unknown')}",file=stream)
  for item in result.get("profiles",[]):
   print(f"{item['core']} / {item['profile']}: {'available' if item['available'] else 'unavailable'}",file=stream)
   for issue in item.get("diagnostics",[]): print(f"  {issue['code']}: {issue['message']} Next: {issue['action']}",file=stream)
  for finding in result.get("findings",[]): print("Finding: "+str(finding),file=stream)
  for issue in result.get("diagnostics",[]): print(f"{issue['code']}: {issue['message']} Next: {issue['action']}",file=stream)
  if result.get("python"):
   print("Python: "+result["python"]["executable"],file=stream)
   for issue in result["python"]["errors"]: print("Dependency: "+issue,file=stream)
 if result.get("runtimeMaterialsMissing"):
  print("Runtime materials missing: "+", ".join(result["runtimeMaterialsMissing"]),file=stream)
 if result.get("privacyEnvelope"):
  envelope=result["privacyEnvelope"]
  print("S6EPE executable: "+envelope["executable"],file=stream)
  print("S6EPE available: "+str(envelope["available"]),file=stream)
  for issue in envelope.get("diagnostics",[]): print(f"{issue['code']}: {issue['message']} Next: {issue['action']}",file=stream)
  print("S6EPE: "+envelope["hint"],file=stream)
 if result.get("hint"): print("Next: "+result["hint"],file=stream)
 if not error and name and stage:
  steps={"setup":f"shadow6 status {name}; shadow6 doctor {name}; shadow6 run {name}","run":f"shadow6 status {name}; shadow6 doctor {name}; shadow6 connect {name}","status":f"shadow6 doctor {name}; shadow6 connect {name} (requires observed application readiness)","stop":f"shadow6 run {name}","relock":f"shadow6 apply {name}; shadow6 run {name}","lock":f"shadow6 apply {name}; shadow6 run {name}","restart":f"shadow6 status {name}; shadow6 doctor {name}"}
  if stage=="setup": steps[stage]=(f"shadow6 status {name}; shadow6 doctor {name}; shadow6 connect {name}" if result.get("state")=="running" else f"shadow6 run {name}; shadow6 status {name}; shadow6 doctor {name}")
  if stage in steps: print("Next: "+steps[stage],file=stream)


LIFECYCLE_ACTIONS = ("run","status","restart","stop","remove","apply","lock","relock","doctor")


def lifecycle_action(action, name, *, human=False):
 if ServiceRegistry is None: raise ValueError("Named Service Python dependencies unavailable; run shadow6 doctor --human")
 registry=ServiceRegistry(catalog=CoreCatalog(ROOT))
 handler=registry.lock if action=="relock" else getattr(registry,action)
 try: result=handler(name)
 except (ValueError,OSError) as error:
  lifecycle_output({"schema":"shadow6.lifecycle-error.v1","stage":action,"error":str(error),"hint":recovery_hint(error,name)},human=human,stage=action,name=name,error=True)
  return 2
 lifecycle_output(result,human=human,stage=action,name=name)
 return 0


def install_inspection(catalog):
 from profile_availability import installed_profiles
 report=installed_profiles(catalog)
 checks=[{"core":core["id"],"available":Path(core["executable"]).is_file(),"executable":os.access(core["executable"],os.X_OK)} for core in catalog.list()]
 return {**report,"schema":"shadow6.lifecycle.v1","stage":"install","operation":"inspect",
         "verified":bool(report['availableProfiles']),"cores":checks,
         "hint":"Use the extracted CLI directly from any cwd, or shadow6 install --prefix /absolute/writable/path to install existing artifacts without building; choose Core/Profile explicitly with shadow6 setup --help."}


def envelope_feature_report(catalog):
 path=catalog.envelope_binary()
 if not path.is_file():
  return {"schema":"shadow6.privacy-envelope.v1","implementation":"ocaml","available":False,
          "diagnostics":[{"code":"EnvelopeArtifactMissing","message":"Optional S6EPE artifact is absent.","action":"Supply a matching prebuilt artifact only if the deployment uses S6EPE; native services do not require it."}]}
 from service_runtime import feature_report
 from privacy_envelope import feature_availability
 report=feature_report(str(path),require_core=False)
 return {**report,**feature_availability(report)}


def environment_doctor():
 """Reuse bounded Profile and Python probes; never create registry state."""
 sys.path.insert(0,str(ROOT/"Tools"))
 from python_runtime import runtime_report
 from profile_availability import installed_profiles
 python=runtime_report("network")
 catalog=CoreCatalog(ROOT)
 report=installed_profiles(catalog)
 from service_runtime import runtime_material_paths, runtime_material_digest
 missing=[]
 material_diagnostics=[]
 for key,path in runtime_material_paths(ROOT).items():
  try: runtime_material_digest(key,path)
  except (ValueError,OSError) as error:
   missing.append(key)
   material_diagnostics.append({"code":"RuntimeMaterialUnavailableOrUnsafe","message":key+": "+str(error),
       "action":"Inspect "+str(path)+"; restore a trusted regular owner-controlled file without group/world write permissions. Review changes before explicitly relocking stopped services."})
 try: envelope_report=envelope_feature_report(catalog)
 except (ValueError,OSError,subprocess.SubprocessError) as error:
  envelope_report={"available":False,"diagnostics":[{"code":"EnvelopeFeatureContractUnavailable","message":str(error),"action":"Inspect the optional S6EPE artifact and bundled runtime libraries; supply a matching prebuilt package."}]}
 envelope={**envelope_report,"executable":str(catalog.envelope_binary()),"present":catalog.envelope_binary().is_file(),
           "hint":"Optional: shadow6 privacy-envelope feature-report checks the executable's compiled carriers. SCTP needs Linux kernel SCTP and compatible native message associations; WebRTC needs libdatachannel and explicit Nim/WebRTC binding, private S6SG1 signaling and reachable ICE candidates. Both need message mode, explicit channel policy and authenticated readiness; neither is selected automatically."}
 return {**report,"schema":"shadow6.environment-doctor.v1","stage":"doctor",
         "root":str(ROOT),"python":python,"runtimeMaterialsMissing":missing,"diagnostics":material_diagnostics,"privacyEnvelope":envelope,
         "healthy":bool(report["availableProfiles"]) and python["usable"] and ServiceRegistry is not None and not missing,
         "hint":"Choose a Core/Profile explicitly from availableProfiles; prepare its native config and run shadow6 setup --help. If dependencies are missing, use the package's compatible Python environment or the documented minimal runtime requirements; compilers are unnecessary for prebuilt products."}


def main():
 raw=sys.argv[1:]
 if not raw: raw=["--help"]
 events=bool(raw and raw[0]=="--json-events")
 if events:raw=raw[1:]
 if ServiceRegistry is None and raw and raw[0] in {"init","service","setup","run","status","restart","stop","remove","apply","lock","relock"} and not any(flag in raw for flag in ("--help","-h")):
  if __name__ == "__main__":
   sys.path.insert(0,str(ROOT/"Tools"))
   try:
    from python_runtime import bootstrap
    bootstrap(ROOT,Path(__file__).resolve())
   except RuntimeError:
    pass
  raise ValueError("Named Service Python dependencies unavailable; run shadow6 doctor --human and use a compatible package Python environment")
 if raw and raw[0] in {"install", "init"} and raw[1:] in ([], ["--json"], ["--human"]):
  catalog=CoreCatalog(ROOT)
  if raw[0]=="init": result=ServiceRegistry(catalog=catalog).init()
  else: result=install_inspection(catalog)
  lifecycle_output(result,human="--human" in raw,stage=raw[0]); return 0
 if raw and raw[0] in COMPONENTS and raw[0] not in {"virtual-broker","virtual-client","virtual-agent","deployment","acceptance","privacy-envelope"}:
  args=raw[1:];return run(raw[0],args[1:] if args[:1]==["--"] else args,events)
 p=argparse.ArgumentParser(prog="shadow6",description="Explicit Core/Profile → setup/run → status/doctor → connect",epilog="Start: shadow6 doctor --human; shadow6 setup --help. JSON is the default; lifecycle commands also accept --human.");p.add_argument("--json-events",action="store_true");sub=p.add_subparsers(dest="command",required=True)
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
 x=core_sub.add_parser("profiles",help="inspect Native Profile source contracts; availability requires runtime verification"); x.add_argument("core",nargs="?"); x.add_argument("--installed",action="store_true",help="probe installed artifacts and runtime prerequisites without building")
 for action in ("inspect","config-schema"):
  x=core_sub.add_parser(action); x.add_argument("core")
 x=core_sub.add_parser("validate-config"); x.add_argument("core"); x.add_argument("config",type=Path)
 x=core_sub.add_parser("import"); x.add_argument("descriptor",type=Path)
 q=sub.add_parser("service",help="manage named explicitly-bound services")
 ss=q.add_subparsers(dest="service_action",required=True); ss.add_parser("list")
 x=ss.add_parser("inspect"); x.add_argument("name")
 x=ss.add_parser("create"); x.add_argument("name"); x.add_argument("--core"); x.add_argument("--profile"); x.add_argument("--config",type=Path); add_service_options(x)
 x=ss.add_parser("configure"); x.add_argument("name"); x.add_argument("--core"); x.add_argument("--profile"); x.add_argument("--config",type=Path); add_service_options(x)
 x=ss.add_parser("upgrade",help="atomically replace, lock and apply a stopped service"); x.add_argument("name"); x.add_argument("--core"); x.add_argument("--profile"); x.add_argument("--config",type=Path); add_service_options(x)
 for action in ("run","connect"):
  x=ss.add_parser(action); x.add_argument("name")
 for action in ("lock","apply","status","restart","stop","remove","doctor","signal"):
  x=ss.add_parser(action,aliases=["relock"] if action=="lock" else []); x.add_argument("name")
 for parser in set(ss.choices.values()):
  output=parser.add_mutually_exclusive_group(); output.add_argument("--json",action="store_true",help="structured JSON (default)"); output.add_argument("--human",action="store_true",help="readable summary and next steps")
 for action in LIFECYCLE_ACTIONS:
  q=sub.add_parser(action,help=("diagnose environment or a named service" if action=="doctor" else action+" a named service"),description=("Without NAME, diagnose host, Python dependencies, installed Profiles and package runtime materials. With NAME, diagnose its binding, lock, drift and observed readiness." if action=="doctor" else "Review current materials and explicitly replace a stopped service lock; follow with apply and run." if action=="relock" else action+" uses the explicitly bound Core/Profile; no automatic selection or repair."),epilog="Example: shadow6 "+action+" home/nas --human")
  q.add_argument("name",nargs="?" if action=="doctor" else None); output=q.add_mutually_exclusive_group(); output.add_argument("--json",action="store_true",help="structured JSON (default)"); output.add_argument("--human",action="store_true",help="readable summary and next steps")
 # init retains its native init-system routing when arguments are supplied.
 q=sub.add_parser("install",help="inspect or install existing artifacts without compiling",description="Without arguments, inspect package artifacts. Global installation is optional; --prefix reuses the existing prebuilt installer.",epilog="Inspect: shadow6 install --human. Install: shadow6 install --prefix /absolute/writable/prefix")
 q.add_argument("--prefix",type=Path,help="absolute writable prefix; optional for using the extracted package directly"); q.add_argument("--destdir",type=Path)
 output=q.add_mutually_exclusive_group(); output.add_argument("--json",action="store_true",help="JSON inspection/result; installer logs go to stderr"); output.add_argument("--human",action="store_true",help="readable inspection/result and next steps")
 q=sub.add_parser("setup",help="prepare a named service; --run also starts it",description="Select --core explicitly. Use --native-config for an existing private Core configuration, or --config for a private binding JSON containing config_path. No credentials are generated.",epilog="Inspect: shadow6 doctor --human\nCheck: shadow6 setup home/nas --core go --profile go-kcp --config /absolute/path/binding.json --check\nStart: shadow6 setup home/nas --core go --profile go-kcp --native-config /absolute/path/core.json --run\nObserve: shadow6 status home/nas; shadow6 doctor home/nas; shadow6 connect home/nas",formatter_class=argparse.RawDescriptionHelpFormatter)
 q.add_argument("name"); q.add_argument("--core",help="required explicit Core identity; inspect core profiles --installed"); q.add_argument("--profile",help="explicit Native Profile ID; primary Profile of the selected Core if omitted"); binding_source=q.add_mutually_exclusive_group(); binding_source.add_argument("--config",type=Path,help="private binding.json (relative config_path resolves beside this file)",default=Path.home()/'.config/shadow6/binding.json'); binding_source.add_argument("--native-config",type=Path,help="use an existing private native configuration directly; reuse the same CoreBinding contract"); add_service_options(q); output=q.add_mutually_exclusive_group(); output.add_argument("--json",action="store_true",help="structured JSON (default)"); output.add_argument("--human",action="store_true",help="readable summary and next steps"); q.add_argument("--check",action="store_true",help="check Profile and binding without creating a service"); q.add_argument("--run",dest="start_service",action="store_true",help="explicitly start the prepared service")
 q=sub.add_parser("privacy-envelope",help="inspect the optional OCaml authenticated external envelope")
 q.add_argument("action",choices=("status","feature-report","compatibility","run")); q.add_argument("--core",action="append"); q.add_argument("--metrics",type=Path); q.add_argument("--config",type=Path)
 a=p.parse_args((["--json-events"] if events else [])+raw);tail=lambda v:v[1:] if v[:1]==["--"] else v
 if a.command in LIFECYCLE_ACTIONS:
  if a.command=="doctor" and a.name is None:
   result=environment_doctor(); lifecycle_output(result,human=a.human,stage="doctor"); return 0 if result["healthy"] else 1
  return lifecycle_action(a.command,a.name,human=a.human)
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
  elif a.core_action=="profiles":
   if a.installed:
    from profile_availability import inspect_profile
    checks=[inspect_profile(catalog,p['core'],p['id']) for p in profiles(a.core)]
    result={"schema":"shadow6.installed-profile-catalog.v1","profiles":checks,"availableProfiles":[p['profile'] for p in checks if p['available']]}
   else: result={"schema":"shadow6.native-profile-catalog.v1","sourceContracts":True,"profiles":profiles(a.core)}
  elif a.core_action=="inspect": result=catalog.inspect(a.core)
  elif a.core_action=="config-schema": result=catalog.inspect(a.core)["configurationSchema"]
  elif a.core_action=="validate-config": result={"valid":True,"core":a.core,"config":catalog.binding(a.core,json.loads(a.config.read_text()))["config"]}
  else: result=catalog.import_file(a.descriptor)
  print(json.dumps(result,ensure_ascii=True,sort_keys=True,indent=2)); return 0
 if a.command=="service":
  if a.service_action in {"create","configure","upgrade"} and not a.core: raise ValueError("CoreSelectionRequired")
  if a.service_action in {"configure","upgrade"} and not a.config: raise ValueError("--config is required")
  registry=ServiceRegistry(catalog=CoreCatalog(ROOT))
  if a.service_action=="list": result={"schema":"shadow6.service-registry.v2","services":registry.list()}
  elif a.service_action=="inspect": result=registry.inspect(a.name)
  elif a.service_action in {"create","configure","upgrade"}:
   config=load_service_config(a.config) if a.config else None
   if a.service_action=="create": result=registry.create(a.name,core=a.core,profile=a.profile,config=config,privacy=a.privacy,spec=service_spec(a),context=service_context(a))
   elif a.service_action=="upgrade": result=registry.upgrade(a.name,core=a.core,profile=a.profile,config=config,privacy=a.privacy,spec=service_spec(a),context=service_context(a))
   else: result=registry.configure(a.name,core=a.core,profile=a.profile,config=config,privacy=a.privacy,spec=service_spec(a),context=service_context(a))
  elif a.service_action in {"lock","relock"}: result=registry.lock(a.name)
  elif a.service_action=="apply": result=registry.apply(a.name)
  elif a.service_action=="doctor": result=registry.doctor(a.name)
  elif a.service_action=="signal": result=registry.webrtc_signal_endpoint(a.name)
  elif a.service_action=="status":
   item=registry.status(a.name); result={**item,"privacyTelemetry":item.get("privacyTelemetry",{})}
  elif a.service_action=="restart": result=registry.restart(a.name)
  elif a.service_action=="stop": result=registry.stop(a.name)
  elif a.service_action=="remove": result=registry.remove(a.name)
  else: result=registry.run(a.name) if a.service_action=="run" else registry.connect(a.name)
  lifecycle_output(result,human=a.human,stage=a.service_action,name=getattr(a,"name",None)); return 0
 if a.command=="install":
  if a.prefix is None:
   if a.destdir is not None: raise ValueError("--destdir requires an explicit --prefix")
   lifecycle_output(install_inspection(CoreCatalog(ROOT)),human=a.human,stage="install"); return 0
  import re
  if any(not path.is_absolute() or not re.fullmatch(r"/[A-Za-z0-9_./-]+",str(path)) or ".." in path.parts for path in (a.prefix,a.destdir) if path is not None):
   raise ValueError("installation paths must be absolute ASCII paths using letters, digits, slash, dot, underscore or hyphen")
  installed=subprocess.run(["make","install-prebuilt","PREFIX="+str(a.prefix)]+(["DESTDIR="+str(a.destdir)] if a.destdir else []),cwd=ROOT,stdout=sys.stderr if a.json else None,check=False)
  if a.json or a.human:
   prefix=a.destdir/a.prefix.relative_to("/") if a.destdir else a.prefix
   lifecycle_output({"schema":"shadow6.lifecycle.v1","stage":"install","operation":"install-prebuilt","prefix":str(prefix),"exit_code":installed.returncode,"verified":installed.returncode==0,"hint":str(prefix/"bin/shadow6")+" doctor --human" if installed.returncode==0 else "Inspect installer diagnostics above; the existing installer retains the old prefix on failed admission."},human=a.human,stage="install")
  return installed.returncode
 if a.command=="setup":
  if not a.core: raise ValueError("CoreSelectionRequired")
  if a.check and a.start_service: raise ValueError("--check cannot start a service")
  catalog=CoreCatalog(ROOT)
  if not a.check and ServiceRegistry is None: raise ValueError("Named Service Python dependencies unavailable; run shadow6 doctor")
  registry=None if a.check else ServiceRegistry(catalog=catalog)
  try:
   from profile_availability import inspect_profile
   availability=inspect_profile(catalog,a.core,a.profile)
   if not availability['available']:
    lifecycle_output({"schema":"shadow6.lifecycle-error.v1","stage":"setup","error":"ProfileUnavailable","profile":availability['profile'],"diagnostics":availability['diagnostics'],"hint":"Run shadow6 doctor --human; explicitly choose an available Core/Profile or supply the missing runtime prerequisite."},human=a.human,error=True); return 2
   if a.native_config:
    from service_storage import private_read
    private_read(a.native_config)
    config={"config_path":str(a.native_config.expanduser().absolute())}
   else: config=load_service_config(a.config)
   spec=service_spec(a); context=service_context(a)
   if a.check:
    catalog.binding(a.core,config)
    bind_profile(a.core,a.profile)
    lifecycle_output({"schema":"shadow6.setup-check.v1","service":a.name,
        "core":a.core,"profile":availability['profile'],"available":True},human=a.human,stage="check",name=a.name)
    return 0
   result=registry.setup(a.name,core=a.core,profile=a.profile,config=config,privacy=a.privacy,
                         spec=spec,context=context,start=a.start_service)
  except (ValueError,OSError,json.JSONDecodeError) as exc:
   error=str(exc)
   lifecycle_output({"schema":"shadow6.lifecycle-error.v1","stage":"setup","error":error,"hint":recovery_hint(error,a.name)},human=a.human,stage="setup",name=a.name,error=True); return 2
  lifecycle_output(result,human=a.human,stage="setup",name=a.name); return 0
 if a.command=="privacy-envelope":
  from privacy_envelope import read_metrics, compatibility
  if a.action=="run":
   if not a.config: raise ValueError("privacy-envelope run requires --config")
   from service_runtime import executable
   return subprocess.run([executable(CoreCatalog(ROOT).envelope_binary()),"--config",str(a.config.absolute())],check=False).returncode
  if a.action=="status": result=read_metrics(a.metrics)
  elif a.action=="feature-report": result=envelope_feature_report(CoreCatalog(ROOT))
  else: result={"schema":"shadow6.privacy-envelope-compatibility.v1","cores":[compatibility(c) for c in (a.core or list(CoreCatalog(ROOT)._items))]}
  print(json.dumps(result,sort_keys=True,indent=2)); return 1 if a.action=="feature-report" and not result["available"] else 0
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
if __name__=="__main__":
 try: raise SystemExit(main())
 except (ValueError, OSError, ImportError, subprocess.SubprocessError) as exc:
  lifecycle_output({"schema":"shadow6.lifecycle-error.v1","error":str(exc),"hint":recovery_hint(exc)},human="--human" in sys.argv,error=True)
  raise SystemExit(2)
