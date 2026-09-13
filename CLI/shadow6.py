#!/usr/bin/env python3
"""Portable unified Shadow6 command router; invokes only fixed components."""
from __future__ import annotations
import argparse,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1] if (Path(__file__).resolve().parents[1]/"Makefile").is_file() else Path(os.environ.get("SHADOW6_ROOT","/usr/local/share/shadow6/tree"))
COMPONENTS={"repo":ROOT/"Online-Repository/shadow6_repo.py","portmap":ROOT/"Gate/portmap.py","go":ROOT/"Core-Go/shadow6-go","rust":ROOT/"Core-Rust/shadow6-rust","gate":ROOT/"Gate/shadow6-gate","relay":ROOT/"C11Relay/bridge_relay","guard":ROOT/"Guard/shadow6-guard","control":ROOT/"Control-Center/shadow6_control.py","plugins":ROOT/"Plugin-System/shadow6_plugins.py","sign-plugin":ROOT/"Plugin-System/sign_plugin.py","migrate":ROOT/"Migration/shadow6_migrate.py","auto":ROOT/"Auto-Orchestrator/shadow6_auto.py","detector":ROOT/"Detector/shadow6_detector.py","security":ROOT/"Security-Assistants/shadow6_security.py","infra":ROOT/"Infrastructure-Assistants/shadow6_infra.py","slots":ROOT/"Slot-System/shadow6_slots.py","packages":ROOT/"Package-Manager/shadow6_pkg.py","public6":ROOT/"Public6/shadow6_public.py","init":ROOT/"Service-Init/shadow6_init.py"}
if not (ROOT/"Makefile").is_file():
 bin_dir=Path(sys.argv[0]).resolve().parent
 COMPONENTS={name:bin_dir/("shadow6-"+name) for name in COMPONENTS}
 COMPONENTS.update({"go":bin_dir/"shadow6-go","rust":bin_dir/"shadow6-rust","control":bin_dir/"shadow6-control","sign-plugin":bin_dir/"shadow6-sign-plugin","packages":bin_dir/"shadow6-pkg","repo":bin_dir/"shadow6-repo","portmap":bin_dir/"shadow6-portmap"})
TRANSPORTS={"schema","rpc","mcp","lsp","openai-tools","openai-rpc","serve","call","privacy"}
def command_for(name,args):
 path=COMPONENTS.get(name)
 if path is None or not path.is_file():raise SystemExit(f"component unavailable: {name}")
 return ([sys.executable,str(path)] if path.suffix==".py" else [str(path)])+args
def run(name,args,events=False):
 if events:print(json.dumps({"event":"process.started","component":name,"argument_count":len(args)}),flush=True)
 result=subprocess.run(command_for(name,args),check=False)
 if events:print(json.dumps({"event":"process.finished","component":name,"exit_code":result.returncode}),flush=True)
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
 p=argparse.ArgumentParser(prog="shadow6");p.add_argument("--json-events",action="store_true");sub=p.add_subparsers(dest="command",required=True)
 q=sub.add_parser("guide",help="read a friendly getting-started guide / 查看中英文入门指引");q.add_argument("--lang",choices=("en","zh"),default="en")
 c=sub.add_parser("component");c.add_argument("name",choices=sorted(COMPONENTS));c.add_argument("args",nargs=argparse.REMAINDER)
 for name in sorted(TRANSPORTS):q=sub.add_parser(name);q.add_argument("args",nargs=argparse.REMAINDER)
 for name in sorted(COMPONENTS):q=sub.add_parser(name);q.add_argument("args",nargs=argparse.REMAINDER)
 add_hands_parser(sub)
 q=sub.add_parser("features");q.add_argument("--component",choices=("go","rust","gate"),action="append",default=[])
 q=sub.add_parser("vcore",help="discover installed cores and capability intersection");q.add_argument("args",nargs=argparse.REMAINDER)
 q=sub.add_parser("sign");ss=q.add_subparsers(dest="kind",required=True);sp=ss.add_parser("plugin");sp.add_argument("manifest");sp.add_argument("--private-key",required=True);sp.add_argument("--signer",required=True)
 q=sub.add_parser("workflow");q.add_argument("stage",choices=("build","test","check","audit","crosed-variants","android-apk","package","release"));q.add_argument("args",nargs=argparse.REMAINDER)
 a=p.parse_args();tail=lambda v:v[1:] if v[:1]==["--"] else v
 if a.command=="guide":return run("control",["guide","--lang",a.lang],a.json_events)
 if a.command=="hands":return run_hands(a)
 if a.command=="component":return run(a.name,tail(a.args),a.json_events)
 if a.command in COMPONENTS:return run(a.command,tail(a.args),a.json_events)
 if a.command in TRANSPORTS:return run("control",[a.command]+tail(a.args),a.json_events)
 if a.command=="features":return max(run(n,["--feature-report"],a.json_events) for n in (a.component or ["go","rust","gate"]))
 if a.command=="vcore":
  return subprocess.run([sys.executable, str(ROOT/"CLI"/"shadow6_vcore.py")]+tail(a.args), check=False).returncode
 if a.command=="sign":return run("sign-plugin",[a.manifest,"--private-key",a.private_key,"--signer",a.signer],a.json_events)
 stages=[a.stage] if a.stage!="release" else ["build","crosed-variants","test","check","audit","android-apk","package"]
 for stage in stages:
  result=subprocess.run(["make",stage]+a.args,cwd=ROOT,check=False)
  if result.returncode:return result.returncode
 return 0
if __name__=="__main__":raise SystemExit(main())
