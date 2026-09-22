#!/usr/bin/env python3
"""Probe installed Python runtimes; never install dependencies or force GIL off."""
from __future__ import annotations
import argparse
import importlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import sysconfig

PROFILES={"network":("cryptography.hazmat.primitives.ciphers.aead","cryptography.hazmat.primitives.asymmetric.ed25519"),
          "base":("aiohttp","asyncssh","cryptography.hazmat.primitives.ciphers.aead","yaml","rich","textual","typer")}


def runtime_report(profile="network"):
    errors=[]
    for module in PROFILES[profile]:
        try: importlib.import_module(module)
        except (ImportError,OSError) as exc: errors.append(f"{module}: {exc}")
    gil=bool(getattr(sys,"_is_gil_enabled",lambda:True)())
    threaded=bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
    return dict(schema="shadow6.python-runtime.v1",executable=sys.executable,version=list(sys.version_info[:3]),
                implementation=platform.python_implementation(),platform=platform.platform(),profile=profile,
                free_threaded_build=threaded,gil_enabled=gil,dependencies_ok=not errors,errors=errors,
                usable=sys.version_info>=(3,11) and not errors,
                preferred=sys.version_info[:2]==(3,14) and threaded and not gil and not errors)


def probe(executable,profile):
    try:
        result=subprocess.run([str(executable),str(Path(__file__).absolute()),"probe","--profile",profile],
                              capture_output=True,text=True,timeout=15,check=False)
        if result.returncode or len(result.stdout)>32768: raise ValueError(result.stderr[-1024:] or "probe failed")
        report=json.loads(result.stdout)
        if report.get("schema")!="shadow6.python-runtime.v1": raise ValueError("invalid runtime report")
        return report
    except (OSError,ValueError,subprocess.TimeoutExpired) as exc:
        return dict(executable=str(executable),usable=False,preferred=False,errors=[str(exc)])


def select_runtime(root,profile="network"):
    root=Path(root)
    relative=("Scripts/python.exe",) if os.name=="nt" else ("bin/python",)
    explicit=os.environ.get("SHADOW6_PYTHON")
    candidates=([explicit] if explicit else [])+[str(root/env/tail) for env in (".venv-ft",".venv") for tail in relative]
    candidates += [sys.executable]+[shutil.which(name) for name in ("python3.14t","python3.14","python3.13","python3")]
    reports=[]; seen=set()
    for candidate in candidates:
        if not candidate: continue
        path=shutil.which(candidate) or candidate
        absolute=os.path.abspath(path)
        if absolute in seen or not os.path.isfile(absolute): continue
        seen.add(absolute); report=probe(absolute,profile); reports.append(report)
        if report.get("usable") and (report.get("preferred") or (explicit and candidate==explicit)):
            return dict(selected=report,fallback=not report.get("preferred",False),reason="explicit runtime" if explicit and candidate==explicit else "Python 3.14 free-threaded with compatible dependencies",probes=reports)
    usable=[r for r in reports if r.get("usable")]
    if not usable: raise RuntimeError("no installed compatible Python: "+json.dumps(reports))
    selected=next((r for r in usable if r["version"][:2]==[3,14]),usable[0])
    return dict(selected=selected,fallback=True,reason="Python 3.14 without GIL unavailable, dependencies incompatible, or GIL enabled; using compatible runtime",probes=reports)


def bootstrap(root,script,profile="network"):
    if os.environ.get("SHADOW6_RUNTIME_SELECTED")==os.path.abspath(sys.executable): return
    report=select_runtime(root,profile)
    selected=report["selected"]["executable"]
    print("shadow6 Python runtime: "+json.dumps({k:v for k,v in report.items() if k!="probes"}),file=sys.stderr)
    if os.path.abspath(selected)!=os.path.abspath(sys.executable):
        environment=dict(os.environ,SHADOW6_RUNTIME_SELECTED=os.path.abspath(selected))
        os.execve(selected,[selected,str(script),*sys.argv[1:]],environment)


def main():
    parser=argparse.ArgumentParser(); parser.add_argument("action",choices=("probe","select"))
    parser.add_argument("--profile",choices=tuple(PROFILES),default="network")
    parser.add_argument("--root",type=Path,default=Path(__file__).resolve().parents[1])
    args=parser.parse_args()
    report=runtime_report(args.profile) if args.action=="probe" else select_runtime(args.root,args.profile)
    print(json.dumps(report,sort_keys=True))
    return 0 if report.get("usable",True) else 1


if __name__=="__main__": raise SystemExit(main())
