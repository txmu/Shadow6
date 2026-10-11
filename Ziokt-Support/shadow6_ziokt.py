#!/usr/bin/env python3
"""Native opt-in Ziokt provider; independent of the Ziokt repository."""
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
for candidate in (HERE, HERE.parent / "share/shadow6/modules"):
    if (candidate / "zfcp_runtime.py").is_file():
        sys.path.insert(0, str(candidate))
        break
from zfcp_runtime import main
for candidate in (HERE.parent / "Crosed", HERE.parent / "share/shadow6/modules"):
    if (candidate / "install_layout.py").is_file():
        sys.path.insert(0, str(candidate))
        break
from install_layout import tree_root

if __name__ == "__main__":
    raise SystemExit(main("shadow6", tree_root(__file__)))
