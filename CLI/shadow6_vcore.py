#!/usr/bin/env python3
"""VCore discovery: inspect installed cores using the fixed feature-report API."""
from __future__ import annotations
import json, subprocess
from pathlib import Path

CORE_PATHS = {
    "go": "Core-Go/shadow6-go", "rust": "Core-Rust/shadow6-rust",
    "zig": "Core-Zig/shadow6-zig", "ada": "Core-Ada/shadow6-ada",
    "d": "Core-D/shadow6-d", "nim": "Core-Nim/shadow6-nim",
    "cpp": "Core-Cpp/shadow6-cpp", "pony": "Core-Pony/shadow6-pony",
    "hare": "Core-Hare/shadow6-hare", "carp": "Core-Carp/shadow6-carp",
    "gleam": "Core-Gleam/shadow6-gleam", "idris": "Core-Idris/shadow6-idris",
}
MAX_REPORT = 131072

def _capabilities(report: dict) -> set[str]:
    value = report.get("capabilities", [])
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ValueError("feature report capabilities must be a string list")
    return set(value)

def discover(root: Path, timeout: float = 5.0) -> dict:
    if timeout <= 0 or timeout > 30: raise ValueError("timeout out of range")
    installed, reports, errors = [], {}, {}
    for name, relative in CORE_PATHS.items():
        binary = root / relative
        if not binary.is_file():
            continue
        try:
            result = subprocess.run([str(binary), "--feature-report"], capture_output=True,
                                    text=True, timeout=timeout, check=False)
            if result.returncode != 0: raise ValueError(f"exit {result.returncode}")
            if len(result.stdout.encode()) > MAX_REPORT: raise ValueError("report too large")
            report = json.loads(result.stdout, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite number")))
            if not isinstance(report, dict): raise ValueError("report must be object")
            reports[name] = report; installed.append(name)
        except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            errors[name] = str(exc)
    common = set.intersection(*(_capabilities(reports[n]) for n in installed)) if installed else set()
    return {"cores": reports, "installed": installed, "errors": errors,
            "capability_intersection": sorted(common)}

def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="shadow6 vcore")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    print(json.dumps(discover(args.root.resolve(), args.timeout), sort_keys=True))
    return 0

if __name__ == "__main__": raise SystemExit(main())
