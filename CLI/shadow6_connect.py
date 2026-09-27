#!/usr/bin/env python3
"""One-click Public6 connection tool for all twelve Shadow6 Cores."""
import argparse, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if not (ROOT / "Public6").is_dir():
    ROOT = ROOT / "share/shadow6/tree"
sys.path.insert(0, str(ROOT / "Tools"))
from python_runtime import bootstrap
if __name__ == "__main__":
    bootstrap(ROOT, Path(__file__).resolve())
sys.path.insert(0, str(ROOT / "Public6"))
from join_code import resolve, install_peer

CORE_NAMES = ("go", "rust", "gleam", "ada", "nim", "pony", "zig", "d", "cpp", "idris", "hare", "carp")

from native_key import generate_native_key

def connect(code: str, core: str, role: str, output_dir: Path, carrier: str,
            gate_port: int, peer_port: int, interactive: bool, directory: str = None, profile: Path = None, pin: str = None, check: bool = False):
    """One-click connect: resolve join-code, install peer configs."""
    if core not in CORE_NAMES:
        raise ValueError(f"unknown core: {core}")
    if role not in ("client", "agent"):
        raise ValueError(f"role must be client or agent, got {role}")
    if carrier not in ("gate", "s6na"):
        raise ValueError(f"carrier must be gate or s6na, got {carrier}")
    
    if interactive:
        print(f"Connecting {core} {role} to Public6")
        print(f"Carrier: {carrier}")
        confirm = input("Proceed? [Y/n] ").strip().lower()
        if confirm and confirm != "y":
            print("Aborted")
            return
    
    if carrier == "s6na":
        raise ValueError("Connect Virtual Peer currently supports Gate only; use shadow6 network for S6NA configuration")
    resolved = resolve(code, directory=directory, manual_profile=profile, manual_pin=pin)
    if not any(route['core'] == core for route in resolved['routes']):
        raise ValueError("Core family is not offered by this node")
    if check:
        result = {"valid": True, "core": core, "role": role, "carrier": carrier}
        print(json.dumps(result))
        return result
    result = install_peer(code, resolved, core, role, output_dir, gate_port, peer_port)

    if core in ("carp", "idris"):
        key_file = output_dir / f"{role}.key"
        generate_native_key(core, role, code, key_file)
        print(f"Generated 96-byte native key: {key_file}")
    print(f"\nArtifacts: {output_dir}")
    print(f"1. shadow6-gate --config {output_dir}/gate.json")
    print(f"2. shadow6 virtual-{role} --config {output_dir}/virtual-peer.json")
    print("Native Core configuration must be prepared separately for its supported transport.")
    return result

def main():
    p = argparse.ArgumentParser(description="One-click Public6 connection")
    p.add_argument("code", help="40-char Public6 join code")
    p.add_argument("--core", required=True, choices=CORE_NAMES)
    p.add_argument("--role", required=True, choices=["client", "agent"])
    p.add_argument("--output", type=Path, default=Path.cwd() / "shadow6-public")
    p.add_argument("--carrier", choices=["gate", "s6na"], default="gate")
    p.add_argument("--gate-port", type=int, default=1086)
    p.add_argument("--peer-port", type=int, default=1087)
    p.add_argument("--interactive", action="store_true")
    p.add_argument("--directory", help="Public6 directory URL for join-code resolution")
    p.add_argument("--generate-key-only", action="store_true")
    p.add_argument("--profile", type=Path, help="owner-only manual profile")
    p.add_argument("--pin", help="manual Gate public-key pin")
    p.add_argument("--check", action="store_true", help="validate the invitation/profile without writing files")
    args = p.parse_args()
    
    if args.generate_key_only:
        if args.core not in ("carp", "idris"):
            p.error("--generate-key-only requires --core carp or idris")
        key_out = args.output / f"{args.role}.key"
        generate_native_key(args.core, args.role, args.code, key_out)
        print(f"Generated: {key_out}")
        return
    
    try:
        connect(args.code, args.core, args.role, args.output, args.carrier,
                args.gate_port, args.peer_port, args.interactive, args.directory, args.profile, args.pin, args.check)
    except (ValueError, OSError) as error:
        p.exit(2, f"error: {error}\n")

if __name__ == "__main__":
    main()
