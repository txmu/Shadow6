#!/usr/bin/env python3
"""One-click Public6 connection tool for all twelve Shadow6 Cores."""
import argparse, json, os, secrets, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "Tools"))
from python_runtime import bootstrap
bootstrap(ROOT, Path(__file__).resolve())
sys.path.insert(0, str(ROOT / "Public6"))
from join_code import peer_seed, peer_public, resolve, install_peer

CORE_NAMES = ("go", "rust", "gleam", "ada", "nim", "pony", "zig", "d", "cpp", "idris", "hare", "carp")

def generate_native_key(core: str, role: str, code: str, output: Path):
    """Generate 96-byte binary key for Carp/Idris cores."""
    if core not in ("carp", "idris"):
        raise ValueError(f"generate_native_key only for carp/idris, got {core}")
    seed_client = peer_seed(code, f"core:{core}:client")
    seed_agent = peer_seed(code, f"core:{core}:agent")
    pub_client = peer_public(code, f"core:{core}:client")
    pub_agent = peer_public(code, f"core:{core}:agent")
    binding = secrets.token_bytes(32)
    if role == "broker":
        material = bytes(32) + pub_client + pub_agent
    elif role == "agent":
        material = seed_agent + pub_client + binding
    elif role == "client":
        material = seed_client + pub_agent + binding
    else:
        raise ValueError(f"unknown role: {role}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(material)
    os.chmod(output, 0o600)
    return output

def connect(code: str, core: str, role: str, output_dir: Path, carrier: str,
            gate_port: int, peer_port: int, interactive: bool, directory: str = None):
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
    
    profile = resolve(code, directory=directory)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if core in ("carp", "idris"):
        key_file = output_dir / f"{role}.key"
        generate_native_key(core, role, code, key_file)
        print(f"Generated 96-byte native key: {key_file}")
        print(f"Usage: shadow6-{core} --chain {role} <broker-host> <broker-port> ...")
        return
    
    install_peer(code, profile, core, role, output_dir, gate_port, peer_port)
    
    if carrier == "s6na":
        vp_cfg = output_dir / "virtual-peer.json"
        if vp_cfg.exists():
            data = json.loads(vp_cfg.read_text())
            data.setdefault("gate", {})["carrier"] = "s6na"
            vp_cfg.write_text(json.dumps(data, indent=2, sort_keys=True))
            os.chmod(vp_cfg, 0o600)
            print(f"S6NA enabled in {vp_cfg}")
    
    print(f"\nArtifacts: {output_dir}")
    print(f"1. shadow6-gate --config {output_dir}/gate.json")
    print(f"2. shadow6 virtual-{role} --config {output_dir}/virtual-peer.json")
    print(f"3. shadow6-{core} --config {output_dir}/core-{role}.json --check-config")

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
    args = p.parse_args()
    
    if args.generate_key_only:
        if args.core not in ("carp", "idris"):
            p.error("--generate-key-only requires --core carp or idris")
        key_out = args.output / f"{args.role}.key"
        generate_native_key(args.core, args.role, args.code, key_out)
        print(f"Generated: {key_out}")
        return
    
    connect(args.code, args.core, args.role, args.output, args.carrier,
            args.gate_port, args.peer_port, args.interactive, args.directory)

if __name__ == "__main__":
    main()
