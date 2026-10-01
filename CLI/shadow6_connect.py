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
from join_code import resolve, install_peer, unpack_invitation, resolve_protocol_envelope

CORE_NAMES = ("go", "rust", "gleam", "ada", "nim", "pony", "zig", "d", "cpp", "idris", "hare", "carp")

from native_key import generate_native_key
from native_config import secure_read, load as load_native, prepare, native_binary, write_new

def connect(code: str, core: str, role: str, output_dir: Path, carrier: str,
            gate_port: int, peer_port: int, interactive: bool, directory: str = None, profile: Path = None, pin: str = None, check: bool = False):
    """One-click connect: resolve join-code, install peer configs."""
    if not 1024 <= gate_port <= 65535 or not 1024 <= peer_port <= 65535 or gate_port == peer_port:
        raise ValueError("Gate and peer ports must be distinct and in 1024..65535")
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
    p.add_argument("code", nargs="?", help="40-char Public6 join code")
    p.add_argument("--core", choices=CORE_NAMES)
    p.add_argument("--role", choices=["client", "agent"])
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
    p.add_argument("--code-file", type=Path, help="read invitation from an owner-only 0600 file")
    p.add_argument("--invitation", help="single long S6INV1 invitation containing code, profile and Gate pin")
    p.add_argument("--protocol-envelope", help="universal S6P1 envelope; extracts its Public6 invitation when present")
    p.add_argument("--protocol-file", type=Path, help="read a complete S6P1 token from an owner-only file")
    p.add_argument("--list-routes", action="store_true", help="resolve invitation and show offered core transports without provisioning")
    p.add_argument("--native-config", type=Path, help="validate and emit a bounded native configuration alongside Virtual Peer files")
    args = p.parse_args()
    try:
        if args.protocol_envelope and args.protocol_file:
            raise ValueError("use only one of --protocol-envelope or --protocol-file")
        token = args.protocol_envelope
        if args.protocol_file:
            token = secure_read(args.protocol_file, 262144).decode("ascii").strip()
        if token:
            envelope, claims = resolve_protocol_envelope(token, component="public6")
            if args.core and envelope["core"] not in (args.core, "all"):
                raise ValueError("S6P1 Core does not match --core")
            if args.role and envelope["role"] not in (args.role, "all"):
                raise ValueError("S6P1 role does not match --role")
            args.core = args.core or (envelope["core"] if envelope["core"] != "all" else None)
            args.role = args.role or (envelope["role"] if envelope["role"] in ("client", "agent") else None)
            embedded = envelope.get("credentials", {}).get("public6_invitation")
            if not isinstance(embedded, str):
                raise ValueError("protocol envelope has no public6_invitation credential")
            args.invitation = embedded
        if args.invitation:
            invitation = unpack_invitation(args.invitation)
            args.code, args.profile, args.pin = invitation["code"], None, invitation["gate_public_key"]
            import tempfile
            temp = Path(tempfile.mkdtemp(prefix="shadow6-invitation-")) / "profile.json"
            temp.write_text(json.dumps(invitation["profile"], separators=(",", ":"))); temp.chmod(0o600)
            args.profile = temp
        elif bool(args.code or args.code_file) == bool(args.invitation):
            raise ValueError("provide exactly one of code, --code-file, --invitation or S6P1")
        if args.code_file: args.code = secure_read(args.code_file, 256).decode('ascii').strip()
        if args.list_routes:
            resolved = resolve(args.code, directory=args.directory, manual_profile=args.profile, manual_pin=args.pin)
            print(json.dumps({'routes': [{'core': route['core'], 'transport': route['transport']} for route in resolved['routes']]}))
            return
        if not args.core or not args.role: raise ValueError("--core and --role are required")
        native = load_native(args.native_config) if args.native_config else None
        if native and (native['core'], native['role']) != (args.core, args.role):
            raise ValueError("native configuration core/role differs from Connect selection")
        if args.generate_key_only and (args.check or native):
            raise ValueError("key-only cannot be combined with --check or --native-config")
    except (ValueError, OSError) as error:
        p.exit(2, f"error: {error}\n")
    
    if args.generate_key_only:
        if args.core not in ("carp", "idris"):
            p.error("--generate-key-only requires --core carp or idris")
        key_out = args.output / f"{args.role}.key"
        try:
            generate_native_key(args.core, args.role, args.code, key_out)
        except (ValueError, OSError) as error:
            p.exit(2, f"error: {error}\n")
        print(f"Generated: {key_out}")
        return
    
    try:
        connected = connect(args.code, args.core, args.role, args.output, args.carrier,
                args.gate_port, args.peer_port, args.interactive, args.directory, args.profile, args.pin, args.check)
        if native and not args.check and connected is not None:
            destination = args.output.resolve() / 'native'
            destination.mkdir(mode=0o700)
            argv = prepare(native, native_binary(args.core), destination)
            write_new(destination / 'argv.json', json.dumps(argv).encode())
            print(f"Native files and fixed argv: {destination}")
    except (ValueError, OSError) as error:
        p.exit(2, f"error: {error}\n")

if __name__ == "__main__":
    main()
