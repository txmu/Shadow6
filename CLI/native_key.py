#!/usr/bin/env python3
"""Create compatible Carp/Idris chain keys from one Public6 invitation."""
import argparse
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
for directory in (HERE.parent / 'Public6', HERE.parent / 'share/shadow6/tree/Public6', HERE.parent / 'share/shadow6/modules'):
    if directory.is_dir(): sys.path.insert(0, str(directory))
from join_code import peer_seed, peer_public
from native_config import write_new

def generate_native_key(core, role, code, output):
    if core not in ('carp', 'idris') or role not in ('broker', 'agent', 'client'):
        raise ValueError('expected Carp/Idris and broker/agent/client')
    # Domain-separated, identical binding at both endpoints; no additional secret
    # beyond the invitation is claimed. Never print the invitation or key bytes.
    binding = hashlib.sha256(b'shadow6.native-binding.v1\x00' + core.encode() + peer_seed(code, 'admission')).digest()
    client = bytes.fromhex(peer_public(code, f'core:{core}:client'))
    agent = bytes.fromhex(peer_public(code, f'core:{core}:agent'))
    material = bytes(32) + client + agent if role == 'broker' else peer_seed(code, f'core:{core}:{role}') + (client if role == 'agent' else agent) + binding
    write_new(output, material)
    return Path(output)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('code')
    parser.add_argument('--core', required=True, choices=('carp', 'idris'))
    parser.add_argument('--role', required=True, choices=('broker', 'agent', 'client'))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        print(generate_native_key(args.core, args.role, args.code, args.output))
    except (ValueError, OSError) as error:
        parser.exit(2, f'error: {error}\n')

if __name__ == '__main__': main()
