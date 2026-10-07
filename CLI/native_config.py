#!/usr/bin/env python3
"""Strict, standalone JSON adapters for four native datagram Core contracts."""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import sys

try:
    from Deployment.service_storage import strict_json as portable_json
except ImportError:
    import sys
    from pathlib import Path
    for _json_path in (Path(__file__).resolve().parents[1] / 'Deployment',
                       Path(__file__).resolve().parents[1] / 'deployment'):
        if (_json_path / 'service_storage.py').is_file():
            sys.path.insert(0, str(_json_path)); break
    from service_storage import strict_json as portable_json

for _modules in (Path(__file__).resolve().parent, Path(__file__).resolve().parents[1] / 'Crosed',
                 Path(__file__).resolve().parents[1] / 'modules'):
    if (_modules / 'native_profiles.py').is_file():
        sys.path.insert(0, str(_modules))
        break
from native_profiles import profiles

CORES = tuple(p['core'] for p in profiles() if p['applicationBoundary']['mode'] == 'seqpacket-fd')
ROLES = ('broker', 'agent', 'client')

def secure_read(path, limit=16384):
    path = Path(path)
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        opened = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_uid, s.st_nlink, s.st_mtime_ns, s.st_ctime_ns)
        if not stat.S_ISREG(opened.st_mode) or identity(before) != identity(opened):
            raise ValueError('configuration must be a stable regular non-symlink file')
        if opened.st_size > limit or opened.st_nlink != 1:
            raise ValueError('configuration size/link limit')
        if os.name != 'nt' and (opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o600):
            raise ValueError('configuration requires owner and mode 0600')
        data = os.read(fd, limit + 1)
        if len(data) > limit or identity(opened) != identity(os.fstat(fd)):
            raise ValueError('configuration changed while reading')
        return data
    finally:
        os.close(fd)

def write_new(path, data):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or (os.name != 'nt' and (parent.st_uid != os.geteuid() or parent.st_mode & 0o022)):
        raise ValueError('output directory must be owner-controlled')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)

def configuration_fields(core, role):
    """Expose the same normalized native field contract to operator forms."""
    if core not in CORES or role not in ROLES:
        raise ValueError('invalid core or role')
    fields = {'core', 'role', 'listen_port'}
    if core == 'hare':
        fields |= {'target_port', 'peer_public_key'}
        fields |= {'client_port', 'agent_public_key'} if role == 'broker' else {'private_key'}
    elif core == 'pony':
        fields |= {'peer_port', 'application_port', 'private_key', 'peer_public_key'}
    else:
        fields |= {'peer_port', 'application_port', 'key_material'}
        if core == 'idris':
            fields |= {'listen_host', 'peer_host', 'application_host', 'iterations'}
    return fields


def validate(config):
    if type(config) is not dict:
        raise ValueError('invalid core or role')
    core, role = config.get('core'), config.get('role')
    fields = configuration_fields(core, role)
    if set(config) != fields:
        raise ValueError('missing or unsupported native configuration fields')
    for field, value in config.items():
        if field.endswith('_port'):
            if type(value) is not int or not 1 <= value <= 65535:
                raise ValueError('port must be an integer in 1..65535')
        elif field.endswith('_key') or field == 'key_material':
            size = 192 if field == 'key_material' else 64
            if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{%d}' % size, value):
                raise ValueError('invalid hexadecimal key')
        elif field.endswith('_host'):
            if not isinstance(value, str) or not ipaddress.ip_address(value).is_loopback or ipaddress.ip_address(value).version != 4:
                raise ValueError('this adapter supports numeric loopback hosts only')
    if core == 'hare' and role == 'client' and config['listen_port'] == 65535:
        raise ValueError('Hare requires listen_port + 1')
    if core == 'idris' and (type(config['iterations']) is not int or not 1 <= config['iterations'] <= 1000000):
        raise ValueError('iterations must be in 1..1000000')
    if core in ('carp', 'idris') and role == 'broker' and bytes.fromhex(config['key_material'])[:32] != bytes(32):
        raise ValueError('broker key material must not contain a private seed')
    return config

def load(path):
    return validate(portable_json(secure_read(path), limit=16384))

def prepare(config, binary, directory):
    """Return argv, creating only private native input files in directory."""
    validate(config)
    core, role = config['core'], config['role']
    path = Path(directory) / 'native.config'
    if core in ('hare', 'pony'):
        write_new(path, json.dumps({k:v for k,v in config.items() if k != 'core'}, separators=(',', ':')).encode())
        return [str(binary), '--config', str(path)]
    write_new(path, bytes.fromhex(config['key_material']))
    ports = [str(config[k]) for k in ('listen_port', 'peer_port', 'application_port')]
    if core == 'carp':
        return [str(binary), '--' + role, str(path), *ports]
    return [str(binary), '--chain', role, config['listen_host'], ports[0], config['peer_host'], ports[1], config['application_host'], ports[2], str(path), str(config['iterations'])]

def native_binary(core):
    here = Path(__file__).resolve().parent
    installed = here / ('shadow6-' + core)
    if installed.is_file():
        return installed
    return here.parent / ('Core-' + core.capitalize()) / ('shadow6-' + core)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--check-config', action='store_true')
    parser.add_argument('--emit', type=Path, help='new directory for native files and argv.json; does not execute')
    args = parser.parse_args()
    try:
        config = load(args.config)
        if args.check_config:
            print(json.dumps({'valid': True, 'core': config['core'], 'role': config['role']}))
            return 0
        binary = native_binary(config['core'])
        if args.emit:
            args.emit.mkdir(mode=0o700)
            argv = prepare(config, binary, args.emit.resolve())
            write_new(args.emit / 'argv.json', json.dumps(argv).encode())
            print(json.dumps({'argv_file': str(args.emit / 'argv.json')}))
            return 0
        with tempfile.TemporaryDirectory(prefix='shadow6-native-') as directory:
            argv = prepare(config, binary, directory)
            child = subprocess.Popen(argv)
            previous = {}
            try:
                for sig in (signal.SIGINT, signal.SIGTERM):
                    previous[sig] = signal.signal(sig, lambda signum, frame: child.send_signal(signum))
                return child.wait()
            finally:
                if child.poll() is None:
                    child.terminate()
                    try: child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill(); child.wait()
                for sig, handler in previous.items(): signal.signal(sig, handler)
    except (OSError, ValueError, RecursionError) as error:
        parser.exit(2, f'error: {error}\n')



def topology_configs(topo, keys, binding):
    """Translate one explicitly bounded loopback trio, rejecting lost semantics."""
    nodes = topo['nodes']
    if len(nodes) != 3 or {n['type'] for n in nodes} != set(ROLES):
        raise ValueError('native datagram adapter requires exactly one broker, agent and client')
    by_role = {n['type']: n for n in nodes}
    core = next(e.removeprefix('shadow6-') for e in nodes[0]['engines'] if e.removeprefix('shadow6-') in CORES)
    for node in nodes:
        for field in ('listen_host', 'advertise_host', 'ssh_host'):
            host = node.get(field, '127.0.0.1')
            if host != 'localhost' and not ipaddress.ip_address(host).is_loopback:
                raise ValueError('native datagram topology adapter supports one loopback host')
        unsupported = set(node) & {'domain', 'on_success', 'allow_local_discovery', 'auto_close_after'}
        if unsupported:
            raise ValueError('unsupported native datagram settings: ' + ', '.join(sorted(unsupported)))
    ports = {role: by_role[role].get('listen_port', default) for role, default in zip(ROLES, (41000, 41004, 41002))}
    application = ports['client'] + 1
    upstream = ports['broker'] + 1
    target = by_role['agent'].get('target_port', 9000)
    used = list(ports.values()) + [application, target] + ([upstream] if core == 'pony' else [])
    if len(set(used)) != len(used) or any(not 1 <= p <= 65535 for p in used):
        raise ValueError('native datagram ports collide or exceed range')
    result = {}
    for role, node in by_role.items():
        cfg = {'core': core, 'role': role, 'listen_port': ports[role]}
        if core == 'hare':
            cfg.update(target_port=ports['agent'] if role == 'broker' else target if role == 'agent' else ports['broker'],
                       peer_public_key=keys['client' if role in ('broker', 'agent') else 'agent'][0])
            if role == 'broker': cfg.update(client_port=ports['client'], agent_public_key=keys['agent'][0])
            else: cfg['private_key'] = keys[role][1]
        elif core == 'pony':
            cfg.update(peer_port=ports['agent'] if role == 'broker' else upstream if role == 'agent' else ports['broker'],
                       application_port=upstream if role == 'broker' else target if role == 'agent' else application,
                       private_key=keys[role][1], peer_public_key=keys['client' if role == 'agent' else 'agent'][0])
        else:
            material = '00' * 32 + keys['client'][0] + keys['agent'][0] if role == 'broker' else keys[role][1] + keys['client' if role == 'agent' else 'agent'][0] + binding
            cfg.update(peer_port=ports['client'] if role == 'broker' else ports['broker'],
                       application_port=ports['agent'] if role == 'broker' else target if role == 'agent' else application,
                       key_material=material)
            if core == 'idris':
                cfg.update(listen_host='127.0.0.1', peer_host='127.0.0.1', application_host='127.0.0.1', iterations=1000000)
        result[node['name']] = validate(cfg)
    return result


if __name__ == '__main__':
    raise SystemExit(main())
