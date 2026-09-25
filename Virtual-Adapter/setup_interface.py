#!/usr/bin/env python3
"""Plan or explicitly create a local TUN/TAP interface; never run through an API."""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess

SUPPORTED = ('Linux', 'FreeBSD', 'OpenBSD', 'NetBSD', 'DragonFly')


def plan(*, name, mode='tun', owner, mtu=1400, address=None, system=None):
    system = system or platform.system()
    if mode not in ('tun', 'tap') or type(name) is not str or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,14}', name):
        raise ValueError('invalid interface name or mode')
    if type(owner) is not int or not 0 <= owner < 2**31 or type(mtu) is not int or not 1280 <= mtu <= 9000:
        raise ValueError('owner or MTU outside bounds')
    if address is not None:
        if type(address) is not str or len(address) > 64:
            raise ValueError('invalid interface address')
        parsed = ipaddress.ip_interface(address)
        if parsed.ip.is_multicast or parsed.ip.is_unspecified:
            raise ValueError('interface address must be unicast')
        address = str(parsed)
    if system not in SUPPORTED:
        reason = {'Darwin': 'utun requires a live platform VPN provider, not a persistent shell-created TUN',
                  'SunOS': 'illumos requires an explicitly provisioned compatible TUN/TAP driver',
                  'Windows': 'use an installed compatible Windows virtual-interface driver and administrator tooling'}.get(system, 'no supported interface creation backend')
        return dict(schema='shadow6.interface-plan.v1', supported=False, system=system, reason=reason, commands=[])
    commands = []
    if system == 'Linux':
        commands.append(['ip', 'tuntap', 'add', 'dev', name, 'mode', mode, 'user', str(owner)])
        if address:
            commands.append(['ip', 'address', 'add', address, 'dev', name])
        commands.append(['ip', 'link', 'set', 'dev', name, 'mtu', str(mtu), 'up'])
        rollback = ['ip', 'tuntap', 'del', 'dev', name, 'mode', mode]
        probe = ['ip', '-json', 'link', 'show']
    else:
        if not re.fullmatch(mode + r'[0-9]{1,4}', name):
            raise ValueError('BSD interface name must be tunN or tapN')
        commands.append(['ifconfig', name, 'create'])
        if address:
            family = 'inet6' if ipaddress.ip_interface(address).version == 6 else 'inet'
            commands.append(['ifconfig', name, family, address])
        commands.append(['ifconfig', name, 'mtu', str(mtu), 'up'])
        rollback = ['ifconfig', name, 'destroy']
        probe = ['ifconfig', '-l']
    return dict(schema='shadow6.interface-plan.v1', supported=True, system=system,
                name=name, mode=mode, owner=owner, mtu=mtu, address=address,
                commands=commands, probe=probe, rollback=rollback,
                root_required=True, changes_default_route=False, changes_forwarding=False,
                note='An assigned address may create a connected route. Forwarding, NAT and default routes require separate explicit administrator configuration.')


def trusted_tool(name):
    for directory in ('/usr/sbin', '/sbin', '/usr/bin', '/bin'):
        path = Path(directory, name).resolve()
        try:
            info = path.stat()
            if stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and os.access(path, os.X_OK):
                return str(path)
        except OSError:
            continue
    raise ValueError(f'root-owned system {name} executable not available')


def run(command):
    return subprocess.run([trusted_tool(command[0]), *command[1:]], check=True,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)


def apply_plan(value):
    if os.geteuid() != 0:
        raise PermissionError('--apply requires root; review the plan before using sudo')
    if not value['supported'] or value['system'] != platform.system():
        raise ValueError('plan is not supported on this host')
    existing = run(value['probe']).stdout
    if len(existing) > 1024 * 1024:
        raise ValueError('interface inventory exceeds limit')
    names = [entry['ifname'] for entry in json.loads(existing)] if value['system'] == 'Linux' else existing.split()
    if value['name'] in names:
        raise ValueError('interface already exists; refusing to modify it')
    created = False
    try:
        for command in value['commands']:
            run(command)
            created = True
        if value['system'] != 'Linux':
            device = Path('/dev', value['name'])
            descriptor = os.open(device, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            try:
                if not stat.S_ISCHR(os.fstat(descriptor).st_mode):
                    raise ValueError('TUN/TAP device is not a character device')
                os.fchown(descriptor, value['owner'], -1)
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
    except Exception:
        if created:
            run(value['rollback'])
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--mode', choices=('tun', 'tap'), default='tun')
    parser.add_argument('--owner', type=int, required=True, help='UID of the unprivileged interface consumer')
    parser.add_argument('--mtu', type=int, default=1400)
    parser.add_argument('--address')
    parser.add_argument('--apply', action='store_true', help='execute this plan as root')
    args = parser.parse_args()
    value = plan(name=args.name, mode=args.mode, owner=args.owner, mtu=args.mtu, address=args.address)
    print(json.dumps(value, indent=2))
    if args.apply:
        apply_plan(value)
    return 0 if value['supported'] else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f'interface setup failed: {error}')
