"""Read process-owned Linux sockets and bounded structured ready events."""
import ipaddress
import json
import os
import socket
from pathlib import Path
try:
    from .service_storage import strict_json
except ImportError:
    from service_storage import strict_json


def sockets(pid):
    inodes = set()
    try:
        for fd in list((Path('/proc') / str(pid) / 'fd').iterdir())[:4096]:
            try:
                target = os.readlink(fd)
                if target.startswith('socket:['): inodes.add(target[8:-1])
            except OSError: pass
    except OSError: return []
    found = []
    for table in ('tcp','tcp6','udp','udp6'):
        try: rows = (Path('/proc') / str(pid) / 'net' / table).read_text().splitlines()[1:]
        except OSError: continue
        for line in rows:
            fields = line.split()
            if len(fields) < 10 or fields[9] not in inodes or table.startswith('tcp') and fields[3] != '0A': continue
            if table.startswith('udp') and int(fields[2].split(':')[1],16) != 0: continue
            host, port = fields[1].split(':')
            raw = bytes.fromhex(host)
            raw = b''.join(raw[n:n+4][::-1] for n in range(0,len(raw),4))
            address = socket.inet_ntop(socket.AF_INET6 if table.endswith('6') else socket.AF_INET, raw)
            found.append({'host':address, 'port':int(port,16), 'transport':'tcp' if table.startswith('tcp') else 'udp', 'observation':'process-owned-socket'})
    return sorted(found, key=lambda x:(x['transport'],x['host'],x['port']))[:64]


def private_socket(item):
    return ipaddress.ip_address(item['host']).is_loopback


def ready(line, core):
    value = strict_json(line)
    if not isinstance(value, dict) or set(value) - {'event','schema','core','role','application_boundary','endpoint'} or value.get('event') not in ('ready','shadow6.ready'):
        raise ValueError('invalid ready event')
    if value.get('role') != 'client' or value.get('schema') != 1 or type(value['schema']) is not int or value.get('core') not in (core,'shadow6-'+core): raise ValueError('ready identity mismatch')
    boundary = value.get('application_boundary')
    if not isinstance(boundary, dict) or set(boundary) - {'kind','mode','endpoint','max_record'} or boundary.get('kind') not in {'stream','message','credited'}:
        raise ValueError('ready boundary unavailable')
    target = boundary.get('endpoint')
    if not isinstance(target, dict) or set(target) != {'host','port'} or not isinstance(target['host'],str) or type(target['port']) is not int or not 1 <= target['port'] <= 65535:
        raise ValueError('invalid ready endpoint')
    if not ipaddress.ip_address(target['host']).is_loopback: raise ValueError('application ready endpoint must be loopback')
    return {'endpoint':{**target,'boundary':boundary['kind'],'mode':boundary.get('mode'), 'observation':'structured-ready-event'}, 'readiness':'application-ready'}
