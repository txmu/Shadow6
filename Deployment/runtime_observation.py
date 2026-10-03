"""Read process-owned Linux sockets and bounded structured ready events."""
import ipaddress
import itertools
import json
import re
import os
import socket
import sys
from pathlib import Path
try:
    from .service_storage import strict_json
except ImportError:
    from service_storage import strict_json


def proc_address(encoded, *, ipv6=False, byteorder=None):
    """Linux proc socket addresses print native-endian 32-bit words."""
    order = sys.byteorder if byteorder is None else byteorder
    if order not in ('little','big'): raise ValueError('invalid proc socket byte order')
    raw = bytes.fromhex(encoded)
    if len(raw) != (16 if ipv6 else 4): raise ValueError('invalid proc socket address')
    if order == 'little':
        raw = b''.join(raw[n:n+4][::-1] for n in range(0,len(raw),4))
    return socket.inet_ntop(socket.AF_INET6 if ipv6 else socket.AF_INET, raw)



MAX_FDS = 4096
MAX_ROWS = 65536
MAX_SOCKETS = 64


def proc_rows(stream):
    def line():
        value=stream.readline(4096)
        if len(value)==4096 and not value.endswith('\n'):
            raise ValueError('socket observation row limit exceeded')
        return value
    line()  # Linux table header.
    for _ in range(MAX_ROWS):
        value=line()
        if not value:return
        yield value
    if stream.read(1):raise ValueError('socket observation table limit exceeded')


def sockets(pid):
    inodes = set()
    try:
        with os.scandir(Path('/proc') / str(pid) / 'fd') as entries:
            descriptors=list(itertools.islice(entries,MAX_FDS+1))
        if len(descriptors)>MAX_FDS:raise ValueError('process FD observation limit exceeded')
        for fd in descriptors:
            try:
                target = os.readlink(fd.path)
                if target.startswith('socket:['): inodes.add(target[8:-1])
            except OSError: pass
    except OSError: return []
    found = []
    for table in ('tcp','tcp6','udp','udp6'):
        try:
            with (Path('/proc') / str(pid) / 'net' / table).open() as stream:
                for line in proc_rows(stream):
                    fields = line.split()
                    if len(fields) < 10 or fields[9] not in inodes or table.startswith('tcp') and fields[3] != '0A': continue
                    if table.startswith('udp') and int(fields[2].split(':')[1],16) != 0: continue
                    host, port = fields[1].split(':')
                    address = proc_address(host, ipv6=table.endswith('6'))
                    found.append({'host':address, 'port':int(port,16), 'transport':'tcp' if table.startswith('tcp') else 'udp', 'observation':'process-owned-socket'})
                    if len(found)>MAX_SOCKETS:raise ValueError('owned listener observation limit exceeded')
        except OSError:continue
    return sorted(found, key=lambda x:(x['transport'],x['host'],x['port']))


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


def validate_observation(value):
    fields = {'observedAt','pid','processIdentity','processes','nativeEndpoints','endpoints',
              'endpoint','readiness','transportReadiness','applicationReadiness'}
    if not isinstance(value,dict) or set(value) != fields:
        raise ValueError('invalid runtime observation fields')
    def process(item):
        if not isinstance(item,dict) or set(item) != {'pid','processIdentity'} or type(item['pid']) is not int or item['pid'] <= 1 or not isinstance(item['processIdentity'],str) or re.fullmatch(r'[0-9a-f-]{36}:[0-9]+',item['processIdentity']) is None:
            raise ValueError('invalid observed process identity')
    process({k:value[k] for k in ('pid','processIdentity')})
    children=value['processes']
    if not isinstance(children,list) or not 1 <= len(children) <= 4:
        raise ValueError('invalid observed critical process list')
    for item in children:process(item)
    pids=[p['pid'] for p in children]
    if len(set(pids)) != len(pids) or value['pid'] in pids:
        raise ValueError('invalid observed process ownership')
    if type(value['observedAt']) is not int or value['observedAt'] < 0:
        raise ValueError('invalid observation timestamp')
    if value['readiness'] not in ('process-alive','listener-ready','application-ready') or value['transportReadiness'] not in ('unknown','unavailable') or value['applicationReadiness'] not in ('unknown','ready','unavailable'):
        raise ValueError('invalid observed readiness')
    def address(item):
        if not isinstance(item['host'],str) or type(item['port']) is not int or not 1 <= item['port'] <= 65535:
            raise ValueError('invalid observed endpoint')
        ipaddress.ip_address(item['host'])
    for field in ('nativeEndpoints','endpoints'):
        endpoints=value[field]
        if not isinstance(endpoints,list) or len(endpoints) > 64:
            raise ValueError('invalid observed endpoint list')
        for item in endpoints:
            if not isinstance(item,dict) or set(item) != {'host','port','transport','observation'} or item['transport'] not in ('tcp','udp') or item['observation'] != 'process-owned-socket':
                raise ValueError('invalid socket observation')
            address(item)
    target=value['endpoint']
    if value['readiness'] == 'application-ready':
        if not isinstance(target,dict) or set(target) != {'host','port','boundary','mode','observation','owner'} or target['observation'] != 'structured-ready-event' or target['boundary'] not in ('stream','message','credited') or not isinstance(target['mode'],(str,type(None))) or value['applicationReadiness'] != 'ready':
            raise ValueError('invalid observed application endpoint')
        address(target);process(target['owner'])
        if not private_socket(target) or target['owner'] != children[0]:
            raise ValueError('application endpoint must belong to the private native process')
    elif target is not None and target not in value['endpoints']:
        raise ValueError('endpoint is not an observed public listener')
    if value['readiness'] == 'process-alive' and (target is not None or value['endpoints']):
        raise ValueError('process-alive observation cannot claim listener readiness')
    if value['readiness'] == 'listener-ready' and not value['endpoints']:
        raise ValueError('listener readiness requires observed sockets')
    return value
