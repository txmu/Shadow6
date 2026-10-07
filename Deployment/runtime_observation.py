"""Read process-owned Linux sockets and bounded structured ready events."""
import ipaddress
import itertools
import json
import re
import os
import socket
import sys
import time
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


def readiness_evidence(value, state, *, now=None):
    """Display view of validated status; never an admission or connect grant."""
    current = False
    if isinstance(value, dict):
        try:
            validate_observation(value)
            age = (int(time.time()) if now is None else now) - value['observedAt']
            current = state == 'running' and 0 <= age <= 5
        except (ValueError, KeyError, TypeError): pass
    readiness = value.get('readiness') if isinstance(value, dict) else 'unavailable'
    runtime_ready = current and readiness in {'listener-ready', 'control-ready', 'application-ready', 'application-active'}
    application_ready = current and readiness in {'application-ready', 'application-active'} and value['applicationReadiness'] == 'ready'
    return {'schema': 'shadow6.readiness-evidence.v1', 'runtimeReady': bool(runtime_ready),
        'applicationReady': bool(application_ready), 'newAttachmentAvailable': bool(application_ready and readiness == 'application-ready'),
        'observation': readiness if current else 'unavailable',
        'reason': 'verified-current-observation' if current else 'runtime-observation-unavailable-or-stale',
        'admissionGrant': False}


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
    try:
        with (Path('/proc') / str(pid) / 'net/sctp/eps').open() as stream:
            for line in proc_rows(stream):
                fields=line.split()
                if len(fields)<8 or fields[7] not in inodes:continue
                # Linux one-to-one endpoint table: STY=2, SST=TCP_LISTEN(10).
                # Bound-but-unlistening and association rows are not listeners.
                if fields[2]!='2' or fields[3]!='10':continue
                if len(fields)<9:raise ValueError('invalid owned SCTP endpoint')
                port=int(fields[5])
                if not 1<=port<=65535:raise ValueError('invalid owned SCTP port')
                for host in fields[8:]:
                    address=str(ipaddress.ip_address(host))
                    found.append({'host':address,'port':port,'transport':'sctp','observation':'process-owned-socket'})
                    if len(found)>MAX_SOCKETS:raise ValueError('owned listener observation limit exceeded')
    except OSError:pass
    try:
        paths={}
        with (Path('/proc') / str(pid) / 'net/unix').open() as stream:
            for line in proc_rows(stream):
                fields=line.split(maxsplit=7)
                if len(fields)!=8 or fields[4] not in ('0001','0005') or fields[3]!='00010000':continue
                path=fields[7].rstrip('\n')
                paths.setdefault((path, fields[4]),[]).append(fields[6])
        for (path, kind),owners in paths.items():
            if any(inode in inodes for inode in owners):
                if len(owners)!=1:raise ValueError('Unix listener path ownership is ambiguous')
                found.append({'path':path,'transport':'unix-stream' if kind=='0001' else 'unix-seqpacket','observation':'process-owned-socket'})
                if len(found)>MAX_SOCKETS:raise ValueError('owned listener observation limit exceeded')
    except OSError:pass
    return sorted(found, key=lambda x:(x['transport'],x.get('host',x.get('path','')),x.get('port',0)))


def private_socket(item):
    if 'path' in item:
        import stat
        path=Path(item['path'])
        if not path.is_absolute() or len(str(path).encode())>103:return False
        try:
            parent=path.parent.lstat();entry=path.lstat()
        except OSError:return False
        return (stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.geteuid() and not parent.st_mode & 0o077
                and stat.S_ISSOCK(entry.st_mode) and entry.st_uid==os.geteuid() and not entry.st_mode & 0o077)
    return ipaddress.ip_address(item['host']).is_loopback


def control_connections(pid, transport='tcp'):
    """Bounded process-owned connected peers; neither auth nor session proof."""
    if transport not in ('tcp', 'udp'):
        raise ValueError('unsupported owned peer transport')
    try:
        with os.scandir(Path('/proc') / str(pid) / 'fd') as entries:
            descriptors = list(itertools.islice(entries, MAX_FDS + 1))
        if len(descriptors) > MAX_FDS: raise ValueError('process FD observation limit exceeded')
        inodes = set()
        for entry in descriptors:
            try:
                value = os.readlink(entry.path)
                if value.startswith('socket:['): inodes.add(value[8:-1])
            except OSError: pass
    except OSError: return []
    result = []
    for table in (transport, transport + '6'):
        try:
            with (Path('/proc') / str(pid) / 'net' / table).open() as stream:
                for line in proc_rows(stream):
                    fields = line.split()
                    if len(fields) < 10 or fields[9] not in inodes or fields[3] != '01': continue
                    local, local_port = fields[1].split(':'); remote, remote_port = fields[2].split(':')
                    result.append(dict(host=proc_address(local, ipv6=table.endswith('6')), port=int(local_port, 16),
                        remoteHost=proc_address(remote, ipv6=table.endswith('6')), remotePort=int(remote_port, 16),
                        transport=transport, observation='process-owned-control-connection'))
                    if len(result) > MAX_SOCKETS: raise ValueError('owned control connection observation limit exceeded')
        except OSError: continue
    return result


def endpoint_matches(observed, target, *, transport=None):
    if target.scheme == 'unix':return observed.get('transport')=='unix-stream' and observed.get('path')==target.path
    return observed.get('host')==target.hostname and observed.get('port')==target.port and observed.get('transport')==(transport or ('udp' if target.scheme in ('udp','quic') else 'tcp'))


def ready(line, core):
    value = strict_json(line)
    from feature_contract import validate_ready_event
    validate_ready_event(value, 'shadow6-' + core)
    boundary = value['application_boundary']
    target = boundary['endpoint']
    if boundary.get('kind') == 'message' and boundary.get('mode') == 'seqpacket-fd':
        return {'endpoint':{**target, 'boundary':'message', 'mode':'seqpacket-fd', 'observation':'native-fd-ready-event'}, 'readiness':'application-ready'}
    return {'endpoint':{**target,'boundary':boundary['kind'],'mode':boundary.get('mode'), 'observation':'structured-ready-event'}, 'readiness':'application-ready'}


def validate_observation(value):
    fields = {'observedAt','pid','processIdentity','processes','nativeEndpoints','endpoints',
              'endpoint','readiness','transportReadiness','applicationReadiness'}
    limit_fields = {'limitResolutionDigest','effectiveLimits','limitsEnforcement'}
    if not isinstance(value,dict) or set(value) not in (fields, fields | limit_fields):
        raise ValueError('invalid runtime observation fields')
    if limit_fields <= set(value):
        from limits import integer
        if not isinstance(value['limitResolutionDigest'], str) or re.fullmatch(r'sha256:[0-9a-f]{64}', value['limitResolutionDigest']) is None:
            raise ValueError('InvalidObservedLimitsDigest')
        if not isinstance(value['effectiveLimits'], dict) or not 1 <= len(value['effectiveLimits']) <= 64:
            raise ValueError('InvalidObservedLimits')
        for name, amount in value['effectiveLimits'].items():
            if not isinstance(name, str) or not 1 <= len(name) <= 64: raise ValueError('InvalidObservedLimitDimension')
            integer(amount, name)
        enforcement = value['limitsEnforcement']
        if not isinstance(enforcement, dict) or set(enforcement) != {'process_fds'} or enforcement['process_fds'] != {'actual':value['effectiveLimits'].get('process_fds'), 'enforced':True}:
            raise ValueError('InvalidObservedLimitsEnforcement')
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
    if value['readiness'] not in ('process-alive','unavailable','listener-ready','control-ready','application-ready','application-active') or value['transportReadiness'] not in ('unknown','pending','ready','unavailable') or value['applicationReadiness'] not in ('unknown','ready','unavailable'):
        raise ValueError('invalid observed readiness')
    if value['transportReadiness'] == 'ready' and not any(
            isinstance(item, dict) and item.get('transport') == 'udp' and
            item.get('observation') == 'process-owned-socket' for item in value['endpoints']):
        raise ValueError('transport readiness requires an owned UDP endpoint')
    def address(item):
        if not isinstance(item['host'],str) or type(item['port']) is not int or not 1 <= item['port'] <= 65535:
            raise ValueError('invalid observed endpoint')
        ipaddress.ip_address(item['host'])
    for field in ('nativeEndpoints','endpoints'):
        endpoints=value[field]
        if not isinstance(endpoints,list) or len(endpoints) > 64:
            raise ValueError('invalid observed endpoint list')
        for item in endpoints:
            if isinstance(item,dict) and set(item) == {'host','port','remoteHost','remotePort','transport','observation'} and item['transport'] in ('tcp', 'udp') and item['observation'] in ('process-owned-control-connection', 'process-owned-application-connection'):
                if item['observation'] == 'process-owned-application-connection' and (
                        item['transport'] != 'tcp' or not private_socket(item) or
                        not ipaddress.ip_address(item['remoteHost']).is_loopback):
                    raise ValueError('application flow must be a private TCP connection')
                address(item)
                address({'host':item['remoteHost'], 'port':item['remotePort']})
                continue
            if isinstance(item,dict) and set(item)=={'path','transport','observation'} and item['transport'] in ('unix-stream','unix-seqpacket') and item['observation']=='process-owned-socket':
                if not isinstance(item['path'],str) or not Path(item['path']).is_absolute() or len(item['path'].encode())>103:
                    raise ValueError('invalid observed Unix endpoint')
                continue
            if not isinstance(item,dict) or set(item) != {'host','port','transport','observation'} or item['transport'] not in ('tcp','udp','sctp') or item['observation'] != 'process-owned-socket':
                raise ValueError('invalid socket observation')
            address(item)
    target=value['endpoint']
    if value['readiness'] == 'application-active':
        fields = {'host','port','remoteHost','remotePort','boundary','mode','observation','owner'}
        if (not isinstance(target, dict) or set(target) != fields or target['boundary'] != 'stream' or
                target['mode'] != 'localhost-tcp-proxy' or target['observation'] != 'structured-ready-active-flow' or
                value['applicationReadiness'] != 'ready'):
            raise ValueError('invalid active application endpoint')
        address(target); address({'host': target['remoteHost'], 'port': target['remotePort']}); process(target['owner'])
        matching = {'host': target['host'], 'port': target['port'], 'remoteHost': target['remoteHost'],
                    'remotePort': target['remotePort'], 'transport': 'tcp', 'observation': 'process-owned-application-connection'}
        if (not private_socket(target) or not ipaddress.ip_address(target['remoteHost']).is_loopback or
                target['owner'] != children[0] or matching not in value['nativeEndpoints'] or matching not in value['endpoints']):
            raise ValueError('active application flow lacks native socket ownership')
    elif value['readiness'] == 'application-ready':
        record = isinstance(target, dict) and target.get('observation') == 'supervisor-owned-record-adapter'
        if record:
            fields = {'path','boundary','mode','observation','owner','nativeOwner','nativeFd','nativeInode','maxRecord','attachmentState'}
            if (set(target) != fields or target['boundary'] != 'message' or target['mode'] != 'seqpacket-fd' or
                    type(target['nativeFd']) is not int or not 0 <= target['nativeFd'] <= 1048576 or
                    not isinstance(target['nativeInode'], str) or not target['nativeInode'].isdecimal() or
                    type(target['maxRecord']) is not int or not 1 <= target['maxRecord'] <= 65536 or
                    target['attachmentState'] not in ('available','attached','draining')):
                raise ValueError('invalid observed native record attachment')
            process(target['owner']); process(target['nativeOwner'])
            if target['owner'] != {k:value[k] for k in ('pid','processIdentity')} or target['nativeOwner'] != children[0]:
                raise ValueError('record adapter must link supervisor and native process')
            if not private_socket(target): raise ValueError('record attachment must be private')
        else:
            if not isinstance(target,dict) or set(target) != {'host','port','boundary','mode','observation','owner'} or target['observation'] != 'structured-ready-event' or target['boundary'] not in ('stream','message','credited') or not isinstance(target['mode'],(str,type(None))) or value['applicationReadiness'] != 'ready':
                raise ValueError('invalid observed application endpoint')
            address(target);process(target['owner'])
            if not private_socket(target) or target['owner'] != children[0]:
                raise ValueError('application endpoint must belong to the private native process')
        if value['applicationReadiness'] != 'ready': raise ValueError('application readiness is not confirmed')
    elif target is not None and target not in value['endpoints']:
        raise ValueError('endpoint is not an observed public listener')
    if value['readiness'] in ('process-alive','unavailable') and (target is not None or value['endpoints']):
        raise ValueError('non-ready observation cannot claim listener readiness')
    if value['readiness'] == 'listener-ready' and not value['endpoints']:
        raise ValueError('listener readiness requires observed sockets')
    if value['readiness'] == 'control-ready' and (not value['endpoints'] or
            any(item.get('observation') != 'process-owned-control-connection' for item in value['endpoints'])):
        raise ValueError('control readiness requires observed owned control peers')
    return value
