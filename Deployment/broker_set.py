"""S6P1 route BrokerSet intent and bounded peripheral selection realization."""
import ipaddress
import re
from urllib.parse import urlsplit


def endpoint(value):
    if not isinstance(value, str) or len(value) > 512 or any(ord(c) < 33 for c in value):
        raise ValueError('invalid BrokerSet endpoint')
    parsed = urlsplit(value if '://' in value or value.startswith('unix:') else 'tcp://' + value)
    if parsed.scheme == 'unix':
        from pathlib import PurePosixPath
        if parsed.netloc or parsed.query or parsed.fragment or not parsed.path.startswith('/') or len(parsed.path.encode()) > 103 or '..' in PurePosixPath(parsed.path).parts:
            raise ValueError('invalid Unix stream endpoint')
        return parsed
    try: port = parsed.port or {"ws":80,"wss":443}.get(parsed.scheme)
    except ValueError: raise ValueError('invalid BrokerSet port') from None
    if parsed.scheme not in {'tcp','udp','ws','wss','quic'} or not parsed.hostname or not port or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('invalid BrokerSet endpoint')
    return parsed


def private_endpoint(value):
    parsed = endpoint(value)
    if parsed.scheme == 'unix':
        import os, stat
        from pathlib import Path
        try: metadata = Path(parsed.path).parent.lstat()
        except OSError: return False
        return stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o077
    try: return ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError: return False


def validate_routes(routes):
    if not isinstance(routes, list) or len(routes) > 256:
        raise ValueError('bounded S6P1 routes required')
    ids = set()
    for route in routes:
        if not isinstance(route, dict): raise ValueError('S6P1 route must be an object')
        if route.get('kind') != 'broker_set': continue  # Other existing S6P1 route contracts.
        if set(route) - {'kind','id','policy','members','boundary','engine'} or not {'kind','id','policy','members'} <= set(route):
            raise ValueError('invalid BrokerSet route fields')
        if 'engine' in route:
            try:
                from .topology_contract import engine_id
            except ImportError:
                from topology_contract import engine_id
            if engine_id(route['engine']) != route['engine']:
                raise ValueError('BrokerSet engine requires a canonical Core identity')
        if not isinstance(route['id'], str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', route['id']) or route['id'] in ids:
            raise ValueError('invalid/duplicate BrokerSet id')
        ids.add(route['id'])
        if route['policy'] not in {'priority','round_robin','random'}: raise ValueError('invalid BrokerSet policy')
        if 'boundary' in route and route['boundary'] not in {'stream','message','credited'}: raise ValueError('invalid boundary')
        members = route['members']
        if not isinstance(members, list) or not 1 <= len(members) <= 16: raise ValueError('BrokerSet requires 1..16 members')
        seen = set()
        for member in members:
            if not isinstance(member, dict) or set(member) - {'identity','endpoint','public_key','priority'} or not {'identity','endpoint'} <= set(member):
                raise ValueError('invalid BrokerSet member; observed health belongs in runtime')
            if not isinstance(member['identity'], str) or not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', member['identity']): raise ValueError('invalid broker identity')
            endpoint(member['endpoint'])
            if member['endpoint'] in seen: raise ValueError('duplicate broker endpoint')
            seen.add(member['endpoint'])
            if 'public_key' in member and (not isinstance(member['public_key'], str) or not re.fullmatch(r'[0-9a-f]{64}', member['public_key'])): raise ValueError('invalid broker trust key')
            if type(member.get('priority',0)) is not int or not 0 <= member.get('priority',0) <= 65535: raise ValueError('invalid broker priority')
    return routes


def realize(route, *, adapter='native-single', observations=None, cursor=0, rng=None):
    validate_routes([route])
    if route.get('kind') != 'broker_set': raise ValueError('BrokerSet required')
    members = route['members']
    if len(members) > 1 and adapter not in {'gate','broker-set-selector'}:
        raise ValueError('capability unavailable: native-single adapter supports one Broker; select a BrokerSet peripheral adapter')
    if adapter not in {'native-single','gate','broker-set-selector'}: raise ValueError('unknown BrokerSet adapter')
    if type(cursor) is not int or cursor < 0: raise ValueError('invalid selection cursor')
    observations = observations or {}
    if not isinstance(observations,dict) or any(k not in {m['endpoint'] for m in members} or v not in {'unknown','available','unavailable'} for k,v in observations.items()): raise ValueError('invalid observed BrokerSet health')
    usable = [m for m in members if observations.get(m['endpoint'], 'unknown') != 'unavailable']
    if not usable: raise ValueError('BrokerSet has no available endpoint')
    policy = route['policy']
    if policy == 'priority': chosen = min(usable, key=lambda m:m.get('priority',0))
    elif policy == 'round_robin': chosen = usable[cursor % len(usable)]
    else:
        import secrets
        chosen = (rng or secrets.SystemRandom()).choice(usable)
    if adapter == 'gate':
        # Gate's single peer pin cannot authenticate a set of different peers.
        keys = {m.get('public_key') for m in members}
        if len(keys) != 1 or None in keys:
            raise ValueError('capability unavailable: Gate BrokerSet requires one explicit shared trust identity')
        if policy == 'priority': raise ValueError('capability unavailable: Gate supports round_robin/random selection')
    return {'brokerSet':route['id'], 'adapter':adapter, 'selected':chosen,
            'endpoints':[m['endpoint'] for m in usable], 'policy':policy,
            'health':{m['endpoint']:observations.get(m['endpoint'],'unknown') for m in members},
            'sessionMigration':False, 'stateReplication':False}


def gate_patch(route, *, side='remote'):
    result = realize(route, adapter='gate')
    parsed = [endpoint(e) for e in result['endpoints']]
    if side == 'remote':
        if len({p.port for p in parsed}) != 1 or any(p.scheme not in {'tcp','udp'} for p in parsed) or len({p.scheme for p in parsed}) != 1:
            raise ValueError('capability unavailable: Gate remote hosts require one TCP/UDP transport and a shared port')
        for p in parsed:
            try: ipaddress.ip_address(p.hostname)
            except ValueError: raise ValueError('Gate remote hosts require IP addresses') from None
        return {'protocol':[parsed[0].scheme], 'remote_hosts':[p.hostname for p in parsed], 'mtd':{'enabled':False,'period_seconds':300,'min_port':parsed[0].port,'max_port':parsed[0].port,'grace_seconds':15},
                'peer_public_keys':[route['members'][0]['public_key']], 'load_balance':route['policy']}
    if side != 'upstream' or any(p.scheme not in {'tcp','udp'} for p in parsed) or len({p.scheme for p in parsed}) != 1: raise ValueError('Gate upstreams require one TCP/UDP transport')
    return {'protocol':[parsed[0].scheme], 'upstreams':[p.netloc for p in parsed], 'load_balance':route['policy']}
