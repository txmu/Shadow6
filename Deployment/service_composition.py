"""Validate explicit Guard/EPE/Gate links without making any layer mandatory."""
try:
    from .broker_set import endpoint, private_endpoint
except ImportError:
    from broker_set import endpoint, private_endpoint


def same_endpoint(left, right):
    a,b=endpoint(left),endpoint(right)
    if 'unix' in (a.scheme,b.scheme):return a.scheme == b.scheme and a.path == b.path
    return (a.hostname,a.port)==(b.hostname,b.port)


def validate_composition(*, privacy, envelope=None, gate=None, guard=None):
    layers=['Core']
    if gate is not None:
        if gate.get('enabled') is not True: raise ValueError('Gate composition requires explicit enabled: true')
        layers.insert(0,'Gate')
    if privacy == 'envelope':
        if envelope is None: raise ValueError('EPE configuration required')
        if not private_endpoint(envelope['upstream']): raise ValueError('EPE native boundary must be private')
        if gate is not None:
            if gate.get('role') != 'server': raise ValueError('capability unavailable: EPE -> Gate -> Core requires a Gate server realization')
            host=gate.get('listen_host','0.0.0.0');port=gate.get('listen_port')
            target=f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
            if not private_endpoint(target) or not same_endpoint(envelope['upstream'],target):
                raise ValueError('EPE upstream must match the private Gate listener')
            protocol='tcp' if envelope.get('mode','stream')=='stream' else 'udp'
            if gate.get('protocol') != [protocol]: raise ValueError('EPE/Gate transport boundary mismatch')
            targets=gate.get('upstreams') or [gate.get('upstream','')]
            if not targets or any(not private_endpoint(e) for e in targets): raise ValueError('Gate upstream Core endpoints must be private')
        layers.insert(0,'S6EPE')
    if guard is not None:
        if privacy == 'envelope':
            # Any enabled forwarding feature must feed EPE rather than bypass it.
            listen=endpoint(envelope['listen'])
            mappings={'spa_config':'agent_tcp_port','lpd_limiter':'agent_port',
                      'anti_probe':'local_port','broker_shield':'local_broker_port'}
            for feature,field in mappings.items():
                setting=guard.get(feature,{})
                if setting.get('enabled') is True and setting.get(field) != listen.port:
                    raise ValueError('Guard forwarding must target the EPE admission listener')
        layers.insert(0,'Guard')
    return {'layers':layers, 'sessionAdmission':'S6EPE' if privacy=='envelope' else 'native',
            'outerEncryptedCamouflage':False}


def broker_realization(context, *, native, gate=None):
    """Check desired BrokerSet against explicit peripheral/native realization.

    Only deterministic intent/realization material is returned for locking;
    selection and observed health are runtime facts.
    """
    try:
        from .broker_set import gate_patch, realize
    except ImportError:
        from broker_set import gate_patch, realize
    pools = [r for r in context['routes'] if r.get('kind') == 'broker_set']
    if not pools:
        return {'adapter':'native-single','brokerSets':[]}
    if len(pools) > 1:
        raise ValueError('capability unavailable: one native broker control endpoint cannot realize multiple BrokerSets')
    route = pools[0]
    targets = []
    def collect(value):
        if isinstance(value,dict):
            for key, child in value.items():
                if key in {'broker_addr','broker_address'}:
                    if not isinstance(child,str): raise ValueError('invalid native broker endpoint')
                    targets.append(child)
                elif key == 'broker_addrs':
                    if not isinstance(child,list) or not child or not all(isinstance(e,str) for e in child): raise ValueError('invalid native broker endpoints')
                    targets.extend(child)
                else: collect(child)
        elif isinstance(value,list):
            for child in value: collect(child)
    collect(native)
    if gate is None or gate.get('role') != 'client':
        realize(route)  # native-single capability validation
        if context['role'] != 'broker':
            if targets != [route['members'][0]['endpoint']]:
                raise ValueError('capability unavailable: native broker endpoint does not realize the S6P1 route')
        return {'adapter':'native-single', 'brokerSets':[route['id']]}
    patch = gate_patch(route)
    if gate.get('enabled') is not True or any(gate.get(key) != value for key,value in patch.items()):
        raise ValueError('Gate realization differs from S6P1 BrokerSet routes/trust/policy')
    host,port = gate.get('listen_host'),gate.get('listen_port')
    if not isinstance(host,str) or type(port) is not int:
        raise ValueError('Gate BrokerSet requires an explicit private local endpoint')
    local = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
    if not private_endpoint(local):
        raise ValueError('Gate BrokerSet native-facing endpoint must be loopback')
    if len(targets) != 1 or not same_endpoint(targets[0],local):
        raise ValueError('capability unavailable: native broker endpoint must explicitly target the Gate BrokerSet listener')
    return {'adapter':'gate','brokerSets':[route['id']], 'gatePatch':patch,
            'nativeEndpoint':targets[0]}


def component_material_paths(component, config):
    """Fixed external credential references, never arbitrary path discovery."""
    from pathlib import Path
    if component not in ('gate', 'guard') or not isinstance(config, dict):
        raise ValueError('invalid component material declaration')
    if component == 'gate': return {}
    shield = config.get('broker_shield', {})
    if not isinstance(shield, dict): raise ValueError('invalid Guard broker_shield')
    fields = ('tls_cert_file', 'tls_key_file')
    present = [field for field in fields if shield.get(field)]
    if present and len(present) != len(fields):
        raise ValueError('complete Guard TLS material required')
    result = {}
    for field in present:
        path = shield[field]
        if not isinstance(path, str) or len(path.encode()) > 4096 or not Path(path).is_absolute() or '\0' in path:
            raise ValueError('Guard TLS material requires bounded absolute paths')
        result['guard.broker_shield.' + field] = path
    if len(set(result.values())) != len(result):
        raise ValueError('Guard TLS material paths must be distinct')
    return result
