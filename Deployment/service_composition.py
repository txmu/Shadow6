"""Validate explicit Guard/EPE/Gate links without making any layer mandatory."""
try:
    from .broker_set import endpoint, private_endpoint
except ImportError:
    from broker_set import endpoint, private_endpoint


def same_endpoint(left, right):
    a,b=endpoint(left),endpoint(right)
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
