"""One resolver for Named Service, S6P1 and Public6 provisioning sources."""
import hashlib
import re
try:
    from .protocol_context import validate_context, check_binding, admit, context_digest, core_allowed
    from .broker_set import realize, gate_patch
except ImportError:
    from protocol_context import validate_context, check_binding, admit, context_digest, core_allowed
    from broker_set import realize, gate_patch


def connection_plan(context, *, catalog, core=None, binding=None, runtime=None, source='s6p1', adapter=None, role=None):
    if role is not None and (not isinstance(role,str) or re.fullmatch(r'[A-Za-z0-9._:-]{1,32}',role) is None):
        raise ValueError('invalid requested role')
    adapter = adapter or 'native-single'
    context = validate_context(context)
    context = admit(context, component='public6' if context['credentials'].get('public6_invitation') else None, role=role)
    effective_role = role or context['role']
    if core and binding and binding['core'] != core: raise ValueError('explicit Core differs from locked CoreBinding')
    requested = core or (binding or {}).get('core')
    scope = context['core']
    requirements = {}
    if effective_role != 'all': requirements['roles'] = effective_role
    kinds = {r['boundary'] for r in context['routes'] if r.get('boundary')}
    if kinds: requirements['applicationBoundaries'] = sorted(kinds)
    resolution = catalog.resolve(requirements, requested or (scope if isinstance(scope,str) and scope != 'all' else None))
    candidates = [c for c in resolution['candidates'] if core_allowed(scope,c['id'])]
    if not requested:
        if len(candidates) > 1: raise ValueError('AmbiguousCore: explicit --core/CoreBinding required')
        if not candidates: raise ValueError('capability unavailable: no compatible Core')
        requested = candidates[0]['id']
    descriptor = check_binding(context, requested, catalog)
    if not any(c['id'] == requested for c in candidates): raise ValueError('capability unavailable: explicit Core does not satisfy context')
    boundaries = sorted({r['boundary'] for r in context['routes'] if r.get('boundary')})
    if len(boundaries) > 1: raise ValueError('AmbiguousApplicationBoundary: select one application boundary')
    boundary = boundaries[0] if boundaries else None
    pools = []
    for route in context['routes']:
        if route.get('kind') == 'broker_set':
            pool = realize(route, adapter=adapter)
            if adapter == 'gate': pool['gateConfigPatch'] = gate_patch(route)
            pools.append(pool)
    observed = runtime or {}
    endpoint = observed.get('endpoint')
    readiness = observed.get('readiness','unavailable')
    if readiness == 'application-ready':
        if 'client' not in descriptor['roles']:
            raise ValueError('capability unavailable: observed client role is not declared by Core')
        if not isinstance(endpoint,dict) or endpoint.get('boundary') not in descriptor['applicationBoundaries']:
            raise ValueError('capability unavailable: observed application boundary is not declared by Core')
        if effective_role not in ('all','client'):
            raise ValueError('observed client application endpoint conflicts with S6P1 role')
        observed_boundary = endpoint['boundary']
        if boundary and boundary != observed_boundary:
            raise ValueError('observed application boundary conflicts with S6P1 routes')
        boundary = observed_boundary
    attach = (readiness == 'application-ready' and isinstance(endpoint,dict) and endpoint.get('boundary') == 'stream' and endpoint.get('mode') == 'localhost-tcp-proxy' and endpoint.get('observation') == 'structured-ready-event')
    # No socket open is invented from native wire data. A ready process is not
    # an application session. Existing Public6 provisioning happens afterward.
    return {'schema':'shadow6.connection-plan.v1', 'source':source, 'core':requested,
            'contextDigest':context_digest(context), 'role':effective_role,
            'binding':binding, 'runtimeIdentity':{k:observed[k] for k in ('pid','processIdentity') if k in observed}, 'endpoint':endpoint, 'readiness':readiness,
            'applicationBoundary':boundary, 'abi':'S6ABI/1' if boundary else None,
            'endpointFraming':'native-application-bytes' if attach else 'core-native' if endpoint else None,
            'brokerSets':pools, 'state':'planned', 'connected':False,
            'capability':{'available':boundary is not None and boundary in descriptor['applicationBoundaries'],
                          'sessionLaunch':'local-application-stream' if attach else 'unavailable', 'reason':'Use --stdio or libshadow6.connect to attach to the observed client proxy' if attach else 'Native endpoint needs its declared application adapter; no uniform session launcher is advertised'},
            'provisioning':{'public6':source == 'public6' or isinstance(context['credentials'].get('public6_invitation'),str)}}


def resolve_connection(*, catalog, service=None, registry=None, context=None, core=None, binding=None, runtime=None, source='s6p1', adapter=None, role=None):
    if service is not None:
        if context is not None: raise ValueError('choose one connection resolve source')
        item, material = registry.connection_inputs(service)
        context, binding, runtime = item['protocolContext'], item['coreBinding'], item['runtime']
        if role is not None and context['role'] == 'all':
            try:
                from .service_storage import private_read, strict_json
            except ImportError:
                from service_storage import private_read, strict_json
            data=private_read(binding['config']['config_path'])
            if 'sha256:'+hashlib.sha256(data).hexdigest() != material['nativeConfigDigest']:
                raise ValueError('deployment drift during connection resolution')
            try:native = strict_json(data)
            except ValueError as error:
                raise ValueError('capability unavailable: named deployment role cannot be verified') from error
            if not isinstance(native,dict) or not isinstance(native.get('role'),str):
                raise ValueError('capability unavailable: named deployment role cannot be verified')
            if native['role'] != role:
                raise ValueError('requested role differs from locked native realization')
        deployed_adapter = material['brokerRealization']['adapter']
        if adapter is not None and adapter != deployed_adapter:
            raise ValueError('requested connection adapter differs from locked service realization')
        adapter = deployed_adapter
        source = 'named-service'
    if context is None: raise ValueError('S6P1 context required')
    return connection_plan(context, catalog=catalog, core=core, binding=binding, runtime=runtime, source=source, adapter=adapter, role=role)


class LocalSession:
    """Attach only to an observed, authenticated native client application proxy."""
    def __init__(self, plan):
        import socket, time
        try:
            from .service_runtime import alive
            from .runtime_observation import sockets
        except ImportError:
            from service_runtime import alive
            from runtime_observation import sockets
        try:
            from .runtime_observation import private_socket
        except ImportError:
            from runtime_observation import private_socket
        target = plan.get('endpoint')
        if plan.get('readiness') != 'application-ready' or not isinstance(target,dict) or target.get('observation') != 'structured-ready-event' or target.get('boundary') != 'stream' or target.get('mode') != 'localhost-tcp-proxy' or not private_socket(target):
            raise ValueError('capability unavailable: safe local application stream session')
        owner=target.get('owner',{})
        if not alive(plan.get('runtimeIdentity',{})) or not alive(owner) or not any(s['transport']=='tcp' and s['host']==target['host'] and s['port']==target['port'] for s in sockets(owner.get('pid'))):
            raise ValueError('application endpoint owner is unavailable')
        self.socket = socket.create_connection((target['host'],target['port']),timeout=5)
        if not alive(owner):
            self.socket.close();raise ValueError("application endpoint owner changed")
        self.deadline=time.monotonic()+300
        self.remaining=16*1024*1024
        self.socket.settimeout(30)

    def _budget(self, size):
        import time
        if time.monotonic() >= self.deadline or size > self.remaining:
            self.close(); raise ValueError('local session lifetime/byte budget exhausted')
        self.remaining -= size

    def send(self, data):
        self._budget(len(data)); self.socket.sendall(data)

    def receive(self, size=65536):
        if type(size) is not int or not 1 <= size <= 65536: raise ValueError('invalid receive bound')
        self._budget(0)
        data=self.socket.recv(min(size,self.remaining or 1));self._budget(len(data));return data

    def close(self): self.socket.close()
    def __enter__(self): return self
    def __exit__(self,*_): self.close()


def open_local_session(plan):
    return LocalSession(plan)
