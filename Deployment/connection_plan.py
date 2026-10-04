"""One resolver for Named Service, S6P1 and Public6 provisioning sources."""
import hashlib
import os
import re
try:
    from .protocol_context import validate_context, check_binding, admit, context_digest, core_allowed
    from .broker_set import realize, gate_patch
    from .profile_registry import validate_profile_binding
except ImportError:
    from protocol_context import validate_context, check_binding, admit, context_digest, core_allowed
    from broker_set import realize, gate_patch
    from profile_registry import validate_profile_binding


def application_adapter(profile, provider='native'):
    """Resolve an app-transparent shim from a locked Native Profile contract."""
    if (not isinstance(profile, dict) or not isinstance(profile.get('id'), str) or
            provider not in {'native', 's6na'}):
        raise ValueError('InvalidApplicationAdapterBinding')
    contract = profile.get('applicationBoundary')
    if not isinstance(contract, dict) or contract.get('kind') not in {'stream', 'message'}:
        raise ValueError('UnsupportedApplicationBoundary')
    result = {'provider':provider, 'profile':profile['id'],
        'boundary':contract['kind'], 'mode':'profile-native'}
    if provider == 's6na':
        result.update(mode='transparent-profile',
            recordPreserving=contract['kind'] == 'message')
    return result


def connection_plan(context, *, catalog, core=None, binding=None, runtime=None, source='s6p1', adapter=None, role=None, profile_binding=None):
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
    profile = validate_profile_binding(profile_binding, core=requested) if profile_binding is not None else None
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
    if profile is not None:
        contract = profile['applicationBoundary']
        if boundary is not None and boundary != contract['kind']:
            raise ValueError('ProfileCapabilityMismatch: application boundary differs from ProfileBinding')
        if readiness == 'application-ready' and endpoint.get('mode') != contract['mode']:
            raise ValueError('ProfileCapabilityMismatch: observed attachment mode differs')
    attach = (readiness == 'application-ready' and isinstance(endpoint,dict) and endpoint.get('boundary') == 'stream' and endpoint.get('mode') == 'localhost-tcp-proxy' and endpoint.get('observation') == 'structured-ready-event')
    message_attach = (readiness == 'application-ready' and isinstance(endpoint,dict) and endpoint.get('boundary') == 'message' and
                      ((endpoint.get('mode') == 'localhost-udp-datagram-proxy' and endpoint.get('observation') == 'structured-ready-event') or
                       (endpoint.get('mode') == 'seqpacket-fd' and endpoint.get('observation') == 'supervisor-owned-record-adapter')))
    # No socket open is invented from native wire data. A ready process is not
    # an application session. Existing Public6 provisioning happens afterward.
    return {'schema':'shadow6.connection-plan.v1', 'source':source, 'core':requested,
            'contextDigest':context_digest(context), 'role':effective_role,
            'binding':binding, 'profileBinding':profile_binding, 'lockDigest':observed.get('lockDigest'), 'runtimeIdentity':{k:observed[k] for k in ('pid','processIdentity') if k in observed}, 'endpoint':endpoint, 'readiness':readiness,
            'applicationBoundary':boundary, 'abi':'S6ABI/1' if boundary else None,
            'endpointFraming':'native-application-records' if message_attach else 'native-application-bytes' if attach else 'core-native' if endpoint else None,
            'brokerSets':pools, 'state':'planned', 'connected':False,
            'capability':{'available':boundary is not None and boundary in descriptor['applicationBoundaries'],
                          'sessionLaunch':'local-application-message' if message_attach else 'local-application-stream' if attach else 'unavailable', 'reason':'Use --records or libshadow6 send_record/receive_record; native record boundaries and limits are preserved' if message_attach else 'Use --stdio or libshadow6.connect to attach to the observed client proxy' if attach else 'Native endpoint needs its declared application adapter; no uniform session launcher is advertised'},
            'provisioning':{'public6':source == 'public6' or isinstance(context['credentials'].get('public6_invitation'),str)}}


def resolve_connection(*, catalog, service=None, registry=None, context=None, core=None, binding=None, runtime=None, source='s6p1', adapter=None, role=None, profile_binding=None):
    if service is not None:
        if context is not None: raise ValueError('choose one connection resolve source')
        item, material = registry.connection_inputs(service)
        context, binding, runtime = item['protocolContext'], item['coreBinding'], item['runtime']
        profile_binding = item.get('profileBinding')
        validate_profile_binding(profile_binding, core=binding['core'])
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
    result = connection_plan(context, catalog=catalog, core=core, binding=binding,
        runtime=runtime, source=source, adapter=adapter, role=role,
        profile_binding=profile_binding)
    if service is not None:
        attachment = material.get('creditedAttachment')
        profile = validate_profile_binding(profile_binding, core=binding['core'])
        result['applicationAdapter'] = application_adapter(profile,
            's6na' if attachment else 'native')
        if attachment:
            result['capability']['sessionLaunch'] = 's6na-transparent-profile'
            result['capability']['reason'] = 'The locked S6NA endpoint is selected automatically from the Named Service Profile; use connect_native for its local Core endpoint'
    return result


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
    if plan.get('applicationBoundary') == 'message': return LocalMessageSession(plan)
    if plan.get('applicationBoundary') == 'credited': raise ValueError('UnsupportedApplicationBoundary: credited provider required')
    return LocalSession(plan)


class LocalMessageSession:
    """One explicit native application record per send/receive operation."""
    def __init__(self, plan):
        import socket, time, secrets, json, struct
        try:
            from .service_runtime import alive
            from .runtime_observation import sockets, private_socket
            from .application_attachment import HANDSHAKE_SCHEMA, owned_seqpacket
        except ImportError:
            from service_runtime import alive
            from runtime_observation import sockets, private_socket
            from application_attachment import HANDSHAKE_SCHEMA, owned_seqpacket
        profile = validate_profile_binding(plan.get('profileBinding'), core=plan.get('core'))
        target = plan.get('endpoint')
        if (plan.get('readiness') != 'application-ready' or profile['applicationBoundary']['kind'] != 'message' or
                not isinstance(target,dict) or target.get('boundary') != 'message' or
                target.get('mode') != profile['attachment']['mode'] or not private_socket(target)):
            raise ValueError('UnsupportedApplicationBoundary: observed local message attachment required')
        owner = target.get('owner', {})
        if not alive(plan.get('runtimeIdentity', {})) or not alive(owner):
            raise ValueError('ApplicationEndpointOwnerUnavailable')
        self.max_record = profile['limits']['max_record']
        self.mode = target['mode']; self.eof = self.write_closed = False
        self.deadline = time.monotonic() + 300; self.remaining = 16 * 1024 * 1024
        self.socket = None
        try:
            if self.mode == 'localhost-udp-datagram-proxy':
                if target.get('observation') != 'structured-ready-event' or not any(
                        e.get('transport') == 'udp' and e.get('host') == target['host'] and e.get('port') == target['port'] for e in sockets(owner['pid'])):
                    raise ValueError('ApplicationEndpointOwnerUnavailable')
                self.socket = socket.socket(socket.AF_INET6 if ':' in target['host'] else socket.AF_INET, socket.SOCK_DGRAM)
                self.socket.connect((target['host'], target['port']))
            elif self.mode == 'seqpacket-fd':
                if target.get('attachmentState') != 'available': raise ValueError('UnsupportedApplicationBoundary:AttachmentConsumed')
                native = target.get('nativeOwner', {})
                if target.get('observation') != 'supervisor-owned-record-adapter' or not alive(native) or not owned_seqpacket(native['pid'], target.get('nativeFd'), target.get('nativeInode')):
                    raise ValueError('NativeApplicationFDOwnerUnavailable')
                if not any(e.get('transport') == 'unix-seqpacket' and e.get('path') == target['path'] for e in sockets(owner['pid'])):
                    raise ValueError('ApplicationEndpointOwnerUnavailable')
                self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                self.socket.settimeout(3); self.socket.connect(target['path'])
                pid, uid, _ = struct.unpack('3i', self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if pid != owner['pid'] or uid != os.geteuid() or not alive(owner):
                    raise ValueError('AttachmentPeerIdentityMismatch')
                nonce = secrets.token_hex(32)
                request = {'schema':HANDSHAKE_SCHEMA, 'nonce':nonce, 'profileBinding':plan['profileBinding'], 'lockDigest':plan['lockDigest']}
                self.socket.send(json.dumps(request, sort_keys=True, separators=(',', ':')).encode())
                try: data, _, flags, _ = self.socket.recvmsg(4096)
                except (ConnectionResetError, BrokenPipeError, TimeoutError) as error:
                    raise ValueError('UnsupportedApplicationBoundary:AttachmentUnavailable') from error
                try:
                    from .service_storage import strict_json
                except ImportError:
                    from service_storage import strict_json
                response = strict_json(data)
                if flags & socket.MSG_TRUNC or not isinstance(response,dict): raise ValueError('InvalidAttachmentAcknowledgement')
                if set(response) == {'schema','error'} and response['schema'] == HANDSHAKE_SCHEMA:
                    raise ValueError('UnsupportedApplicationBoundary:' + str(response['error']))
                if response != {'schema':HANDSHAKE_SCHEMA, 'nonce':nonce, 'state':'accepted', 'maxRecord':self.max_record}:
                    raise ValueError('InvalidAttachmentAcknowledgement')
            else:
                raise ValueError('UnsupportedApplicationBoundary: message attachment mode')
            if not alive(owner): raise ValueError('ApplicationEndpointOwnerChanged')
            self.socket.settimeout(30)
        except BaseException:
            if self.socket is not None: self.socket.close()
            raise

    def _budget(self, count):
        import time
        if time.monotonic() >= self.deadline or count > self.remaining:
            self.close(); raise ValueError('ApplicationSessionBudgetExhausted')

    def send_record(self, data):
        import socket
        if not isinstance(data, (bytes, bytearray)) or len(data) > self.max_record:
            raise ValueError('OversizedApplicationRecord')
        if self.write_closed: raise ValueError('ApplicationWriteClosed')
        self._budget(len(data))
        if self.mode == 'seqpacket-fd' and not data:
            self.finish(); return
        try: count = self.socket.send(data, socket.MSG_DONTWAIT)
        except (BlockingIOError, InterruptedError) as error:
            raise BlockingIOError('ApplicationBackpressure') from error
        if count != len(data): raise ValueError('ApplicationRecordPartialSend')
        self.remaining -= count

    def receive_record(self):
        import socket
        self._budget(0)
        data, _, flags, _ = self.socket.recvmsg(self.max_record + 1)
        if flags & socket.MSG_TRUNC or len(data) > self.max_record:
            raise ValueError('OversizedApplicationRecord')
        self._budget(len(data)); self.remaining -= len(data)
        if self.mode == 'seqpacket-fd' and not data: self.eof = True
        return data

    def finish(self):
        if self.mode != 'seqpacket-fd': raise ValueError('UnsupportedApplicationEOF: best-effort datagram boundary')
        if self.write_closed: return
        self._budget(0)
        self.socket.send(b''); self.write_closed = True

    def half_close(self): raise ValueError('UnsupportedApplicationHalfClose: message boundary')
    def send(self, data): return self.send_record(data)
    def receive(self, size=None):
        if size is not None and (type(size) is not int or size < self.max_record):
            raise ValueError('UnsupportedPartialRecordReceive')
        return self.receive_record()
    def close(self):
        if self.socket is not None:
            self.socket.close(); self.socket = None
    def __enter__(self): return self
    def __exit__(self, *_): self.close()
