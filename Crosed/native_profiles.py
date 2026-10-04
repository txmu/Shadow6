"""Native Profile authority, independent of toolchains and runtime discovery.

These are source contracts, never an availability assertion. Consumers must
verify installed artifacts, feature reports, platform support and lifecycle
observations before advertising an available service. Native protocols are not
translated by this registry. Returned records are detached copies.
"""
from copy import deepcopy
import hashlib
import json

SCHEMA = 'shadow6.native-profile.v1'
ROLES = ['broker', 'agent', 'client']

# family, directory, native transport, config transport, toolchain,
# application connection/record bound, benchmark compatibility name
_ROWS = (
    ('go', 'Go', 'kcp', 'kcp', 'go', 64, 'go'),
    ('rust', 'Rust', 'quic', 'quic', 'cargo', 256, 'rust'),
    ('gleam', 'Gleam', 'secure-stream', 'secure-stream', 'gleam', 1, 'gleam'),
    ('ada', 'Ada', 'cell-relay', 'cell-relay', 'gnatmake', 1, 'ada'),
    ('nim', 'Nim', 'webrtc', 'webrtc', 'nim', 1, 'nim'),
    ('pony', 'Pony', 'udp', 'udp', 'ponyc', 1172, 'pony'),
    ('zig', 'Zig', 'enet', 'enet', 'zig', 16, 'zig'),
    ('d', 'D', 'secure-stream', 'secure-stream', 'ldc2', 1, 'd'),
    ('cpp', 'Cpp', 'sctp-tls13', 'sctp', 'c++', 64, 'cpp'),
    ('idris', 'Idris', 'udp', 'udp', 'idris2', 1024, 'idris'),
    ('hare', 'Hare', 'udp', 'udp', 'hare', 978, 'hare'),
    ('carp', 'Carp', 'udp', 'udp', 'carp', 986, 'carp'),
    ('gleam', 'Gleam', 'micro-mux', 'micro-mux', 'gleam', 65465, 'gleam-mux'),
)
_MESSAGE_MODES = {'pony': 'seqpacket-fd', 'hare': 'seqpacket-fd',
                  'carp': 'seqpacket-fd', 'idris': 'seqpacket-fd',
                  'gleam-mux': 'localhost-udp-datagram-proxy'}


def _boundary(family, limit, alias):
    mode = _MESSAGE_MODES.get(alias)
    if mode == 'seqpacket-fd':
        return dict(kind='message', mode=mode, roles=['client'], max_record=limit,
            message_preserving=True, backpressure='native-window',
            endpoint_discovery='stdout-ready-jsonl-v1',
            producer_send_success='kernel-queue-only', oversize='discard-record-continue',
            transient_error='retry-eagain-eintr', hard_error='fail-closed',
            eof='empty-record-drain', close='drain-accepted-then-stop')
    if mode == 'localhost-udp-datagram-proxy':
        return dict(kind='message', mode=mode, roles=['client'], message_preserving=True,
            ordered=False, reliable=False, delivery='best-effort',
            backpressure='udp-datagram-loss', max_record=limit, listener_ownership='core',
            endpoint_discovery='stdout-ready-jsonl-v1', listener_ready='bound-and-listening',
            local_peer_limit=1, oversize='discard-datagram')
    return dict(kind='stream', mode='localhost-tcp-proxy', roles=['client'],
        full_duplex=True, ordered=True, reliable=True, backpressure='tcp-flow-control',
        half_close=True, listener_ownership='core', endpoint_discovery='stdout-ready-jsonl-v1',
        listener_ready='bound-and-listening', local_connection_limit=limit,
        shutdown='close-active-flows', eof='propagate-half-close',
        connection_mapping='one-local-connection-per-native-flow')


def _record(row):
    family, directory, transport, config_transport, toolchain, limit, alias = row
    boundary = _boundary(family, limit, alias)
    return dict(schema=SCHEMA, id=family + '-' + transport, core=family,
        primary=alias == family, roles=ROLES.copy(), nativeTransport=transport,
        configTransport=config_transport, applicationBoundary=boundary,
        artifact=f'Core-{directory}/shadow6-{family}', benchmarkAlias=alias,
        realization=dict(schema='shadow6.core-config.v1', version='1',
            launcher='native-files' if boundary['mode'] == 'seqpacket-fd' else 'native-config',
            source='CLI/native_config.py' if boundary['mode'] == 'seqpacket-fd' else
                   'Deployment/native_realization.py',
            materialReferences=[{'role': 'broker', 'fields': ['tls_cert', 'tls_key'],
                                 'requiredTogether': True, 'maxBytes': 16384}]
                if family in {'ada', 'nim', 'd'} else []),
        requirements=dict(toolchains=[toolchain],
            libraries=['libdatachannel'] if family == 'nim' else [],
            kernelFeatures=['sctp'] if family == 'cpp' else [],
            platformContract=f'Core-{directory}/README.md'),
        readiness=dict(applicationEvent=boundary.get('endpoint_discovery'),
            acknowledgement='identity-owned-endpoint-and-material-recheck',
            processAliveSufficient=False, clientStartup='owned-application-endpoint',
            agentStartup='owned-listener-or-declared-control-peer',
            brokerStartup='owned-listener', controlPeerProves='tcp-connection-only'),
        observation=dict(contract='Deployment/runtime_observation.py',
            required=['process-identity', 'parent-child', 'owned-endpoint',
                      'actual-transport', 'readiness', 'material-digests', 'component-health'],
            platformDegradation='explicit-supervisor-capabilities'),
        shutdown=dict(eof=boundary.get('eof'), halfClose=boundary.get('half_close', False),
            drain=boundary.get('close', boundary.get('shutdown', 'no-delivery-guarantee'))),
        limits={key: boundary[key] for key in ('max_record', 'local_connection_limit',
                'local_peer_limit') if key in boundary},
        limit_model=_limit_model(boundary),
        nativeSecurity=dict(authority='Crosed/security_capabilities.json', core='shadow6-' + family),
        composition=dict(authority='Deployment/service_composition.py',
            routes='S6P1.routes', nativeTranslation=False,
            components=['BrokerSet', 'Gate', 'Guard', 'S6EPE', 'S6NA'],
            admission='explicit-policy-and-boundary-validation'),
        attachment=dict(kind=boundary['kind'], mode=boundary['mode'],
            adapter=({'kind':'local-record-relay', 'pendingRecordsPerDirection':1,
                      'activePeers':1, 'drainSeconds':8, 'sendSuccess':'local-kernel-queue-only'}
                     if boundary['mode'] == 'seqpacket-fd' else None),
            transport={'localhost-tcp-proxy': 'tcp', 'localhost-udp-datagram-proxy': 'udp',
                       'seqpacket-fd': 'unix-seqpacket'}[boundary['mode']],
            roles=boundary['roles'].copy(), unsupportedError='UnsupportedApplicationBoundary'),
        featureReport=dict(core='shadow6-' + family,
            transport='secure-stream' if alias == 'gleam-mux' else transport,
            boundaryMode=boundary['mode']))


def _limit_model(boundary):
    """Native maxima are not mislabeled as expandable protocol capacity."""
    # Leave room for the default optional Gate (128 bounded connections) and
    # envelope sidecar while keeping the descriptor ceiling finite.
    safe = {'process_fds': 512}
    recommended = {'process_fds': 1024}
    hard = {'process_fds': None}
    capacities = {'process_fds': dict(memory_per_unit=1024, fds_per_unit=1,
                                    native_ceiling=None, mutable=True)}
    enforcers = {'process_fds': 'supervisor.kernel.RLIMIT_NOFILE'}
    for key in ('max_record', 'local_connection_limit', 'local_peer_limit'):
        if key not in boundary: continue
        value = boundary[key]
        safe[key] = recommended[key] = value
        hard[key] = value if key == 'max_record' else None
        capacities[key] = dict(memory_per_unit=1 if key == 'max_record' else 131072,
            fds_per_unit=0 if key == 'max_record' else 2, native_ceiling=value,
            mutable=key == 'max_record')
        enforcers[key] = ('supervisor.application-record-adapter' if key == 'max_record'
            and boundary['mode'] == 'seqpacket-fd' else 'core.native-boundary')
        if boundary['mode'] == 'localhost-udp-datagram-proxy': capacities[key]['mutable'] = False
    return dict(schema='shadow6.profile-limits.v1', hard_protocol_limits=hard,
        safe_defaults=safe, recommended_limits=recommended,
        capacity_models=capacities, enforced_by=enforcers)


_PROFILES = tuple(_record(row) for row in _ROWS)
CORE_IDS = tuple(p['core'] for p in _PROFILES if p['primary'])


def profiles(core=None):
    if core is not None and (not isinstance(core, str) or core not in CORE_IDS):
        raise ValueError('UnknownCore')
    return deepcopy([p for p in _PROFILES if core is None or p['core'] == core])


def select_profile(core, profile=None):
    """Normalize an explicit family and optional primary Profile at setup time.

    Runtime callers must pass their locked Profile ID. Unknown/mismatched IDs
    always fail; no fallback is permitted.
    """
    if not isinstance(core, str) or (profile is not None and not isinstance(profile, str)):
        raise ValueError('InvalidCoreProfileBinding')
    candidates = profiles(core)
    matches = [p for p in candidates if p['id'] == profile] if profile is not None else [
        p for p in candidates if p['primary']]
    if len(matches) != 1:
        raise ValueError('InvalidCoreProfileBinding')
    return matches[0]


def profile_digest(profile):
    if not isinstance(profile, dict) or not isinstance(profile.get('core'), str) or not isinstance(profile.get('id'), str):
        raise ValueError('InvalidCoreProfileBinding')
    canonical = select_profile(profile['core'], profile['id'])
    if json.dumps(profile, sort_keys=True, separators=(',', ':'), allow_nan=False) != json.dumps(canonical, sort_keys=True, separators=(',', ':'), allow_nan=False):
        raise ValueError('NativeProfileContractDrift')
    return 'sha256:' + hashlib.sha256(json.dumps(canonical, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def application_boundaries(core):
    return [p['applicationBoundary'] for p in profiles(core)]


def transport_map(*, configuration=False):
    field = 'configTransport' if configuration else 'nativeTransport'
    return {'shadow6-' + p['core']: p[field] for p in profiles() if p['primary']}


def artifact_map(*, benchmark=False):
    return {(p['benchmarkAlias'] if benchmark else 'shadow6-' + p['core']):
            p['artifact'] for p in profiles() if benchmark or p['primary']}


def topology_profile(core, settings):
    """Immediately normalize the legacy Gleam selector into a Profile ID."""
    profile_id = settings.get('native_profile')
    legacy = settings.get('gleam_transport')
    if legacy is not None:
        if core != 'gleam' or not isinstance(legacy, str):
            raise ValueError('InvalidCoreProfileBinding: gleam_transport applies only to Gleam')
        legacy_profile = select_profile(core, 'gleam-' + legacy)
        if profile_id is not None and profile_id != legacy_profile['id']:
            raise ValueError('InvalidCoreProfileBinding: conflicting legacy transport')
        profile_id = legacy_profile['id']
    return select_profile(core, profile_id)


PROFILE_BINDING_SCHEMA = 'shadow6.profile-binding.v1'


def bind_profile(core, profile=None):
    """Make a local binding at explicit setup/reconfiguration time only."""
    selected = select_profile(core, profile)
    return dict(schema=PROFILE_BINDING_SCHEMA, core=core, profile=selected['id'],
                contractDigest=profile_digest(selected))


def validate_profile_binding(binding, *, core=None, current=True):
    import re
    fields = {'schema', 'core', 'profile', 'contractDigest'}
    if (not isinstance(binding, dict) or set(binding) != fields or
            binding['schema'] != PROFILE_BINDING_SCHEMA or
            not isinstance(binding['core'], str) or
            not isinstance(binding['profile'], str) or not binding['profile'] or
            not isinstance(binding['contractDigest'], str) or
            re.fullmatch(r'sha256:[0-9a-f]{64}', binding['contractDigest']) is None):
        raise ValueError('InvalidProfileBinding')
    selected = select_profile(binding['core'], binding['profile'])
    if core is not None and binding['core'] != core:
        raise ValueError('InvalidCoreProfileBinding')
    if current and binding['contractDigest'] != profile_digest(selected):
        raise ValueError('ProfileBindingDrift: explicitly stop and reconfigure/relock')
    return selected


def validate_profile_realization(binding, native, context=None):
    """Validate application/config selectors without interpreting native wire."""
    selected = validate_profile_binding(binding)
    if not isinstance(native, dict):
        raise ValueError('ProfileConfigMismatch: native configuration must be an object')
    role = native.get('role')
    if role is not None and role not in selected['roles']:
        raise ValueError('ProfileConfigMismatch: role is outside Profile contract')
    if 'core' in native and native['core'] not in (selected['core'], 'shadow6-' + selected['core']):
        raise ValueError('ProfileConfigMismatch: native Core identity differs')
    role_config = native.get(role) if isinstance(role, str) else None
    selectors = [value['transport'] for value in (native, role_config)
                 if isinstance(value, dict) and 'transport' in value]
    if any(value != selected['configTransport'] for value in selectors):
        raise ValueError('ProfileConfigMismatch: transport differs from locked Profile')
    # A non-primary Profile requires an actual selector; absence must never
    # silently realize the Core's primary transport.
    if not selected['primary'] and not selectors and role in ('agent', 'client'):
        raise ValueError('ProfileConfigMismatch: explicit non-primary transport required')
    if context is not None:
        requested = {route['boundary'] for route in context['routes'] if route.get('boundary')}
        if requested - {selected['applicationBoundary']['kind']}:
            raise ValueError('ProfileCapabilityMismatch: S6P1 application boundary differs')
    return selected


def native_material_paths(binding, native):
    from pathlib import Path
    selected = validate_profile_realization(binding, native)
    result = {}
    for reference in selected['realization']['materialReferences']:
        value = native.get(reference['role'])
        if not isinstance(value, dict): continue
        fields = reference['fields']
        present = [field for field in fields if value.get(field)]
        if reference['requiredTogether'] and present and len(present) != len(fields):
            raise ValueError('ProfileMaterialMismatch: complete TLS material required')
        for field in present:
            path = value[field]
            if not isinstance(path, str) or len(path.encode()) > 4096 or not Path(path).is_absolute() or '\0' in path:
                raise ValueError('ProfileMaterialMismatch: bounded absolute material path required')
            result[reference['role'] + '.' + field] = path
    if len(set(result.values())) != len(result):
        raise ValueError('ProfileMaterialMismatch: material paths must be distinct')
    return result
