"""Reuse S6P1 as portable intent; local realization lives in CoreBinding."""
import hashlib
import sys
from pathlib import Path

# Resolve siblings both in a checkout and in share/shadow6/tree or deployment.
_root = Path(__file__).resolve().parents[1]
_paths = [_root / 'Public6', _root / 'tree/Public6', _root / 'modules']
_paths += [ancestor / 'share/shadow6/tree/Public6' for ancestor in Path(__file__).resolve().parents]
for _path in _paths:
    if (_path / 'join_code.py').is_file():
        sys.path.insert(0, str(_path))
        break
from join_code import pack_protocol, unpack_protocol, resolve_protocol_envelope
try:
    from .broker_set import validate_routes
except ImportError:
    from broker_set import validate_routes

_LOCAL = {'pid', 'processIdentity', 'pidfd', 'binaryDigest', 'config_path', 'configPath', 'telemetry', 'runtime'}


def validate_context(value):
    if isinstance(value, str):
        value = unpack_protocol(value)
    # Existing S6P1 validator owns the schema. Also enforce portable bounds.
    token = pack_protocol(value)
    def check(item):
        if isinstance(item, dict):
            if set(item) & _LOCAL:
                raise ValueError('local runtime/realization material cannot enter S6P1')
            for child in item.values(): check(child)
        elif isinstance(item,list):
            for child in item: check(child)
    check(value)
    validate_routes(value['routes'])
    return unpack_protocol(token)


def minimal_context(core=None):
    # Unspecified logical role/identity stays unspecified, never inferred from PID.
    return validate_context({'schema':'shadow6.protocol-envelope.v1', 'version':1,
        'purpose':'local-service', 'core':core or 'all', 'role':'all',
        'identity':{}, 'routes':[], 'components':{}, 'credentials':{}})


def context_digest(value):
    return 'sha256:' + hashlib.sha256(pack_protocol(validate_context(value)).encode()).hexdigest()


def core_allowed(scope, core):
    if isinstance(scope,list): return core in scope
    return scope in ('all',core)


def check_binding(context, core, catalog):
    context = validate_context(context)
    descriptor = catalog.inspect(core)
    if not core_allowed(context['core'], core):
        raise ValueError('S6P1 core scope conflicts with explicit CoreBinding')
    scope = context['role']
    if scope != 'all' and scope not in descriptor['roles']:
        raise ValueError('capability unavailable: Core role')
    for route in context['routes']:
        boundary = route.get('boundary') if isinstance(route, dict) else None
        if boundary and boundary not in descriptor['applicationBoundaries']:
            raise ValueError('capability unavailable: application boundary')
    return descriptor


def admit(context, *, component=None, role=None):
    context = validate_context(context)
    if role is None and context['role'] != 'all': role = context['role']
    return resolve_protocol_envelope(pack_protocol(context), component=component, role=role)[0]


def admit_realization(context, *, native_role=None, components=()):
    """Authorize actual local consumers using the existing S6P1 scope validator.

    Empty component intent remains unspecified for legacy local configurations;
    explicit true/false intent must match realization. Local paths are never
    projected back into the portable component model.
    """
    context = validate_context(context)
    if context['role'] == 'all' and native_role is None and any(k in context['credentials'] for k in ('passport','visa')):
        raise ValueError('capability unavailable: credential-bearing deployment requires an explicit logical or native role')
    context = admit(context, role=native_role)
    actual = set(components)
    managed = {'gate', 'guard', 's6epe'}
    if actual - managed: raise ValueError('unknown managed component realization')
    for component in sorted(managed):
        desired = context['components'].get(component)
        if desired is True and component not in actual:
            raise ValueError(f'capability unavailable: S6P1 {component} requires an explicit local realization')
        if component in actual:
            # Enforces explicit disablement and signed Passport/Visa scope.
            admit(context, component=component, role=native_role)
    return context
