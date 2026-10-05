"""Native wire-family admission shared by fleet and node realization.

Core-neutral control interfaces do not translate native data planes. The
legacy Zig broker declaration adds control dialect support to a Go/Rust
broker declaration; it does not choose a different native invocation.
"""
import re

_ENGINE = re.compile(r'[a-z][a-z0-9-]{0,63}')


def engine_id(value):
    if not isinstance(value, str):
        raise ValueError('invalid topology engine')
    identity = value.removeprefix('shadow6-')
    if not _ENGINE.fullmatch(identity):
        raise ValueError('invalid topology engine')
    return identity


def selected_engine(engines, role):
    if engines is None or engines == []: raise ValueError('CoreSelectionRequired')
    if role not in {'broker', 'agent', 'client'}:
        raise ValueError('invalid topology role')
    if not isinstance(engines, list) or not 1 <= len(engines) <= 12:
        raise ValueError('exactly one core engine required')
    selected = [engine_id(e) for e in engines]
    if len(set(selected)) != len(selected):
        raise ValueError('duplicate core engine')
    if len(selected) == 2 and role == 'broker' and 'zig' in selected:
        ordinary = next(e for e in selected if e != 'zig')
        if ordinary not in {'go', 'rust'}:
            raise ValueError('Zig broker control exception requires Go or Rust')
        return ordinary
    if len(selected) != 1:
        raise ValueError('exactly one core engine required; Zig exception is broker-only')
    return selected[0]


def check_node_binding(engine, core, *, role):
    if role not in {'broker', 'agent', 'client', 'gate'}:
        raise ValueError('invalid topology role')
    if engine_id(core) != engine_id(engine):
        raise ValueError('all broker, agent, and client nodes must use the same core engine; CoreBinding conflicts with topology engine')
    return engine_id(engine)


def check_topology(bindings, *, engine=None):
    if not isinstance(bindings, list) or not 1 <= len(bindings) <= 256:
        raise ValueError('topology requires 1..256 native bindings')
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != {'role', 'core'}:
            raise ValueError('invalid topology binding')
        if engine is None:
            engine = binding['core']
        check_node_binding(engine, binding['core'], role=binding['role'])
    return {'schema': 'shadow6.topology-compatibility.v1',
            'engine': engine_id(engine), 'nativeTranslation': False}
