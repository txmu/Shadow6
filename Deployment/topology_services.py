"""Materialize generated local topology configs as locked Named Services."""
from __future__ import annotations

import re
from pathlib import Path

try:
    from .core_catalog import CoreCatalog
    from .profile_availability import inspect_profile
    from .protocol_context import minimal_context
    from .service_registry import ServiceRegistry
except ImportError:
    from core_catalog import CoreCatalog
    from profile_availability import inspect_profile
    from protocol_context import minimal_context
    from service_registry import ServiceRegistry


_NAMESPACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def materialize_local_topology(*, topology: dict, config_paths: dict[str, Path],
                               namespace: str, catalog: CoreCatalog | None = None,
                               registry: ServiceRegistry | None = None) -> list[dict]:
    """Create, lock, and apply generated local nodes without starting them.

    The topology generator owns local key/config creation. This adapter binds
    each generated file to the same Profile, S6P1 role/identity, DeploymentLock,
    Limits and supervisor contract used by `shadow6 setup`. Existing service
    records are never overwritten; callers must request an explicit upgrade.
    """
    if not isinstance(namespace, str) or not _NAMESPACE.fullmatch(namespace):
        raise ValueError("named_service_namespace must be one bounded namespace")
    nodes = topology.get("nodes")
    if not isinstance(nodes, list) or set(config_paths) != {node["name"] for node in nodes}:
        raise ValueError("generated configs must cover every topology node")
    for node in nodes:
        host = node.get("ssh_host")
        if host and host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("Named Services can only realize local topology nodes")
        if node.get("deploy_root"):
            raise ValueError("Named Services do not accept remote deploy_root")

    catalog = catalog or CoreCatalog()
    registry = registry or ServiceRegistry(catalog=catalog)
    try:
        from .native_realization import engine_id, selected_engine
        from .profile_registry import topology_profile
    except ImportError:
        from native_realization import engine_id, selected_engine
        from profile_registry import topology_profile

    broker = next(node for node in nodes if node["type"] == "broker")
    core = engine_id(selected_engine(broker["engines"], "broker"))
    profile = topology_profile(core, topology.get("global", {}))
    names = [namespace + "/" + node["name"] for node in nodes]
    if len(set(names)) != len(names):
        raise ValueError("duplicate generated Named Service name")
    for name in names:
        try:
            registry.inspect(name)
        except ValueError as error:
            if str(error) != "unknown named service":
                raise
        else:
            raise ValueError("Named Service already exists; use explicit stopped service upgrade: " + name)

    available = inspect_profile(catalog, core, profile["id"])
    if not available["available"]:
        diagnostics = available["diagnostics"]
        raise ValueError("ProfileUnavailable: " + "; ".join(
            item.get("message", item.get("code", "unavailable")) for item in diagnostics))

    created = []
    try:
        result = []
        for node, name in zip(nodes, names):
            context = minimal_context(core)
            context["role"] = node["type"]
            context["identity"] = {"ref": node["name"]}
            path = Path(config_paths[node["name"]]).absolute()
            registry.create(name, core=core, profile=profile["id"],
                            config={"config_path": str(path)}, context=context)
            created.append(name)
        for name in created:
            registry.lock(name)
            result.append(registry.apply(name))
        return result
    except BaseException:
        for name in reversed(created):
            try:
                registry.remove(name)
            except (OSError, ValueError):
                pass
        raise
