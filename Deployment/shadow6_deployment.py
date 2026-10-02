#!/usr/bin/env python3
"""Strict, Core-neutral deployment intent for Shadow6.

The manifest describes identities, services and policy.  It deliberately does
not contain native Core argv or private keys; drivers translate the intent to
the installed Core without rebuilding it.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

MAX_BYTES = 1024 * 1024
MAX_NODES = 256
MAX_SERVICES = 1024
MAX_POLICIES = 2048
CORES = frozenset(("go", "rust", "gleam", "ada", "nim", "pony", "zig", "d", "cpp", "idris", "hare", "carp"))
ROLES = frozenset(("broker", "agent", "client", "gate"))
SCHEMA = "shadow6.deployment.v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


def _no_float(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("floating-point values are not permitted in deployment manifests")
    if isinstance(value, dict):
        for item in value.values():
            _no_float(item)
    elif isinstance(value, list):
        for item in value:
            _no_float(item)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate manifest field: {key}")
        result[key] = value
    return result


def _read(path: Path) -> Any:
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES:
        raise ValueError("deployment manifest is oversized")
    try:
        if path.suffix.lower() == ".json":
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_float=lambda _: (_ for _ in ()).throw(ValueError("float")), parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
        else:
            try:
                import yaml  # type: ignore
            except ImportError as exc:
                raise ValueError("YAML manifests require PyYAML; use canonical JSON in minimal installations") from exc
            value = yaml.safe_load(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("manifest must be UTF-8") from exc
    if not isinstance(value, dict):
        raise ValueError("manifest root must be an object")
    _no_float(value)
    return value


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def _keys(value: dict, allowed: set[str], required: set[str], label: str) -> None:
    if set(value) - allowed or not required <= set(value):
        raise ValueError(f"invalid {label} fields")


def validate_manifest(value: dict) -> dict:
    _keys(value, {"apiVersion", "kind", "metadata", "spec"}, {"apiVersion", "kind", "metadata", "spec"}, "manifest")
    if value["apiVersion"] != SCHEMA or value["kind"] != "Deployment":
        raise ValueError("unsupported deployment manifest")
    if not isinstance(value["metadata"], dict):
        raise ValueError("metadata must be an object")
    _keys(value["metadata"], {"name", "labels"}, {"name"}, "metadata")
    name = _id(value["metadata"]["name"], "metadata.name")
    labels = value["metadata"].get("labels", {})
    if not isinstance(labels, dict) or len(labels) > 32 or any(not isinstance(k, str) or not _ID.fullmatch(k) or not isinstance(v, str) or len(v) > 128 for k, v in labels.items()):
        raise ValueError("invalid metadata.labels")
    spec = value["spec"]
    if not isinstance(spec, dict):
        raise ValueError("spec must be an object")
    allowed = {"artifact", "brokerSets", "nodes", "services", "policies", "applications"}
    _keys(spec, allowed, {"artifact", "brokerSets", "nodes", "services", "policies", "applications"}, "spec")
    artifact = spec["artifact"]
    if not isinstance(artifact, dict):
        raise ValueError("artifact must be an object")
    _keys(artifact, {"version", "platform", "digest", "source"}, {"version"}, "artifact")
    _id(artifact["version"], "artifact.version")
    if "platform" in artifact and (not isinstance(artifact["platform"], str) or len(artifact["platform"]) > 64):
        raise ValueError("invalid artifact.platform")
    if "digest" in artifact and (not isinstance(artifact["digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"])):
        raise ValueError("invalid artifact.digest")
    brokers = spec["brokerSets"]
    if not isinstance(brokers, list) or not 1 <= len(brokers) <= 32:
        raise ValueError("brokerSets must contain 1..32 logical Broker sets")
    broker_ids = set()
    for broker in brokers:
        if not isinstance(broker, dict):
            raise ValueError("invalid broker set")
        _keys(broker, {"id", "identity", "endpoints", "core", "mode"}, {"id", "identity", "endpoints", "core"}, "broker set")
        bid = _id(broker["id"], "broker set id")
        if bid in broker_ids:
            raise ValueError("duplicate broker set id")
        broker_ids.add(bid)
        _id(broker["identity"], "broker identity")
        if broker["core"] not in CORES:
            raise ValueError("unknown Broker Core")
        endpoints = broker["endpoints"]
        if not isinstance(endpoints, list) or not 1 <= len(endpoints) <= 16 or not all(isinstance(x, str) and 1 <= len(x) <= 512 for x in endpoints):
            raise ValueError("broker endpoints must contain 1..16 URLs")
        if broker.get("mode", "replica") not in ("replica", "standby"):
            raise ValueError("independent Broker authorities require separate topologies")
    nodes = spec["nodes"]
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_NODES:
        raise ValueError("nodes must contain 1..256 entries")
    node_ids = set()
    for node in nodes:
        if not isinstance(node, dict):
            raise ValueError("invalid node")
        _keys(node, {"id", "role", "core", "brokerSet", "platform", "artifact", "identityRef", "labels"}, {"id", "role", "core", "brokerSet", "identityRef"}, "node")
        nid = _id(node["id"], "node id")
        if nid in node_ids:
            raise ValueError("duplicate node id")
        node_ids.add(nid)
        if node["role"] not in ROLES or node["core"] not in CORES or node["brokerSet"] not in broker_ids:
            raise ValueError("invalid node role, Core or brokerSet")
        if not isinstance(node["identityRef"], str) or not _REF.fullmatch(node["identityRef"]):
            raise ValueError("invalid node identityRef")
    services = spec["services"]
    if not isinstance(services, list) or len(services) > MAX_SERVICES:
        raise ValueError("services must be a bounded list")
    service_ids = set()
    for service in services:
        if not isinstance(service, dict):
            raise ValueError("invalid service")
        _keys(service, {"id", "node", "name", "protocol", "listen", "target", "boundary"}, {"id", "node", "name", "protocol", "target"}, "service")
        sid = _id(service["id"], "service id")
        if sid in service_ids:
            raise ValueError("duplicate service id")
        service_ids.add(sid)
        if service["node"] not in node_ids or not isinstance(service["name"], str) or not 1 <= len(service["name"]) <= 128 or service["protocol"] not in ("stream", "message", "credited") or not isinstance(service["target"], str) or not 1 <= len(service["target"]) <= 256:
            raise ValueError("invalid service fields")
        if "listen" in service and (not isinstance(service["listen"], str) or not service["listen"].startswith(("127.0.0.1:", "[::1]:"))):
            raise ValueError("services must bind loopback endpoints")
        if "boundary" in service and service["boundary"] not in ("stream", "message", "credited"):
            raise ValueError("invalid service boundary")
    policies = spec["policies"]
    if not isinstance(policies, list) or len(policies) > MAX_POLICIES:
        raise ValueError("policies must be a bounded list")
    for policy in policies:
        if not isinstance(policy, dict):
            raise ValueError("invalid policy")
        _keys(policy, {"id", "subject", "service", "effect", "expiresAt"}, {"id", "subject", "service", "effect"}, "policy")
        _id(policy["id"], "policy id")
        if not isinstance(policy["subject"], str) or not isinstance(policy["service"], str) or policy["service"] not in service_ids or policy["effect"] not in ("allow", "deny"):
            raise ValueError("invalid policy target")
    apps = spec["applications"]
    if not isinstance(apps, list) or len(apps) > 256:
        raise ValueError("applications must be a bounded list")
    for app in apps:
        if not isinstance(app, dict):
            raise ValueError("invalid application")
        _keys(app, {"id", "subject", "requirements", "ttl"}, {"id", "subject", "requirements"}, "application")
        _id(app["id"], "application id")
        if not isinstance(app["subject"], str) or not isinstance(app["requirements"], dict):
            raise ValueError("invalid application")
        req = app["requirements"]
        _keys(req, {"boundary", "ordered", "reliable", "fullDuplex", "maxRecord"}, {"boundary"}, "application requirements")
        if req["boundary"] not in ("stream", "message", "credited") or any(type(req.get(k)) is not bool for k in ("ordered", "reliable", "fullDuplex") if k in req):
            raise ValueError("invalid application requirements")
        if "maxRecord" in req and (type(req["maxRecord"]) is not int or not 1 <= req["maxRecord"] <= 16 * 1024 * 1024):
            raise ValueError("invalid application maxRecord")
    result = {"apiVersion": value["apiVersion"], "kind": value["kind"], "metadata": {"name": name, "labels": dict(sorted(labels.items()))}, "spec": spec}
    return result


def load_manifest(path: str | Path) -> dict:
    return validate_manifest(_read(Path(path)))


def canonical_manifest(manifest: dict) -> bytes:
    return json.dumps(validate_manifest(manifest), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def manifest_lock(manifest: dict) -> dict:
    canonical = canonical_manifest(manifest)
    return {"schema": "shadow6.deployment-lock.v1", "manifestDigest": "sha256:" + hashlib.sha256(canonical).hexdigest(), "manifest": json.loads(canonical), "brokerSets": [{"id": b["id"], "identity": b["identity"], "endpoints": b["endpoints"], "core": b["core"], "mode": b.get("mode", "replica")} for b in manifest["spec"]["brokerSets"]], "nodes": [{"id": n["id"], "role": n["role"], "core": n["core"], "brokerSet": n["brokerSet"], "identityRef": n["identityRef"]} for n in manifest["spec"]["nodes"]]}


def plan_manifest(manifest: dict) -> dict:
    manifest = validate_manifest(manifest)
    lock = manifest_lock(manifest)
    return {"schema": "shadow6.deployment-plan.v1", "manifestDigest": lock["manifestDigest"], "logicalBrokers": [{"id": b["id"], "endpoints": len(b["endpoints"]), "identity": b["identity"], "mode": b.get("mode", "replica")} for b in manifest["spec"]["brokerSets"]], "nodes": [{"id": n["id"], "role": n["role"], "core": n["core"], "brokerSet": n["brokerSet"]} for n in manifest["spec"]["nodes"]], "services": [{"id": s["id"], "node": s["node"], "boundary": s.get("boundary", s.get("protocol"))} for s in manifest["spec"]["services"]], "requiresCoreBuild": False, "nativeConfigStrategy": "installed-core-driver"}
