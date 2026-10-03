"""Compare one Named Service's S6P1 intent with claims and Linux observations."""
from __future__ import annotations

import json
import os
import selectors
import subprocess
import time
from urllib.parse import urlsplit

from Deployment.core_catalog import CoreCatalog
from Deployment.service_registry import ServiceRegistry, digest, encoded
from Deployment.service_storage import private_read, strict_json
from Deployment.runtime_observation import validate_observation, private_socket
from Deployment.protocol_context import validate_context, admit_realization


def _feature_report(binary: str) -> dict:
    process = subprocess.Popen([binary, "--feature-report"], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, close_fds=True)
    data = bytearray()
    deadline = time.monotonic() + 3
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("feature-report timeout")
                events = selector.select(remaining)
                if not events:
                    raise ValueError("feature-report timeout")
                block = os.read(process.stdout.fileno(), min(16385, 65537 - len(data)))
                data.extend(block)
                if len(data) > 65536:
                    raise ValueError("feature-report exceeds 64 KiB")
                if not block:
                    break
        if process.wait(timeout=max(0.1, deadline-time.monotonic())) != 0:
            raise ValueError("feature-report failed")
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()
    value = strict_json(bytes(data))
    if not isinstance(value, dict) or not isinstance(value.get("core"), str):
        raise ValueError("invalid Core feature-report")
    return value


def verify_named_service(name: str, *, registry: ServiceRegistry | None = None) -> dict:
    """Read real feature reports, DeploymentLock, supervisor state and owned sockets."""
    catalog = registry.catalog if registry else CoreCatalog()
    registry = registry or ServiceRegistry(catalog=catalog)
    item, current, material = registry.compliance_snapshot(name)
    context = validate_context(item["protocolContext"])
    binding = registry.require_binding(name)
    descriptor = catalog.inspect(binding["core"])
    findings: list[str] = []

    report = _feature_report(descriptor["executable"])
    if report["core"] not in {binding["core"], "shadow6-" + binding["core"]}:
        findings.append("feature-report-core-mismatch")
    try:
        native = strict_json(private_read(binding["config"]["config_path"]))
    except (OSError, ValueError):
        native = {}
        findings.append("native-config-unavailable")
    native_role = native.get("role") if isinstance(native, dict) else None
    if native_role not in {"broker", "agent", "client"}:
        findings.append("native-role-unavailable")
    elif context["role"] not in {"all", native_role}:
        findings.append("s6p1-role-mismatch")

    boundaries = report.get("application_boundaries", [])
    if not isinstance(boundaries, list):
        findings.append("feature-report-boundaries-invalid")
        boundaries = []
    requested = {r["boundary"] for r in context["routes"] if isinstance(r, dict) and r.get("boundary")}
    claimed = {b.get("kind") for b in boundaries if isinstance(b, dict)}
    if requested - claimed:
        findings.append("s6abi-boundary-unclaimed")

    components = {c: item.get("spec", {}).get(c + "_config") is not None
                  for c in ("gate", "guard")}
    components["s6epe"] = item.get("privacy") == "envelope"
    try:
        admit_realization(context, native_role=native_role,
                          components=[c for c, enabled in components.items() if enabled])
    except ValueError:
        findings.append("s6p1-component-or-credential-mismatch")
    for component, present in components.items():
        expected = context["components"].get(component)
        if expected is True and not present:
            findings.append("required-component-missing:" + component)
        if expected is False and present:
            findings.append("forbidden-component-present:" + component)

    lock = item.get("deploymentLock")
    lock_valid = False
    if isinstance(lock, dict) and material is not None:
        lock_valid = (lock.get("contextDigest") == material["contextDigest"]
                      and lock.get("digest") == digest(encoded(material)))
    if not lock_valid:
        findings.append("deployment-lock-missing-or-drifted")

    runtime = current.get("runtime", {})
    observation = current.get("runtimeObservation")
    if current.get("state") != "running" or not isinstance(observation, dict):
        findings.append("runtime-observation-unavailable")
    else:
        try:
            validate_observation(observation)
            if time.time() - observation["observedAt"] > 5:
                findings.append("runtime-observation-stale")
            if runtime.get("lockDigest") != (lock or {}).get("digest"):
                findings.append("runtime-lock-mismatch")
            expected_processes = 1 + sum(components.values())
            if len(observation["processes"]) != expected_processes:
                findings.append("component-process-count-mismatch")
            if item.get("privacy") == "envelope" and any(
                    not private_socket(endpoint) for endpoint in observation["nativeEndpoints"]):
                findings.append("private-listener-exposed")
            listen_values: list[str] = []
            def collect_listeners(value):
                if isinstance(value, dict):
                    for key, child in value.items():
                        if key in {"listen_addr", "listen_address"} and isinstance(child, str):
                            listen_values.append(child)
                        else:
                            collect_listeners(child)
                elif isinstance(value, list):
                    for child in value:
                        collect_listeners(child)
            collect_listeners(native)
            if listen_values:
                observed_native = observation["nativeEndpoints"]
                for address in listen_values:
                    parsed = urlsplit(address if "://" in address else "tcp://" + address)
                    if not parsed.hostname or parsed.port is None or not any(
                            socket.get("host") == parsed.hostname and socket.get("port") == parsed.port
                            for socket in observed_native):
                        findings.append("configured-listener-not-observed")
        except (ValueError, KeyError, TypeError):
            findings.append("runtime-observation-invalid")

    return {"schema": "shadow6.service-compliance.v1", "service": name,
            "compliant": not findings, "findings": sorted(set(findings)),
            "evidence": {"intent": "S6P1", "capability": "feature-report",
                         "realization": "DeploymentLock" if lock_valid else "invalid",
                         "runtimeClaim": runtime.get("readiness", "unavailable"),
                         "observed": "OS-process-and-socket" if observation else "unavailable",
                         "core": binding["core"], "role": native_role,
                         "applicationBoundaries": sorted(claimed),
                         "ownedEndpoints": observation.get("endpoints", []) if observation else []}}
