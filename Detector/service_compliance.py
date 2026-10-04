"""Compare one Named Service's S6P1 intent with claims and Linux observations."""
from __future__ import annotations

import json
import time
from urllib.parse import urlsplit

from Deployment.core_catalog import CoreCatalog
from Deployment.profile_registry import (LimitResolution, LimitResolver,
                                         validate_profile_binding, validate_profile_realization)
from Deployment.service_registry import ServiceRegistry, digest, encoded
from Deployment.service_storage import private_read, strict_json
from Deployment.runtime_observation import validate_observation, private_socket
from Deployment.protocol_context import validate_context, admit_realization


from Deployment.service_runtime import feature_report as _feature_report

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
    try:
        selected_profile = validate_profile_binding(item.get('profileBinding'), core=binding['core'])
        validate_profile_realization(item['profileBinding'], native, context)
    except ValueError:
        selected_profile = None
        findings.append('profile-binding-missing-or-drifted')
    native_role = native.get("role") if isinstance(native, dict) else None
    if native_role not in {"broker", "agent", "client"}:
        findings.append("native-role-unavailable")
    elif context["role"] not in {"all", native_role}:
        findings.append("s6p1-role-mismatch")

    boundaries = report.get("application_boundaries", [])
    if not isinstance(boundaries, list):
        findings.append("feature-report-boundaries-invalid")
        boundaries = []
    if selected_profile is not None and selected_profile['applicationBoundary'] not in boundaries:
        findings.append('profile-feature-boundary-mismatch')
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
        lock_valid = (lock.get("profileBinding") == item.get("profileBinding")
                      and lock.get("contextDigest") == material["contextDigest"]
                      and lock.get("digest") == digest(encoded(material)))
    if not lock_valid:
        findings.append("deployment-lock-missing-or-drifted")
    resolution = None
    if lock_valid and selected_profile is not None:
        try:
            resolution = LimitResolver().validate(
                lock.get('limitResolution'), selected_profile,
                item.get('spec', {}).get('limits'), check_host=True)
        except (ValueError, KeyError, TypeError) as error:
            findings.append('limits-host-budget-drift' if str(error).startswith('HostBudgetDrift')
                            else 'limits-resolution-drift')
    component_resolution = None
    if lock_valid and resolution is not None:
        try:
            inputs = {}
            if item.get('spec', {}).get('gate_config'):
                inputs['gate'] = strict_json(private_read(item['spec']['gate_config']))
            if item.get('privacy') == 'envelope':
                from Deployment.service_runtime import parse_envelope
                inputs['envelope'] = parse_envelope(private_read(item['spec']['envelope_config']))
            component_resolution = lock.get('componentLimits')
            if component_resolution is None:
                if inputs:
                    raise ValueError('component lock missing')
            else:
                from Deployment.profile_registry import HostBudget
                LimitResolver().validate_components(component_resolution, inputs,
                    host=HostBudget.from_dict(resolution['host_budget']),
                    process_fds=resolution['effective_limits']['process_fds'])
        except (OSError, ValueError, KeyError, TypeError):
            findings.append('component-limits-resolution-drift')

    runtime = current.get("runtime", {})
    observation = current.get("runtimeObservation")
    if current.get("state") != "running" or not isinstance(observation, dict):
        findings.append("runtime-observation-unavailable")
    else:
        try:
            validate_observation(observation)
            if (resolution is None or
                    observation.get('limitResolutionDigest') != LimitResolution(resolution).digest or
                    observation.get('effectiveLimits') != resolution['effective_limits']):
                findings.append('runtime-limits-drift')
            if time.time() - observation["observedAt"] > 5:
                findings.append("runtime-observation-stale")
            if runtime.get('profileBinding') != item.get('profileBinding'):
                findings.append('runtime-profile-mismatch')
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
                         "core": binding["core"], "profileBinding": item.get("profileBinding"), "role": native_role,
                         "applicationBoundaries": sorted(claimed),
                         "effectiveLimits": resolution['effective_limits'] if resolution else None,
                         "componentLimits": component_resolution,
                         "limitResolutionDigest": LimitResolution(resolution).digest if resolution else None,
                         "limitsEnforcement": observation.get('limitsEnforcement') if observation else None,
                         "ownedEndpoints": observation.get("endpoints", []) if observation else []}}
