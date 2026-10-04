"""Typed requests for an external, platform-owned service operator.

The contract deliberately carries an operation enum and lock-bound paths, not
an argv or shell fragment. A native supervisor adapter may translate these
requests to its fixed platform API and return an observation receipt.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import time

SCHEMA = "shadow6.system-operation.v1"
RECEIPT_SCHEMA = "shadow6.system-operation-receipt.v1"
OPERATIONS = frozenset({"install-definition", "activate", "deactivate",
                        "restart", "status", "remove-definition", "logs"})
MAX_TTL = 300


def operation_request(*, backend, operation, service, plan_path, lock_digest,
                      definition_digest=None, now=None, ttl=60):
    if not isinstance(backend, str) or backend not in {
            "systemd", "openrc", "runit", "sysv", "rc.d", "procd", "launchd", "guix"}:
        raise ValueError("invalid system operation backend")
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise ValueError("unsupported system operation")
    if not isinstance(service, str) or not service or len(service.encode()) > 255:
        raise ValueError("invalid Named Service identity")
    if not isinstance(plan_path, str) or not plan_path.startswith("/") or "\x00" in plan_path or len(plan_path.encode()) > 4096:
        raise ValueError("invalid lock-bound launch plan path")
    if (not isinstance(lock_digest, str) or
            re.fullmatch(r"sha256:[0-9a-f]{64}", lock_digest) is None):
        raise ValueError("invalid DeploymentLock digest")
    if definition_digest is not None and (not isinstance(definition_digest, str) or
            re.fullmatch(r"sha256:[0-9a-f]{64}", definition_digest) is None):
        raise ValueError("invalid service definition digest")
    if type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
        raise ValueError("invalid system operation request lifetime")
    issued = int(time.time()) if now is None else now
    if type(issued) is not int or issued < 0:
        raise ValueError("invalid system operation issue time")
    label = "shadow6-" + hashlib.sha256(service.encode("utf-8")).hexdigest()[:24]
    request = {"schema": SCHEMA, "requestId": secrets.token_hex(16),
        "backend": backend, "operation": operation, "serviceLabel": label,
        "lockDigest": lock_digest, "launchPlan": plan_path,
        "issuedAt": issued, "expiresAt": issued + ttl}
    if definition_digest is not None:
        request["definitionDigest"] = definition_digest
    return request


def validate_request(value, *, now=None):
    required = {"schema", "requestId", "backend", "operation", "serviceLabel",
                "lockDigest", "launchPlan", "issuedAt", "expiresAt"}
    optional = {"definitionDigest"}
    if (not isinstance(value, dict) or set(value) - required - optional or
            not required <= set(value) or value["schema"] != SCHEMA):
        raise ValueError("invalid system operation request schema")
    if not isinstance(value["requestId"], str) or re.fullmatch(r"[0-9a-f]{32}", value["requestId"]) is None:
        raise ValueError("invalid system operation request id")
    if not isinstance(value["backend"], str) or value["backend"] not in {
            "systemd", "openrc", "runit", "sysv", "rc.d", "procd", "launchd", "guix"}:
        raise ValueError("invalid system operation backend")
    if not isinstance(value["operation"], str) or value["operation"] not in OPERATIONS:
        raise ValueError("unsupported system operation")
    if not isinstance(value["serviceLabel"], str) or re.fullmatch(r"shadow6-[0-9a-f]{24}", value["serviceLabel"]) is None:
        raise ValueError("invalid system operation service label")
    if (not isinstance(value["launchPlan"], str) or not value["launchPlan"].startswith("/")
            or "\x00" in value["launchPlan"] or len(value["launchPlan"].encode()) > 4096):
        raise ValueError("invalid lock-bound launch plan path")
    if (not isinstance(value["lockDigest"], str) or
            re.fullmatch(r"sha256:[0-9a-f]{64}", value["lockDigest"]) is None):
        raise ValueError("invalid DeploymentLock digest")
    if "definitionDigest" in value and (not isinstance(value["definitionDigest"], str) or re.fullmatch(
            r"sha256:[0-9a-f]{64}", value["definitionDigest"]) is None):
        raise ValueError("invalid service definition digest")
    if (type(value["issuedAt"]) is not int or type(value["expiresAt"]) is not int or
            not 0 < value["expiresAt"] - value["issuedAt"] <= MAX_TTL):
        raise ValueError("invalid system operation lifetime")
    current = int(time.time()) if now is None else now
    if type(current) is not int or current > value["expiresAt"] or current < value["issuedAt"] - 5:
        raise ValueError("system operation request expired or not yet valid")
    return dict(value)


def validate_receipt(value, request, *, now=None):
    request = validate_request(request, now=now)
    fields = {"schema", "requestId", "operation", "lockDigest", "result",
              "observedAt", "readiness"}
    if not isinstance(value, dict) or set(value) != fields or value.get("schema") != RECEIPT_SCHEMA:
        raise ValueError("invalid system operation receipt schema")
    if (value["requestId"] != request["requestId"] or
            value["operation"] != request["operation"] or
            value["lockDigest"] != request["lockDigest"]):
        raise ValueError("system operation receipt binding mismatch")
    if not isinstance(value["result"], str) or value["result"] not in {"accepted", "completed", "rejected", "unavailable"}:
        raise ValueError("invalid system operation result")
    if type(value["observedAt"]) is not int or value["observedAt"] < request["issuedAt"]:
        raise ValueError("invalid system operation observation time")
    if not isinstance(value["readiness"], str) or value["readiness"] not in {"unknown", "pending", "ready", "unavailable"}:
        raise ValueError("invalid system operation readiness")
    if value["operation"] in {"activate", "restart"} and value["result"] == "completed" and value["readiness"] == "ready":
        raise ValueError("external process readiness requires a separately verified observation")
    return dict(value)


class SystemOperationsProvider:
    """Optional host-owned interface. Implementations must map enum actions to fixed APIs."""
    def capabilities(self, backend):
        raise NotImplementedError

    def submit(self, request):
        raise NotImplementedError

    def observe(self, request_id):
        raise NotImplementedError
