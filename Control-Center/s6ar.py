"""S6AR1 unified API Receiver/Router envelope."""
from __future__ import annotations
import base64, json, re, uuid

try:
    from Deployment.service_storage import strict_json as portable_json
except ImportError:
    import sys
    from pathlib import Path
    for _json_path in (Path(__file__).resolve().parents[1] / 'Deployment',
                       Path(__file__).resolve().parents[1] / 'deployment'):
        if (_json_path / 'service_storage.py').is_file():
            sys.path.insert(0, str(_json_path)); break
    from service_storage import strict_json as portable_json

PREFIX = "S6AR1."
MAX_SIZE = 262144

def pack(message: dict) -> str:
    if type(message) is not dict or set(message) != {"schema", "version", "kind", "receiver", "router", "payload"}:
        raise ValueError("invalid S6AR1 message")
    if message["schema"] != "shadow6.api-receiver-router.v1" or type(message["version"]) is not int or message["version"] != 1:
        raise ValueError("invalid S6AR1 schema")
    if message["kind"] not in ("request", "response", "event"):
        raise ValueError("invalid S6AR1 kind")
    if not isinstance(message["receiver"], dict) or not isinstance(message["router"], dict) or not isinstance(message["payload"], dict):
        raise ValueError("invalid S6AR1 sections")
    receiver = message["receiver"]
    router = message["router"]
    payload = message["payload"]
    if set(receiver) - {"component", "instance"} or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", str(receiver.get("component", ""))): raise ValueError("invalid S6AR1 receiver")
    if "instance" in receiver and not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", str(receiver["instance"])): raise ValueError("invalid S6AR1 receiver instance")
    if set(router) - {"route", "hops", "timeout_ms"} or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", str(router.get("route", ""))): raise ValueError("invalid S6AR1 route")
    if "hops" in router and (not isinstance(router["hops"], list) or len(router["hops"]) > 16 or not all(isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", item) for item in router["hops"])): raise ValueError("invalid S6AR1 route hops")
    if "timeout_ms" in router and (type(router["timeout_ms"]) is not int or not 1 <= router["timeout_ms"] <= 300000): raise ValueError("invalid S6AR1 route timeout")
    if message["kind"] == "request":
        if set(payload) - {"action", "correlation_id", "params", "context"} or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", str(payload.get("action", ""))): raise ValueError("invalid S6AR1 action")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", str(payload.get("correlation_id", ""))): raise ValueError("missing S6AR1 correlation_id")
        if "params" in payload and not isinstance(payload["params"], dict): raise ValueError("invalid S6AR1 params")
        if "context" in payload and (not isinstance(payload["context"], str) or not payload["context"].startswith("S6P1.")): raise ValueError("invalid S6P1 context")
    elif message["kind"] == "response":
        if set(payload) - {"correlation_id", "result", "error"} or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", str(payload.get("correlation_id", ""))): raise ValueError("missing S6AR1 correlation_id")
        if ("result" in payload) == ("error" in payload): raise ValueError("response must contain exactly one result or error")
        if "error" in payload and (not isinstance(payload["error"], dict) or set(payload["error"]) - {"code", "message", "details"} or not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", str(payload["error"].get("code", ""))) or not isinstance(payload["error"].get("message"), str) or len(payload["error"]["message"]) > 512): raise ValueError("invalid S6AR1 error")
    else:
        if set(payload) - {"event", "correlation_id", "data"} or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", str(payload.get("event", ""))): raise ValueError("invalid S6AR1 event")
        if "correlation_id" in payload and not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", str(payload["correlation_id"])): raise ValueError("invalid S6AR1 event correlation")
    raw = json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    portable_json(raw, limit=MAX_SIZE)
    token = PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")
    if len(token) > MAX_SIZE: raise ValueError("S6AR1 message is oversized")
    return token

def unpack(token: str) -> dict:
    if type(token) is not str or not token.startswith(PREFIX) or len(token) > MAX_SIZE:
        raise ValueError("invalid S6AR1 message")
    if not re.fullmatch(r"[A-Za-z0-9_-]+",token[len(PREFIX):]):raise ValueError("invalid S6AR1 alphabet")
    try: value = portable_json(base64.b64decode(token[len(PREFIX):] + "=" * (-len(token[len(PREFIX):]) % 4), altchars=b"-_", validate=True), limit=MAX_SIZE)
    except Exception as exc: raise ValueError("invalid S6AR1 encoding") from exc
    pack(value)
    return value

def to_rpc(message: dict) -> dict:
    """Map an S6AR1 request to the legacy Control Center method shape."""
    if message["kind"] != "request": raise ValueError("S6AR1 message is not a request")
    component = message["receiver"]["component"]
    action = message["payload"].get("action")
    if not isinstance(action, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", action): raise ValueError("invalid S6AR1 action")
    params = message["payload"].get("params", {})
    if not isinstance(params, dict): raise ValueError("invalid S6AR1 params")
    return {"id": message["payload"]["correlation_id"], "method": f"{component}.{action}", "params": params}

def response_for(message: dict, result: dict | None = None, *, error: dict | None = None) -> str:
    if (result is None) == (error is None): raise ValueError("provide exactly one S6AR1 result or error")
    payload = {"correlation_id": message["payload"]["correlation_id"]}
    payload["result" if error is None else "error"] = result if error is None else error
    return pack({"schema":"shadow6.api-receiver-router.v1", "version":1, "kind":"response", "receiver":message["receiver"], "router":message["router"], "payload":payload})

def error_for(message: dict, code: str, text: str, details: dict | None = None) -> str:
    error = {"code": code, "message": text}
    if details is not None: error["details"] = details
    return response_for(message, error=error)

def request(component: str, route: str, action: str, *, correlation_id: str | None = None,
            params: dict | None = None, context: str | None = None) -> str:
    payload = {"action": action, "correlation_id": correlation_id or uuid.uuid4().hex, "params": params or {}}
    if context is not None: payload["context"] = context
    return pack({"schema":"shadow6.api-receiver-router.v1", "version":1, "kind":"request", "receiver":{"component":component}, "router":{"route":route}, "payload":payload})
