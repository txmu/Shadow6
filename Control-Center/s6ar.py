"""S6AR1 unified API Receiver/Router envelope."""
from __future__ import annotations
import base64, json, re, uuid

PREFIX = "S6AR1."
MAX_SIZE = 262144

def pack(message: dict) -> str:
    if type(message) is not dict or set(message) != {"schema", "version", "kind", "receiver", "router", "payload"}:
        raise ValueError("invalid S6AR1 message")
    if message["schema"] != "shadow6.api-receiver-router.v1" or message["version"] != 1:
        raise ValueError("invalid S6AR1 schema")
    if message["kind"] not in ("request", "response", "event"):
        raise ValueError("invalid S6AR1 kind")
    if not isinstance(message["receiver"], dict) or not isinstance(message["router"], dict) or not isinstance(message["payload"], dict):
        raise ValueError("invalid S6AR1 sections")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", str(message["receiver"].get("component", ""))): raise ValueError("invalid S6AR1 receiver")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", str(message["router"].get("route", ""))): raise ValueError("invalid S6AR1 route")
    if message["kind"] in ("request", "response") and not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", str(message["payload"].get("correlation_id", ""))): raise ValueError("missing S6AR1 correlation_id")
    raw = json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    token = PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")
    if len(token) > MAX_SIZE: raise ValueError("S6AR1 message is oversized")
    return token

def unpack(token: str) -> dict:
    if type(token) is not str or not token.startswith(PREFIX) or len(token) > MAX_SIZE:
        raise ValueError("invalid S6AR1 message")
    try: value = json.loads(base64.urlsafe_b64decode(token[len(PREFIX):] + "==="))
    except Exception as exc: raise ValueError("invalid S6AR1 encoding") from exc
    pack(value)
    return value

def request(component: str, route: str, action: str, *, correlation_id: str | None = None, params: dict | None = None) -> str:
    return pack({"schema":"shadow6.api-receiver-router.v1", "version":1, "kind":"request", "receiver":{"component":component}, "router":{"route":route}, "payload":{"action":action, "correlation_id":correlation_id or uuid.uuid4().hex, "params":params or {}}})
