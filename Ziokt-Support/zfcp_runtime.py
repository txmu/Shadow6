"""ZFCP/1 local read-only profile. Vendored in S and embedded in C.

No Ziokt installation is needed by either native provider. This profile has no
remote transport, grants, mutations or persistent replay protection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import unicodedata

PROTOCOL = "zfcp/1"
MAX_REQUEST = 65_536
MAX_RESPONSE = 262_144
MAX_CONFIG = 262_144
MAX_OBJECTS = 4096
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
METHODS = ("capabilities.get", "status.get", "objects.list", "operation.prepare",
           "operation.commit", "operation.abort", "operation.status", "operation.reconcile", "events.list")


class ProtocolError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def fail(code, message):
    raise ProtocolError(code, message)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def windows_owner_controlled(handle, private):
    """Validate actual NT owner/DACL; chmod bits are not an ACL on Windows."""
    import ctypes
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetSecurityInfo.restype = wintypes.DWORD
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    token, allowed = wintypes.HANDLE(), []
    try:
        if advapi.GetSecurityInfo(handle, 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor)):
            fail("UNSAFE_FILE", "Windows file security cannot be inspected")
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            fail("UNSAFE_FILE", "Windows owner token unavailable")
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not 1 <= size.value <= 16384:
            fail("UNSAFE_FILE", "invalid Windows owner token")
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            fail("UNSAFE_FILE", "Windows owner token unavailable")
        current = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        for name in ("S-1-5-18", "S-1-5-32-544"):
            sid = ctypes.c_void_p()
            if not advapi.ConvertStringSidToSidW(name, ctypes.byref(sid)):
                fail("UNSAFE_FILE", "Windows trusted SID unavailable")
            allowed.append(sid)
        if not owner or not any(advapi.EqualSid(owner, sid) for sid in (current, allowed[1])):
            fail("UNSAFE_FILE", "Windows file owner must be current user or local administrators")
        if private:
            if not dacl:
                fail("UNSAFE_FILE", "private Windows file requires a restrictive DACL")
            header = ctypes.string_at(dacl, 8)
            count = int.from_bytes(header[4:6], "little")
            if count > 128:
                fail("UNSAFE_FILE", "Windows ACL exceeds budget")
            for index in range(count):
                ace = ctypes.c_void_p()
                if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                    fail("UNSAFE_FILE", "Windows ACL cannot be read")
                raw = ctypes.string_at(ace, 8)
                if raw[1] & 8:  # INHERIT_ONLY_ACE does not grant this object access.
                    continue
                if raw[0] == 1:  # ACCESS_DENIED_ACE
                    continue
                if raw[0] != 0 or int.from_bytes(raw[2:4], "little") < 12:
                    fail("UNSAFE_FILE", "unsupported Windows permission entry")
                sid = ctypes.c_void_p(ace.value + 8)
                if not any(advapi.EqualSid(sid, trusted) for trusted in (current, *allowed)):
                    fail("UNSAFE_FILE", "private Windows file grants access to another identity")
    finally:
        if token:
            kernel.CloseHandle(token)
        if descriptor:
            kernel.LocalFree(descriptor)
        for sid in allowed:
            kernel.LocalFree(sid)


def strict_json(raw, limit=MAX_REQUEST, string_limit=8192):
    if not isinstance(raw, bytes) or len(raw) > limit:
        fail("INVALID_JSON", "JSON size limit")
    try:
        text = raw.decode("utf-8", "strict")
        depth, quoted, escaped = 0, False, False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > 16:
                    raise ValueError("nesting")
            elif char in "]}":
                depth -= 1

        def pairs(items):
            result = {}
            for key, child in items:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = child
            return result

        def reject(_):
            raise ValueError("noninteger number")

        value = json.loads(text, object_pairs_hook=pairs,
                           parse_float=reject, parse_constant=reject)

        def bounded(item, level=0):
            if level > 16:
                raise ValueError("nesting")
            if type(item) is int and not -(2**53 - 1) <= item <= 2**53 - 1:
                raise ValueError("integer range")
            if isinstance(item, str):
                if (len(item.encode("utf-8")) > string_limit or "\0" in item or
                        unicodedata.normalize("NFC", item) != item):
                    raise ValueError("string")
            if isinstance(item, dict):
                for key, child in item.items():
                    bounded(key, level + 1)
                    bounded(child, level + 1)
            elif isinstance(item, list):
                for child in item:
                    bounded(child, level + 1)
        bounded(value)
        return value
    except (ValueError, UnicodeError, RecursionError):
        fail("INVALID_JSON", "strict bounded UTF-8 JSON required")


def secure_read(path, limit=MAX_CONFIG, private=True):
    """Stable regular-file reads, never symlinks, FIFOs or unsafe modes."""
    path = Path(path)
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)

        def identity(s):
            return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink,
                    s.st_size, s.st_mtime_ns, s.st_ctime_ns)

        if os.name == "nt":
            import msvcrt
            windows_owner_controlled(msvcrt.get_osfhandle(fd), private is True)
        if (not stat.S_ISREG(opened.st_mode) or (os.name != "nt" and opened.st_uid != os.geteuid())
                or opened.st_nlink != 1 or opened.st_size > limit
                or (os.name != "nt" and private and stat.S_IMODE(opened.st_mode) != 0o600)
                or (os.name != "nt" and private is False and opened.st_mode & 0o022)
                or identity(before) != identity(opened)
                or identity(path.lstat()) != identity(opened)):
            fail("UNSAFE_FILE", "stable owner-controlled regular file required")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if (len(data) != opened.st_size or len(data) > limit
                or identity(opened) != identity(os.fstat(fd))
                or identity(opened) != identity(path.lstat())):
            fail("UNSAFE_FILE", "file changed during read")
        return bytes(data)
    finally:
        os.close(fd)


def validate_config(value):
    allowed = {"schema", "enabled", "federation_id", "provider_id", "allow_mutations",
               "allowed_operations", "allowed_resources"}
    if (not isinstance(value, dict) or set(value) - allowed or
            value.get("schema") != "ziokt.provider.v1" or
            type(value.get("enabled", False)) is not bool or
            type(value.get("allow_mutations", False)) is not bool):
        fail("INVALID_CONFIG", "invalid provider configuration")
    result = {"schema": "ziokt.provider.v1", "enabled": False,
              "federation_id": None, "provider_id": None,
              "allow_mutations": False, "allowed_operations": [], "allowed_resources": [], **value}
    for name in ("federation_id", "provider_id"):
        field = result[name]
        if field is not None and (not isinstance(field, str) or not ID.fullmatch(field)):
            fail("INVALID_CONFIG", "invalid provider scope")
        if result["enabled"] and field is None:
            fail("INVALID_CONFIG", "enabled provider requires explicit scope")
    for field in ("allowed_operations", "allowed_resources"):
        values = result[field]
        if (not isinstance(values, list) or len(values) > 64 or
                any(not isinstance(v, str) or not 1 <= len(v) <= 160 for v in values) or len(set(values)) != len(values)):
            fail("INVALID_CONFIG", "bounded explicit native action/resource allowlists required")
    if any(v not in {"service.stop", "artifact.stage"} for v in result["allowed_operations"]):
        fail("INVALID_CONFIG", "unknown native action")
    if result["allow_mutations"] and (not result["enabled"] or not result["allowed_operations"] or not result["allowed_resources"]):
        fail("INVALID_CONFIG", "mutations require enabled support and explicit action/resource allowlists")
    return result


def load_config(provider, path):
    if path is None:
        return validate_config({"schema": "ziokt.provider.v1"})
    try:
        raw = secure_read(path)
    except FileNotFoundError:
        # An explicitly selected missing configuration is an error.
        fail("INVALID_CONFIG", "selected provider configuration is missing")
    if provider == "shadow6":
        return validate_config(strict_json(raw, MAX_CONFIG))
    try:
        text = raw.decode("utf-8", "strict")
        fields, inside, seen = {}, False, False
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("["):
                if not line.endswith("]"):
                    if inside:
                        raise ValueError("section")
                    continue
                inside = line[1:-1].strip() == "ziokt"
                if inside:
                    if seen:
                        raise ValueError("duplicate section")
                    seen = True
                continue
            if inside:
                key, sep, value = line.partition("=")
                key, value = key.strip(), value.strip()
                if not sep or key in fields or key not in {
                        "enabled", "federation_id", "provider_id", "allow_mutations", "allowed_operations", "allowed_resources"}:
                    raise ValueError("field")
                if key in {"enabled", "allow_mutations"}:
                    if value not in {"TRUE", "FALSE"}:
                        raise ValueError("boolean")
                    value = value == "TRUE"
                elif key in {"allowed_operations", "allowed_resources"}:
                    value = [part.strip() for part in value.split(",") if part.strip()]
                fields[key] = value
        return validate_config({"schema": "ziokt.provider.v1", **fields})
    except (ValueError, UnicodeError):
        fail("INVALID_CONFIG", "strict [ziokt] configuration required")


def identifier(value, label):
    if not isinstance(value, str) or not ID.fullmatch(value):
        fail("INVALID_REQUEST", "invalid " + label)


def validate_request(value, config):
    fields = {"protocol", "request_id", "federation_id", "provider_id",
              "method", "params", "deadline_ms", "nonce"}
    if not isinstance(value, dict) or set(value) != fields or value["protocol"] != PROTOCOL:
        fail("INVALID_REQUEST", "exact ZFCP/1 request required")
    for field in ("request_id", "federation_id", "provider_id"):
        identifier(value[field], field)
    if not isinstance(value["nonce"], str) or not re.fullmatch(r"[0-9a-f]{32}", value["nonce"]):
        fail("INVALID_REQUEST", "invalid nonce")
    now = time.time_ns() // 1_000_000
    if type(value["deadline_ms"]) is not int or not now < value["deadline_ms"] <= now + 30_000:
        fail("DEADLINE_EXCEEDED", "deadline must be within 30 seconds")
    if (not isinstance(value["method"], str) or not isinstance(value["params"], dict)):
        fail("INVALID_REQUEST", "typed method and params required")
    if not config["enabled"]:
        fail("ZIOKT_DISABLED", "native Ziokt support is disabled")
    if any(value[k] != config[k] for k in ("federation_id", "provider_id")):
        fail("SCOPE_MISMATCH", "provider scope does not match")
    if value["method"] not in METHODS:
        fail("METHOD_UNSUPPORTED", "operation not available in read-only profile")
    params = value["params"]
    method = value["method"]
    if method.startswith("operation."):
        expected = ({"operation_id", "action", "resource", "arguments", "expected_revision"}
                    if method == "operation.prepare" else
                    {"operation_id", "plan_digest"} if method in {"operation.commit", "operation.abort"} else {"operation_id"})
        if set(params) != expected:
            fail("INVALID_PARAMS", "exact native operation parameters required")
        identifier(params.get("operation_id"), "operation_id")
        if method == "operation.prepare" and (not isinstance(params["action"], str) or not isinstance(params["resource"], str) or not isinstance(params["arguments"], dict)):
            fail("INVALID_PARAMS", "typed native operation required")
    elif method == "events.list":
        if (set(params) - {"after_seq", "limit"} or type(params.get("after_seq", 0)) is not int or params.get("after_seq", 0) < 0 or
                type(params.get("limit", 50)) is not int or not 1 <= params.get("limit", 50) <= 100):
            fail("INVALID_PARAMS", "bounded event cursor required")
    elif method != "objects.list":
        if params:
            fail("INVALID_PARAMS", "empty params required")
    else:
        if set(params) - {"kind", "limit", "cursor"}:
            fail("INVALID_PARAMS", "unknown object query field")
        if (type(params.get("limit", 50)) is not int or
                not 1 <= params.get("limit", 50) <= 100):
            fail("INVALID_PARAMS", "page size must be 1..100")
        if (not isinstance(params.get("kind", "all"), str) or
                params.get("kind", "all") not in {"all", "service", "package", "environment"}):
            fail("INVALID_PARAMS", "unsupported object kind")
        if "cursor" in params and (not isinstance(params["cursor"], str) or
                not re.fullmatch(r"[0-9a-f]{64}:[0-9]{1,5}", params["cursor"])):
            fail("INVALID_PARAMS", "invalid snapshot cursor")
    return value


def safe_directory(path):
    """Read inventory only through non-symlink owner-controlled directories."""
    path = Path(path).absolute()
    for candidate in reversed((path, *path.parents)):
        info = candidate.lstat()
        if not stat.S_ISDIR(info.st_mode):
            fail("UNSAFE_FILE", "inventory directory must not be a symlink")
        if candidate == path and os.name != "nt" and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
            fail("UNSAFE_FILE", "inventory directory must be owner-controlled")
    return path


def object_record(config, kind, native_id, state, properties):
    strict_json(encoded(properties), MAX_RESPONSE)
    if not isinstance(native_id, str) or len(native_id.encode()) > 512:
        fail("INVALID_NATIVE_STATE", "invalid native object identity")
    key = hashlib.sha256((kind + "\0" + native_id).encode()).hexdigest()
    record = {"object_id": "ziokt://{}/{}/{}/{}".format(
        config["federation_id"], config["provider_id"], kind, key),
        "owner_provider": config["provider_id"], "kind": kind,
        "native_id": native_id, "state": state,
        "observation": "stored-metadata", "properties": properties}
    record["revision"] = "sha256:" + digest(record)
    return record


def native_objects(provider, root, network, config):
    records = []
    if provider == "shadow6":
        # Reuse the native validator, but do not call @transaction list/status:
        # those methods create lock files and can migrate stored state.
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(root / "Deployment"))
        from service_registry import ServiceRegistry
        from core_catalog import CoreCatalog
        registry = ServiceRegistry(catalog=CoreCatalog(root))
        for name, item in registry.services.items():
            binding, profile = item.get("coreBinding") or {}, item.get("profileBinding") or {}
            lock = item.get("deploymentLock") or {}
            record = object_record(config, "service", name, item["state"], {
                "core": binding.get("core"), "core_version": binding.get("version"),
                "profile": profile.get("profile"), "lock_digest": lock.get("digest")})
            from service_registry import digest as native_digest, encoded as native_encode
            record["revision"] = native_digest(native_encode(item))
            records.append(record)
    else:
        suffix = "networks/" + network
        directories = (("package", root / "var/lib/corix" / suffix / "installed"),
                       ("environment", root / "usr/corix/strata" / suffix))
        for kind, path in directories:
            try:
                safe_directory(path)
            except FileNotFoundError:
                continue
            with os.scandir(path) as entries:
                count = 0
                for entry in entries:
                    count += 1
                    if count > MAX_OBJECTS:
                        fail("INVENTORY_LIMIT", "native inventory exceeds snapshot budget")
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    directory = safe_directory(entry.path)
                    if kind == "package":
                        try:
                            fields = {key: secure_read(directory / key, 512, False).decode("utf-8").strip()
                                      for key in ("name", "slot", "version")}
                        except FileNotFoundError:
                            continue
                        if not all(fields.values()):
                            fail("INVALID_NATIVE_STATE", "incomplete package identity")
                        native_id = fields["name"] + ":" + fields["slot"]
                        state = "registered"
                    else:
                        native_id, fields, state = entry.name, {"network_id": network}, "present"
                    records.append(object_record(config, kind, native_id, state, fields))
    if len(records) > MAX_OBJECTS:
        fail("INVENTORY_LIMIT", "native inventory exceeds snapshot budget")
    records.sort(key=lambda item: item["object_id"])
    if len({item["object_id"] for item in records}) != len(records):
        fail("INVALID_NATIVE_STATE", "duplicate native object identity")
    return records


def page(records, params):
    records = [r for r in records if params.get("kind", "all") in {"all", r["kind"]}]
    snapshot = digest(records)
    offset = 0
    if "cursor" in params:
        previous, raw_offset = params["cursor"].split(":")
        offset = int(raw_offset)
        if previous != snapshot:
            fail("STALE_CURSOR", "inventory changed; restart pagination")
        if offset > len(records):
            fail("INVALID_PARAMS", "cursor beyond snapshot")
    limit = params.get("limit", 50)
    end = offset + limit
    return {"objects": records[offset:end], "snapshot_digest": "sha256:" + snapshot,
            "next_cursor": snapshot + ":" + str(end) if end < len(records) else None,
            "total": len(records)}


def capabilities(provider, config):
    return {"schema": "ziokt.capabilities.v1", "native_project": provider,
            "enabled": config["enabled"], "provider_id": config["provider_id"],
            "federation_id": config["federation_id"], "protocol": PROTOCOL,
            "profile": "local-v1", "mutations": config["allow_mutations"],
            "capabilities": [{"id": "ziokt." + method + ".v1", "operation": method,
                              "status": "available" if config["enabled"] and (method not in {"operation.prepare", "operation.commit", "operation.abort", "operation.reconcile"} or config["allow_mutations"]) else "disabled"}
                             for method in METHODS]}


def status(provider, config, network):
    return {"schema": "ziokt.provider-status.v1", "native_project": provider,
            "enabled": config["enabled"], "provider_id": config["provider_id"],
            "federation_id": config["federation_id"], "network_id": network,
            "mutations": config["allow_mutations"], "listeners": 0,
            "recovery": "not-run-by-readonly-provider"}


def rpc(provider, root, network, config, stream):
    request_id = None
    try:
        raw = stream.readline(MAX_REQUEST + 2)
        if not raw.endswith(b"\n") or len(raw) > MAX_REQUEST + 1:
            fail("INVALID_REQUEST", "bounded newline-terminated request required")
        if stream.read(1):
            fail("INVALID_REQUEST", "one request per process required")
        value = strict_json(raw[:-1])
        if isinstance(value, dict) and isinstance(value.get("request_id"), str) and ID.fullmatch(value["request_id"]):
            request_id = value["request_id"]
        request = validate_request(value, config)
        method = request["method"]
        if method == "capabilities.get":
            result = capabilities(provider, config)
        elif method == "status.get":
            result = status(provider, config, network)
        elif method.startswith("operation.") or method == "events.list":
            result = operation_dispatch(provider, root, network, config, method, request["params"])
        else:
            result = page(native_objects(provider, root, network, config), request["params"])
        if time.time_ns() // 1_000_000 >= request["deadline_ms"]:
            fail("DEADLINE_EXCEEDED", "request deadline exceeded")
        response = {"protocol": PROTOCOL, "request_id": request_id, "ok": True, "result": result}
        if len(encoded(response)) > MAX_RESPONSE:
            fail("RESPONSE_LIMIT", "response exceeds page budget")
    except ProtocolError as exc:
        response = {"protocol": PROTOCOL, "request_id": request_id, "ok": False,
                    "error": {"code": exc.code, "message": str(exc)}}
    except (OSError, ValueError, ImportError, UnicodeError):
        response = {"protocol": PROTOCOL, "request_id": request_id, "ok": False,
                    "error": {"code": "NATIVE_STATE_UNAVAILABLE", "message": "native inventory cannot be read safely"}}
    sys.stdout.buffer.write(encoded(response) + b"\n")
    return 0 if response["ok"] else 2


def main(provider, root=None, argv=None, rpc_stream=None):
    parser = argparse.ArgumentParser(prog=provider + " ziokt")
    parser.add_argument("--config", type=Path, help="private native provider configuration")
    if provider == "corium":
        parser.add_argument("--network", default=os.environ.get("CORIUM_NETWORK_ID_OVERRIDE", "default"))
    parser.add_argument("action", choices=("capabilities", "status", "rpc"))
    parser.add_argument("--stdio", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.stdio != (args.action == "rpc"):
            fail("INVALID_REQUEST", "rpc requires --stdio; other actions do not accept it")
        network = args.network if provider == "corium" else None
        if network is not None:
            identifier(network, "network")
        root = Path(root or os.environ.get("CORIUM_ROOT", "/")).absolute()
        path = args.config
        if provider == "corium" and path is not None:
            expected = root / "etc/corix/networks" / network / "corix.conf"
            if path.absolute() != expected:
                fail("INVALID_CONFIG", "Corium config must match its native root/network")
        if provider == "corium" and path is None:
            path = root / "etc/corix/networks" / network / "corix.conf"
            # Absent native config means disabled, without creating any state.
            if not path.exists() and not path.is_symlink():
                path = None
        elif provider == "shadow6" and path is None:
            path = Path.home() / ".config/shadow6/ziokt.json"
            if not path.exists() and not path.is_symlink():
                path = None
        config = load_config(provider, path)
        if args.action == "rpc":
            return rpc(provider, root, network, config, rpc_stream or sys.stdin.buffer)
        value = capabilities(provider, config) if args.action == "capabilities" else status(provider, config, network)
        sys.stdout.buffer.write(encoded(value) + b"\n")
        return 0
    except (ProtocolError, OSError, ValueError) as exc:
        response = {"protocol": PROTOCOL, "request_id": None, "ok": False,
                    "error": {"code": getattr(exc, "code", "INVALID_CONFIG"),
                              "message": str(exc) if isinstance(exc, ProtocolError) else "configuration cannot be read safely"}}
        sys.stdout.buffer.write(encoded(response) + b"\n")
        return 2

"""Local native operation journal. Exact actions, durable intents, no shell.

This is not distributed ACID. A crash after native mutation leaves unknown;
status reconciles supported postconditions before any retry.
"""
import base64
import sqlite3

OPERATIONS = {"shadow6": {"service.stop"}, "corium": {"artifact.stage"}}


def operation_directory(provider, root, network):
    if provider == "shadow6":
        return Path.home() / ".config/shadow6/ziokt-state"
    return root / "var/lib/corix/networks" / network / "ziokt"


def private_mkdir(path):
    path = Path(path)
    if not path.exists():
        path.mkdir(mode=0o700, parents=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        fail("UNSAFE_FILE", "private native operation directory required")
    return path


def operation_db(provider, root, network, create=False, write=False):
    directory = operation_directory(provider, root, network)
    path = directory / "operations.sqlite"
    if not create and not path.exists():
        fail("OPERATION_NOT_FOUND", "operation journal does not exist")
    if create:
        private_mkdir(directory)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
    secure_read(path, 64 * 1024 * 1024)
    db = sqlite3.connect(path if create or write else path.as_uri() + "?mode=ro", uri=not (create or write), timeout=5)
    if create or write:
        db.execute("PRAGMA synchronous=FULL")
    if create:
        db.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, plan TEXT NOT NULL, state TEXT NOT NULL, result TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS outbox (seq INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, state TEXT NOT NULL, evidence TEXT NOT NULL, UNIQUE(operation_id,state))")
        db.commit()
    return db


def operation_view(row):
    plan = strict_json(row[2].encode())
    return {"operation_id": row[0], "plan_digest": "sha256:" + digest(plan),
            "action": plan["action"], "resource": plan["resource"],
            "state": row[3], "expires_at_ms": plan["expires_at_ms"],
            "result": strict_json(row[4].encode()) if row[4] else None}


def native_registry(root):
    sys.path.insert(0, str(root / "Deployment"))
    from service_registry import ServiceRegistry
    from core_catalog import CoreCatalog
    return ServiceRegistry(catalog=CoreCatalog(root))


def operation_preflight(provider, root, network, params, config):
    action, resource, args = params["action"], params["resource"], params["arguments"]
    if action not in OPERATIONS[provider] or action not in config["allowed_operations"]:
        fail("POLICY_DENIED", "native action is not allowed")
    if resource not in config["allowed_resources"] and "*" not in config["allowed_resources"]:
        fail("POLICY_DENIED", "native resource is not allowed")
    if action == "service.stop":
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}/[A-Za-z0-9][A-Za-z0-9._-]{0,63}", resource) or args:
            fail("INVALID_PARAMS", "fixed named-service stop required")
        registry = native_registry(root)
        if resource not in registry.services:
            fail("NATIVE_STATE_UNAVAILABLE", "named service does not exist")
        from service_registry import digest as native_digest, encoded as native_encode
        revision = native_digest(native_encode(registry.services[resource]))
        if revision != params["expected_revision"]:
            fail("STALE_PLAN", "native service revision changed")
        item = registry.services[resource]
        return {"core_binding": digest(item.get("coreBinding")), "profile_binding": digest(item.get("profileBinding")),
                "context": digest(item.get("protocolContext")), "lock": (item.get("deploymentLock") or {}).get("digest")}
    else:
        if set(args) != {"data_base64"} or not re.fullmatch(r"sha256:[a-f0-9]{64}", resource):
            fail("INVALID_PARAMS", "content-addressed native artifact required")
        try:
            data = base64.b64decode(args["data_base64"], validate=True)
        except (ValueError, TypeError):
            fail("INVALID_PARAMS", "bounded base64 content required")
        if len(data) > 6144 or "sha256:" + hashlib.sha256(data).hexdigest() != resource:
            fail("ARTIFACT_DIGEST_MISMATCH", "content digest or control budget mismatch")
        if params["expected_revision"] is not None:
            fail("INVALID_PARAMS", "artifact staging requires null expected_revision")
        dht = root / "var/lib/corix/p2p/dht.db"
        if not dht.is_file() or dht.is_symlink():
            fail("NATIVE_STATE_UNAVAILABLE", "native Corium content database not initialized")
        with sqlite3.connect(dht.as_uri() + "?mode=ro", uri=True) as db:
            db.execute("SELECT hash,file_path,offset,size FROM local_chunks LIMIT 1").fetchall()
        return {"artifact_digest": resource}


def operation_execute(provider, root, network, plan):
    resource = plan["resource"]
    if plan["action"] == "service.stop":
        registry = native_registry(root)
        registry.ziokt_stop(resource, expected_revision=plan["expected_revision"])
        return {"native_id": resource, "postcondition": "stopped"}
    content = base64.b64decode(plan["arguments"]["data_base64"], validate=True)
    directory = root / "var/lib/corix/p2p/objects/ziokt"
    private_mkdir(directory)
    target = directory / resource.removeprefix("sha256:")
    existed = target.exists()
    if existed:
        if hashlib.sha256(secure_read(target, 6144, private=None)).hexdigest() != resource[7:]:
            fail("ARTIFACT_DIGEST_MISMATCH", "existing native object was changed")
    else:
        temporary = directory / (".stage-" + plan["operation_id"])
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content); stream.flush(); os.fsync(stream.fileno())
            # Never replace a concurrently published native object.
            os.link(temporary, target)
        except FileExistsError:
            if hashlib.sha256(secure_read(target, 6144, private=None)).hexdigest() != resource[7:]:
                fail("ARTIFACT_DIGEST_MISMATCH", "concurrent native object conflict")
        finally:
            temporary.unlink(missing_ok=True)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    dht = root / "var/lib/corix/p2p/dht.db"
    with sqlite3.connect(dht) as db:
        previous = db.execute("SELECT file_path,offset,size FROM local_chunks WHERE hash=?", (resource[7:],)).fetchone()
        if previous and tuple(previous) != (str(target), 0, len(content)):
            # Do not steal another native provider's existing same-content record.
            path = Path(previous[0])
            if previous[1] != 0 or previous[2] != len(content) or hashlib.sha256(secure_read(path, 6144, private=None)).hexdigest() != resource[7:]:
                fail("NATIVE_STATE_CONFLICT", "native content registration conflicts")
        else:
            db.execute("INSERT OR REPLACE INTO local_chunks VALUES (?,?,0,?)", (resource[7:], str(target), len(content)))
    return {"digest": resource, "native_registered": True, "created": not existed,
            "compensation": "manual-content-retention-review"}


def operation_reconcile(provider, root, network, plan):
    if plan["action"] == "service.stop":
        registry = native_registry(root)
        item = registry.services.get(plan["resource"])
        if item and item["state"] == "stopped":
            evidence = {"core_binding": digest(item.get("coreBinding")), "profile_binding": digest(item.get("profileBinding")),
                        "context": digest(item.get("protocolContext")), "lock": (item.get("deploymentLock") or {}).get("digest")}
            if evidence != plan["binding_evidence"]:
                fail("STALE_PLAN", "native binding changed during interrupted operation")
            return {"native_id": plan["resource"], "postcondition": "stopped", "reconciled": True}
        return None
    target = root / "var/lib/corix/p2p/objects/ziokt" / plan["resource"][7:]
    if target.is_file() and not target.is_symlink() and hashlib.sha256(secure_read(target, 6144, private=None)).hexdigest() == plan["resource"][7:]:
        # Resume the fixed content registration only; hashing prevents a changed
        # payload from being mistaken for the interrupted operation.
        return {**operation_execute(provider, root, network, plan), "reconciled": True}
    return None


def operation_dispatch(provider, root, network, config, method, params):
    if method in {"operation.prepare", "operation.commit", "operation.abort", "operation.reconcile"} and not config["allow_mutations"]:
        fail("MUTATION_DISABLED", "native mutations are disabled")
    if method == "events.list":
        try:
            db = operation_db(provider, root, network)
        except ProtocolError as exc:
            if exc.code == "OPERATION_NOT_FOUND":
                return {"events": [], "next_seq": params.get("after_seq", 0)}
            raise
        try:
            rows = db.execute("SELECT seq,operation_id,state,evidence FROM outbox WHERE seq>? ORDER BY seq LIMIT ?",
                              (params.get("after_seq", 0), params.get("limit", 50))).fetchall()
            return {"events": [{"seq": r[0], "operation_id": r[1], "state": r[2], "evidence": strict_json(r[3].encode())} for r in rows],
                    "next_seq": rows[-1][0] if rows else params.get("after_seq", 0)}
        finally:
            db.close()
    identifier(params.get("operation_id"), "operation_id")
    db = operation_db(provider, root, network, create=method == "operation.prepare", write=method in {"operation.commit", "operation.abort", "operation.reconcile"})
    try:
        if method != "operation.status":
            db.execute("BEGIN IMMEDIATE")
        if method == "operation.prepare":
            if set(params) != {"operation_id", "action", "resource", "arguments", "expected_revision"}:
                fail("INVALID_PARAMS", "exact native operation plan required")
            if not isinstance(params["action"], str) or not isinstance(params["resource"], str) or not isinstance(params["arguments"], dict):
                fail("INVALID_PARAMS", "typed native action required")
            if params["expected_revision"] is not None and not re.fullmatch(r"sha256:[a-f0-9]{64}", str(params["expected_revision"])):
                fail("INVALID_PARAMS", "native revision digest required")
            request_digest = digest(params)
            row = db.execute("SELECT * FROM operations WHERE id=?", (params["operation_id"],)).fetchone()
            if row:
                if row[1] != request_digest:
                    fail("IDEMPOTENCY_CONFLICT", "operation ID cannot change its request")
                return operation_view(row)
            evidence = operation_preflight(provider, root, network, params, config)
            if db.execute("SELECT COUNT(*) FROM operations").fetchone()[0] >= 4096:
                fail("JOURNAL_LIMIT", "native operation journal requires explicit archival")
            plan = {**params, "federation_id": config["federation_id"], "provider_id": config["provider_id"],
                    "expires_at_ms": time.time_ns() // 1_000_000 + 30_000, "binding_evidence": evidence}
            with db:
                db.execute("INSERT INTO operations VALUES (?,?,?,'prepared',NULL)", (params["operation_id"], request_digest, encoded(plan).decode()))
            return operation_view(db.execute("SELECT * FROM operations WHERE id=?", (params["operation_id"],)).fetchone())
        row = db.execute("SELECT * FROM operations WHERE id=?", (params["operation_id"],)).fetchone()
        if row is None:
            fail("OPERATION_NOT_FOUND", "native operation not found")
        plan = strict_json(row[2].encode())
        if plan["federation_id"] != config["federation_id"] or plan["provider_id"] != config["provider_id"]:
            fail("SCOPE_MISMATCH", "operation belongs to another provider scope")
        if method in {"operation.status", "operation.reconcile"}:
            if row[3] == "unknown" and method == "operation.reconcile":
                if (plan["action"] not in config["allowed_operations"] or
                        (plan["resource"] not in config["allowed_resources"] and "*" not in config["allowed_resources"])):
                    fail("POLICY_DENIED", "current native policy no longer allows reconciliation")
                if time.time_ns() // 1_000_000 < plan["expires_at_ms"]:
                    fail("OPERATION_IN_PROGRESS", "wait for execution lease before reconciliation")
                if provider == "corium":
                    operation_preflight(provider, root, network, plan, config)
                result = operation_reconcile(provider, root, network, plan)
                if result:
                    with db:
                        db.execute("UPDATE operations SET state='committed',result=? WHERE id=? AND state='unknown'", (encoded(result).decode(), row[0]))
                        db.execute("INSERT OR IGNORE INTO outbox(operation_id,state,evidence) VALUES (?,'committed',?)", (row[0], encoded(result).decode()))
            return operation_view(db.execute("SELECT * FROM operations WHERE id=?", (row[0],)).fetchone())
        if params.get("plan_digest") != "sha256:" + digest(plan):
            fail("STALE_PLAN", "native plan digest mismatch")
        if method == "operation.abort":
            if row[3] != "prepared":
                fail("OPERATION_CONFLICT", "only a prepared operation can be aborted")
            with db:
                db.execute("UPDATE operations SET state='aborted' WHERE id=?", (row[0],))
            return operation_view(db.execute("SELECT * FROM operations WHERE id=?", (row[0],)).fetchone())
        if row[3] == "committed":
            return operation_view(row)
        if row[3] != "prepared":
            fail("RESULT_UNKNOWN", "query native status before deciding whether to retry")
        if time.time_ns() // 1_000_000 >= plan["expires_at_ms"]:
            fail("STALE_PLAN", "native prepare lease expired")
        operation_preflight(provider, root, network, plan, config)
        with db:
            changed = db.execute("UPDATE operations SET state='unknown' WHERE id=? AND state='prepared'", (row[0],)).rowcount
            if changed != 1:
                fail("OPERATION_CONFLICT", "operation already claimed")
        result = operation_execute(provider, root, network, plan)
        with db:
            db.execute("UPDATE operations SET state='committed',result=? WHERE id=?", (encoded(result).decode(), row[0]))
            db.execute("INSERT OR IGNORE INTO outbox(operation_id,state,evidence) VALUES (?,'committed',?)", (row[0], encoded(result).decode()))
        return operation_view(db.execute("SELECT * FROM operations WHERE id=?", (row[0],)).fetchone())
    except sqlite3.Error:
        fail("JOURNAL_UNAVAILABLE", "native operation journal is busy or invalid")
    finally:
        db.close()
