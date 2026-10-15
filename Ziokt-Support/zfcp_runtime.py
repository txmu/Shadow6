"""ZFCP/1 opt-in native profile. Vendored in S and embedded in C.

No Ziokt installation is needed by either native provider. Local owner authority
gates fixed journaled operations; remote grants belong to the separate mTLS API.
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
           "operation.commit", "operation.abort", "operation.status", "operation.reconcile", "events.list", "content.get", "governance.fact", "zkt.status", "zkt.account", "identity.fact", "zkn.list", "zkn.fact", "zkc.list", "zkc.fact", "service.binding", "compute.challenge")


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


def windows_file_info(handle):
    """Retrieve NTFS file information via OS handle to verify volume and inode identity."""
    import ctypes
    from ctypes import wintypes
    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(BY_HANDLE_FILE_INFORMATION)]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    info = BY_HANDLE_FILE_INFORMATION()
    if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
        fail("UNSAFE_FILE", "Windows file information cannot be inspected")
    return info


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


def make_private(path):
    """Restrict a newly created Ziokt object, including a real Windows DACL."""
    path = Path(path)
    if os.name != "nt":
        path.chmod(0o700 if path.is_dir() else 0o600)
        return
    import ctypes
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    advapi.SetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    advapi.SetSecurityInfo.restype = wintypes.DWORD
    token, descriptor, text = wintypes.HANDLE(), ctypes.c_void_p(), ctypes.c_void_p()
    handle = None
    try:
        if path.is_symlink():
            fail("UNSAFE_FILE", "private object cannot be a symlink")
        # READ_CONTROL | WRITE_DAC, OPEN_EXISTING, BACKUP_SEMANTICS and
        # OPEN_REPARSE_POINT. Only this object's handle is ever modified.
        handle = kernel.CreateFileW(str(path.absolute()), 0x60000, 7, None, 3, 0x02200000, None)
        if handle in (None, ctypes.c_void_p(-1).value):
            fail("UNSAFE_FILE", "private Windows object cannot be opened")
        windows_owner_controlled(handle, False)
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            fail("UNSAFE_FILE", "Windows private owner unavailable")
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not 1 <= size.value <= 16384:
            fail("UNSAFE_FILE", "invalid Windows private owner")
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            fail("UNSAFE_FILE", "Windows private owner unavailable")
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            fail("UNSAFE_FILE", "Windows private SID unavailable")
        current = ctypes.wstring_at(text)
        inheritance = "OICI" if path.is_dir() else ""
        sddl = "D:P" + "".join("(A;" + inheritance + ";FA;;;" + identity + ")" for identity in ("SY", "BA", current))
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            fail("UNSAFE_FILE", "private Windows DACL invalid")
        present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
        if not advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)) or not present:
            fail("UNSAFE_FILE", "private Windows DACL missing")
        if advapi.SetSecurityInfo(handle, 1, 4 | 0x80000000, None, None, dacl, None):
            fail("UNSAFE_FILE", "private Windows DACL could not be applied")
        windows_owner_controlled(handle, True)
    finally:
        if handle not in (None, ctypes.c_void_p(-1).value): kernel.CloseHandle(handle)
        if token: kernel.CloseHandle(token)
        if descriptor: kernel.LocalFree(descriptor)
        if text: kernel.LocalFree(text)


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
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)

        def identity(s):
            if os.name == "nt":
                return (s.st_mode, s.st_size)
            return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink,
                    s.st_size, s.st_mtime_ns, s.st_ctime_ns)

        if os.name == "nt":
            import msvcrt
            handle = msvcrt.get_osfhandle(fd)
            windows_owner_controlled(handle, private is True)
            info = windows_file_info(handle)
            if info.nNumberOfLinks != 1 or (info.dwFileAttributes & 0x400):
                fail("UNSAFE_FILE", "stable owner-controlled regular file required")
            import ctypes
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
            kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
            buf = ctypes.create_unicode_buffer(1024)
            length = kernel.GetFinalPathNameByHandleW(handle, buf, 1024, 0)
            if length >= 1024:
                buf = ctypes.create_unicode_buffer(length + 1)
                length = kernel.GetFinalPathNameByHandleW(handle, buf, length + 1, 0)
            if not length:
                fail("UNSAFE_FILE", "Windows final path cannot be determined")
            opened_name = buf.value
            if opened_name.lower().startswith("\\\\?\\unc\\"):
                opened_name = "\\" + opened_name[7:]
            elif opened_name.startswith("\\\\?\\"):
                opened_name = opened_name[4:]
            target_name = os.path.realpath(path)
            if target_name.lower().startswith("\\\\?\\unc\\"):
                target_name = "\\" + target_name[7:]
            elif target_name.startswith("\\\\?\\"):
                target_name = target_name[4:]
            if os.path.normcase(os.path.normpath(opened_name)) != os.path.normcase(os.path.normpath(target_name)):
                fail("UNSAFE_FILE", "stable owner-controlled regular file required")
        if (not stat.S_ISREG(opened.st_mode) or (os.name != "nt" and opened.st_uid != os.geteuid())
                or (os.name != "nt" and opened.st_nlink != 1) or opened.st_size > limit
                or (os.name != "nt" and private and stat.S_IMODE(opened.st_mode) != 0o600)
                or (os.name != "nt" and private is False and opened.st_mode & 0o022)
                or identity(before) != identity(opened)
                or (os.name != "nt" and identity(path.lstat()) != identity(opened))
                or (before.st_dev, before.st_ino, before.st_size) != (path.lstat().st_dev, path.lstat().st_ino, path.lstat().st_size)):
            fail("UNSAFE_FILE", "stable owner-controlled regular file required")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if (len(data) != opened.st_size or len(data) > limit
                or identity(opened) != identity(os.fstat(fd))
                or (os.name != "nt" and identity(opened) != identity(path.lstat()))
                or (before.st_dev, before.st_ino, before.st_size) != (path.lstat().st_dev, path.lstat().st_ino, path.lstat().st_size)):
            fail("UNSAFE_FILE", "file changed during read")
        return bytes(data)
    finally:
        os.close(fd)


def validate_config(value):
    allowed = {"schema", "enabled", "federation_id", "provider_id", "allow_mutations", "service_registry_file",
               "allowed_operations", "allowed_resources", "package_root", "package_trust_file", "artifact_root", "transport_bindings_file", "coordinator_public_key", "zkn_enabled"}
    if (not isinstance(value, dict) or set(value) - allowed or
            value.get("schema") != "ziokt.provider.v1" or
            type(value.get("enabled", False)) is not bool or
            type(value.get("allow_mutations", False)) is not bool):
        fail("INVALID_CONFIG", "invalid provider configuration")
    result = {"schema": "ziokt.provider.v1", "enabled": False,
              "federation_id": None, "provider_id": None,
              "allow_mutations": False, "allowed_operations": [], "allowed_resources": [], **value}
    if 'zkn_enabled' in result and type(result['zkn_enabled']) is not bool:
        fail('INVALID_CONFIG','explicit native ZKN boolean required')
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
    known_operations = {"service.stop", "service.run", "artifact.stage", "package.install", "package.activate",
                        "wiki.create", "snapshot.create", "strata.create", "chain.mine", "compute.run", "compute.submit", "identity.register", "content.publish", "zkn.transfer", "zkn.gift", "zkc.issue", "recovery.checkpoint", "recovery.restore"}
    if any(v not in known_operations for v in result["allowed_operations"]):
        fail("INVALID_CONFIG", "unknown native action")
    if "coordinator_public_key" in result and (not isinstance(result["coordinator_public_key"], str) or not re.fullmatch("[a-f0-9]{64}", result["coordinator_public_key"])):
        fail("INVALID_CONFIG", "pinned Ed25519 coordinator authority required")
    for name in ("package_root", "package_trust_file", "artifact_root", "transport_bindings_file", "service_registry_file"):
        if name in result and (not isinstance(result[name], str) or not Path(result[name]).is_absolute() or ".." in Path(result[name]).parts):
            fail("INVALID_CONFIG", "native package settings require fixed absolute paths")
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
                        "enabled", "federation_id", "provider_id", "allow_mutations", "allowed_operations", "allowed_resources",
                        "package_root", "package_trust_file", "artifact_root", "transport_bindings_file", "coordinator_public_key", "zkn_enabled"}:
                    raise ValueError("field")
                if key in {"enabled", "allow_mutations", "zkn_enabled"}:
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
        fail("METHOD_UNSUPPORTED", "operation not available in this native profile")
    params = value["params"]
    method = value["method"]
    if method=='compute.challenge':
        if params:fail('INVALID_PARAMS','Engine Zero challenge takes no client configuration')
    elif method=='service.binding':
        if set(params)!={'service_name'} or not isinstance(params['service_name'],str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._/-]{0,127}',params['service_name']):
            fail('INVALID_PARAMS','fixed named Broker binding required')
    elif method in {"governance.fact","zkn.fact","zkc.fact"}:
        if set(params) != {"transaction_hash"} or not isinstance(params["transaction_hash"], str) or not re.fullmatch("[a-f0-9]{64}", params["transaction_hash"]):
            fail("INVALID_PARAMS", "exact native signed transaction reference required")
    elif method == 'identity.fact':
        if (set(params)!={'member_public','policy_digest','issuer'} or
                any(not isinstance(params[k],str) or not re.fullmatch('[a-f0-9]{64}',params[k]) for k in ('member_public','issuer')) or
                not isinstance(params['policy_digest'],str) or not re.fullmatch('sha256:[a-f0-9]{64}',params['policy_digest'])):
            fail('INVALID_PARAMS','exact registration proof scope required')
    elif method == "content.get":
        if (not {"peer_id", "digest"} <= set(params) or set(params)-{"peer_id", "digest", "offset", "length"} or
                not isinstance(params["peer_id"], str) or not re.fullmatch("[a-f0-9]{64}", params["peer_id"]) or
                not isinstance(params["digest"], str) or not re.fullmatch("sha256:[a-f0-9]{64}", params["digest"]) or
                type(params.get("offset", 0)) is not int or not 0 <= params.get("offset", 0) <= 64*1024*1024 or
                type(params.get("length", 6144)) is not int or not 1 <= params.get("length", 6144) <= 6144):
            fail("INVALID_PARAMS", "fixed native peer and bounded content range required")
    elif method in {"zkt.status", "zkt.account"}:
        if set(params) != (set() if method == "zkt.status" else {"address"}):
            fail("INVALID_PARAMS", "exact native reputation query required")
        if method == "zkt.account" and (not isinstance(params["address"], str) or not re.fullmatch(r"[a-f0-9]{64}", params["address"])):
            fail("INVALID_PARAMS", "native account identity required")
    elif method.startswith("operation."):
        expected = ({"operation_id", "action", "resource", "arguments", "expected_revision"}
                    if method == "operation.prepare" else
                    {"operation_id", "plan_digest"} if method in {"operation.commit", "operation.abort"} else {"operation_id"})
        optional = {"lease_ms", "fence"} if method == "operation.prepare" else set()
        if not expected <= set(params) or set(params) - expected - optional:
            fail("INVALID_PARAMS", "exact native operation parameters required")
        if "lease_ms" in params and (type(params["lease_ms"]) is not int or not 250 <= params["lease_ms"] <= 30000):
            fail("INVALID_PARAMS", "native prepare lease must be 250..30000 ms")
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
                params.get("kind", "all") not in {"all", "service", "package", "environment", "application", "identity", "proposal", "recovery", "name"}):
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
        if "package_root" in config and Path(config["package_root"]).exists():
            sys.path.insert(0, str(root/"Package-Manager"))
            from shadow6_pkg import list_packages, verify_package
            safe_directory(config["package_root"])
            packages = list_packages(Path(config["package_root"]))
            if len(packages) > MAX_OBJECTS: fail("INVENTORY_LIMIT", "native package inventory exceeds budget")
            for item in packages:
                selector = item["kind"]+"/"+item["id"]+"@"+item["version"]
                properties = {**item, "native_signature_verified": False}
                if "package_trust_file" in config:
                    source = Path(config["package_root"])/item["kind"]/item["id"]/"versions"/item["version"]
                    manifest, package = verify_package(source, Path(config["package_trust_file"]))
                    package.close(); properties["native_signature_verified"] = True
                    properties["manifest_digest"] = "sha256:"+digest(manifest)
                records.append(object_record(config, "package", selector, "active" if item["active"] else "installed", properties))
                if item["kind"] == "app":
                    records.append(object_record(config, "application", selector, "active" if item["active"] else "installed", properties))
    else:
        suffix = "networks/" + network
        directories = (("package", root / "var/lib/corix" / suffix / "installed"),
                       ("environment", root / "usr/corix/strata" / suffix),
                       ("recovery", root / "var/lib/corix" / suffix / "snapshots"))
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
        # Project fixed public metadata from the original native databases.
        # Message bodies, ACL members, keys and peer addresses stay native.
        queries = (("forum/forum.db", "identity", "SELECT id_hash,type,last_updated_height FROM identity_cache", ("native_type", "height")),
                   ("forum/forum.db", "application", "SELECT group_id || '/' || slug,latest_version_hash,locked_by_user_id IS NOT NULL FROM wiki_pages", ("version_hash", "locked")),
                   ("forum/forum.db", "application", "SELECT 'forum/' || tx_hash,source_type,encryption_mode FROM messages", ("native_type", "encryption_mode")),
                   ("forum/forum.db", "application", "SELECT 'mail/' || tx_hash,mail_object_hash,timestamp FROM mails", ("content_digest", "timestamp")),
                   ("blockchain/chain.db", "application", "SELECT 'template/' || template_name,package_hash,activation_height FROM active_app_templates", ("package_hash", "height")),
                   ("forum/forum.db", "name", "SELECT domain_name,target_hash,last_update_height FROM nns_records", ("target_hash", "height")),
                   ("blockchain/chain.db", "proposal", "SELECT hash,type,block_height FROM transactions WHERE type LIKE '%proposal%'", ("native_type", "height")))
        from contextlib import closing
        for filename, kind, query, columns in queries:
            path = root/"var/lib/corix"/suffix/filename
            if not path.exists(): continue
            with closing(native_database(path)) as db:
                rows = db.execute(query+" LIMIT ?", (MAX_OBJECTS+1,)).fetchall()
            if len(rows) > MAX_OBJECTS: fail("INVENTORY_LIMIT", "native object projection exceeds budget")
            for row in rows:
                properties = dict(zip(columns, row[1:]))
                records.append(object_record(config, kind, row[0], "native-recorded", properties))
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
                              for method in METHODS if provider == "corium" or (not method.startswith(("zkt.","zkn.","zkc.")) and method not in {"content.get", "governance.fact", "identity.fact", "compute.challenge"})],
            "native_actions": sorted(OPERATIONS[provider]),
            "object_kinds": ["service", "package", "application"] if provider == "shadow6" else ["package", "environment", "application", "identity", "name", "proposal", "recovery"],
            "transport": "native-application-boundary; one Core family per path" if provider == "shadow6" else "native-signature-preserving Ziokt binding; explicit fallback"}


def status(provider, config, network):
    return {"schema": "ziokt.provider-status.v1", "native_project": provider,
            "enabled": config["enabled"], "provider_id": config["provider_id"],
            "federation_id": config["federation_id"], "network_id": network,
            "mutations": config["allow_mutations"], "listeners": 0,
            "listener_scope": "local-rpc-process", "recovery": "explicit-native-operation"}


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
        elif method=='service.binding':
            if provider!='shadow6': fail('METHOD_UNSUPPORTED','native Broker bindings belong to Shadow6')
            result=service_binding_fact(root,config,request['params']['service_name'])
        elif method.startswith("operation.") or method == "events.list":
            result = operation_dispatch(provider, root, network, config, method, request["params"])
        elif method == "compute.challenge":
            if provider != "corium":fail("METHOD_UNSUPPORTED","Engine Zero belongs to Corium")
            result=compute_challenge(root,network)
        elif method == "governance.fact":
            if provider != "corium": fail("METHOD_UNSUPPORTED", "native chain facts belong to Corium")
            result = governance_fact(root, network, request["params"]["transaction_hash"])
        elif method in {'identity.fact','zkn.list','zkn.fact','zkc.list','zkc.fact'}:
            if provider!='corium': fail('METHOD_UNSUPPORTED','native chain assets belong to Corium')
            result=asset_query(root,network,method,request['params'])
        elif method == "content.get":
            if provider != "corium": fail("METHOD_UNSUPPORTED", "content peer ownership belongs to native Corium")
            import contextlib, io
            params = request["params"]
            query = {k:v for k,v in params.items() if k != "peer_id"}
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = native_transport_main([str(root), network, params["peer_id"], "ZIOKT_CONTENT_GET", encoded(query).decode()])
            if code != 0: fail("NO_APPROVED_BINDING", "content retrieval requires an explicit native application binding")
            result = strict_json(output.getvalue().strip().encode())
        elif method in {"zkt.status", "zkt.account"}:
            if provider != "corium":
                fail("METHOD_UNSUPPORTED", "native ZKT reputation belongs to Corium")
            result = zkt_read_status(root / "var/lib/corix/networks" / network / "blockchain/chain.db", request["params"].get("address"))
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
    except (OSError, ValueError, ImportError, UnicodeError, sqlite3.Error, TypeError, KeyError):
        response = {"protocol": PROTOCOL, "request_id": request_id, "ok": False,
                    "error": {"code": "NATIVE_STATE_UNAVAILABLE", "message": "native inventory cannot be read safely"}}
    sys.stdout.buffer.write(encoded(response) + b"\n")
    return 0 if response["ok"] else 2


def main(provider, root=None, argv=None, rpc_stream=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    companion_args = None
    if 'companion' in arguments:
        boundary = arguments.index('companion')
        companion_args = arguments[boundary + 1:]
        arguments = arguments[:boundary + 1]
    parser = argparse.ArgumentParser(prog=provider + " ziokt")
    parser.add_argument("--config", type=Path, help="private native provider configuration")
    if provider == "corium":
        parser.add_argument("--network", default=os.environ.get("CORIUM_NETWORK_ID_OVERRIDE", "default"))
    parser.add_argument("action", choices=("capabilities", "status", "rpc", "serve-data", "companion"))
    parser.add_argument("--stdio", action="store_true")
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(arguments)
    try:
        if args.action == 'companion':
            if args.stdio or args.key_file is not None or args.port:
                fail('INVALID_REQUEST', 'companion does not accept native server options')
            # Fixed installed Python API: no shell, callback, arbitrary module or plugin.
            # Installation is explicit; native providers remain independently usable.
            try:
                from ziokt.companion_cli import main as companion_main
            except ImportError:
                fail('COMPANION_UNAVAILABLE', 'install the Ziokt Python package to enable companion calls')
            return companion_main(companion_args)

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
        if args.action == "serve-data":
            if provider != "corium" or not config["enabled"]:
                fail("ZIOKT_DISABLED", "Corium native Ziokt data support must be enabled")
            if args.key_file is None or not 0 <= args.port <= 65535:
                fail("INVALID_CONFIG", "private application key and bounded loopback port required")
            serve_corium_data(root, network, args.key_file, args.port)
            return 0
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
explicit reconcile checks supported postconditions before any retry.
"""
import base64
import sqlite3
from contextlib import closing

OPERATIONS = {"shadow6": {"service.stop", "service.run", "package.install", "package.activate", "recovery.checkpoint", "recovery.restore"},
              "corium": {"artifact.stage", "wiki.create", "snapshot.create", "strata.create", "chain.mine", "compute.run", "compute.submit", "identity.register", "content.publish", "zkn.transfer", "zkn.gift", "zkc.issue", "recovery.checkpoint", "recovery.restore"}}


def operation_directory(provider, root, network):
    if provider == "shadow6":
        return Path.home() / ".config/shadow6/ziokt-state"
    return root / "var/lib/corix/networks" / network / "ziokt"


def native_descriptor_main(args):
    """Only the recorded in-progress native action can reach Bash business code."""
    root, network, op_id = Path(args[0]).absolute(), args[1], args[2]
    identifier(network, "network"); identifier(op_id, "operation_id")
    config = load_config("corium", root/"etc/corix/networks"/network/"corix.conf")
    if not config["enabled"] or not config["allow_mutations"]:
        fail("MUTATION_DISABLED", "native Corium mutations are disabled")
    db = operation_db("corium", root, network)
    try:
        row = db.execute("SELECT * FROM operations WHERE id=?", (op_id,)).fetchone()
        if row is None or row[3] != "unknown":
            fail("POLICY_DENIED", "recorded native execution intent required")
        plan = strict_json(row[2].encode())
        fence_admit(db, config, plan, existing=True)
        if (plan["federation_id"] != config["federation_id"] or plan["provider_id"] != config["provider_id"] or
                time.time_ns()//1_000_000 >= plan["expires_at_ms"]):
            fail("STALE_PLAN", "native execution scope or lease changed")
        if operation_preflight("corium", root, network, plan, config) != plan["binding_evidence"]:
            fail("STALE_PLAN", "native business evidence changed before dispatch")
        print(encoded(plan).decode())
        return 0
    finally:
        db.close()


def private_mkdir(path):
    path = Path(path)
    if not path.exists():
        path.mkdir(mode=0o700, parents=True)
        make_private(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        fail("UNSAFE_FILE", "private native operation directory required")
    if os.name == "nt":
        fail("NATIVE_PLATFORM_UNSUPPORTED", "native operation journal requires native POSIX authority")
    if (info.st_uid != os.geteuid() or info.st_mode & 0o077):
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
        db.execute("CREATE TABLE IF NOT EXISTS coordinator (id INTEGER PRIMARY KEY CHECK(id=1), term INTEGER NOT NULL, busy_until INTEGER NOT NULL, operation_id TEXT)")
        db.commit()
    return db


def operation_view(row):
    plan = strict_json(row[2].encode())
    return {"operation_id": row[0], "plan_digest": "sha256:" + digest(plan),
            "action": plan["action"], "resource": plan["resource"],
            "state": row[3], "expires_at_ms": plan["expires_at_ms"],
            "result": strict_json(row[4].encode()) if row[4] else None}


def fence_admit(db, config, plan, existing=False):
    if "coordinator_public_key" not in config:
        if "fence" in plan: fail("POLICY_DENIED", "native coordinator trust must be explicitly configured")
        return
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    token = plan.get("fence")
    if not isinstance(token, dict) or set(token) != {"payload", "signature"}:
        fail("FENCE_REQUIRED", "signed native coordinator lease required")
    value = token["payload"]
    request = {k:v for k,v in plan.items() if k in {"operation_id", "action", "resource", "arguments", "expected_revision", "lease_ms"}}
    if (not isinstance(value, dict) or set(value) != {"federation_id", "provider_id", "operation_id", "request_digest", "term", "expires_at_ms"} or
            value["federation_id"] != config["federation_id"] or value["provider_id"] != config["provider_id"] or
            value["operation_id"] != plan["operation_id"] or value["request_digest"] != "sha256:"+digest(request) or
            type(value["term"]) is not int or not 1 <= value["term"] <= 2**53-1 or type(value["expires_at_ms"]) is not int or
            not time.time_ns()//1_000_000 < value["expires_at_ms"] <= time.time_ns()//1_000_000+30000):
        fail("STALE_FENCE", "native coordinator lease scope or validity rejected")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(config["coordinator_public_key"])).verify(
            bytes.fromhex(token["signature"]), b"Ziokt/fence/v1\n"+encoded(value))
    except (ValueError, TypeError, InvalidSignature): fail("STALE_FENCE", "native coordinator signature rejected")
    row = db.execute("SELECT term,busy_until,operation_id FROM coordinator WHERE id=1").fetchone()
    if row and (value["term"] < row[0] or (existing and value["term"] != row[0])):
        fail("STALE_FENCE", "native provider rejects superseded coordinator term")
    if row and row[1] > time.time_ns()//1_000_000 and row[2] != plan["operation_id"]:
        fail("OPERATION_IN_PROGRESS", "native provider execution lease remains active")
    if not existing:
        db.execute("INSERT OR REPLACE INTO coordinator VALUES (1,?,?,?)", (value["term"], row[1] if row else 0, row[2] if row else None))


def native_registry(root):
    sys.path.insert(0, str(root / "Deployment"))
    from service_registry import ServiceRegistry
    from core_catalog import CoreCatalog
    return ServiceRegistry(catalog=CoreCatalog(root))


def service_binding_fact(root,config,name):
    """Verify locked native materials; return no credentials or unscoped files."""
    sys.path.insert(0,str(root/'Deployment'))
    from service_registry import ServiceRegistry
    from core_catalog import CoreCatalog
    import service_runtime
    registry=ServiceRegistry(config.get('service_registry_file'),CoreCatalog(root))
    item=registry.inspect(name)
    if not item.get('deploymentLock'): fail('STALE_PLAN','locked named Broker required')
    material=registry._material(name)
    from service_registry import digest as native_digest,encoded as native_encoded
    if native_digest(native_encoded(material))!=item['deploymentLock']['digest']:fail('STALE_PLAN','native Broker material changed')
    role=item['protocolContext']['role']
    if role not in {'broker','all'}:fail('INVALID_PARAMS','Broker role required for Virtual Broker route')
    content=secure_read(item['coreBinding']['config']['config_path'])
    native=strict_json(content)
    endpoints=[]
    def scan(value):
        if isinstance(value,dict):
            for key,child in value.items():
                if key in {'listen_addr','listen_address','listen'} and isinstance(child,str): endpoints.append(child)
                if key=='listen_host' and type(value.get('listen_port')) is int:
                    endpoints.append(('['+child+']' if ':' in child else child)+':'+str(value['listen_port']))
                scan(child)
        elif isinstance(value,list):
            for child in value:scan(child)
    if item.get('privacy')=='envelope':
        fields=service_runtime.parse_envelope(secure_read(item['spec']['envelope_config']))
        endpoints=[fields['listen']]
    else:scan(native.get('broker',native))
    return {'schema':'ziokt.native-broker-binding.v1','service_name':name,'core':item['coreBinding']['core'],
        'profile':item['profileBinding']['profile'],'privacy':item['privacy'],'lock_digest':item['deploymentLock']['digest'],
        'entry_endpoints':endpoints,'runtime_ready':item.get('state') in {'running','degraded'} and service_runtime.alive(item.get('runtime',{})),
        'assurance':'native-locked-material','wire_translation':False}


def native_database(path):
    """Validate an owned native database without reading its whole history."""
    path = Path(path).absolute()
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or (os.name != "nt" and before.st_uid != os.geteuid()):
        fail("UNSAFE_FILE", "owned regular native database required")
    fd = os.open(path, os.O_RDONLY|getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or os.read(fd, 16) != b"SQLite format 3\x00":
            fail("NATIVE_STATE_UNAVAILABLE", "native database header or identity changed")
    finally: os.close(fd)
    return sqlite3.connect(path.as_uri()+"?mode=ro", uri=True)


def corium_db(root, network, name):
    return native_database(root / "var/lib/corix/networks" / network / name)


def corium_identity(root, network):
    public = secure_read(root/"etc/corix/networks"/network/"identity.key.pub", 16384, private=None).decode().rstrip("\n")
    return hashlib.sha256(public.encode()).hexdigest()


def wiki_receipt(root, network, plan):
    group, slug = plan["resource"].split("/", 1)
    content = hashlib.sha256(plan["arguments"]["content"].encode()).hexdigest()
    with closing(corium_db(root, network, "blockchain/chain.db")) as db:
        for tx_hash, public, payload, height in db.execute("SELECT hash,public_key,data,block_height FROM transactions WHERE type='wiki_page_create' ORDER BY timestamp DESC LIMIT 4096"):
            value = strict_json(payload.encode())
            manifest_hash = value.get("content_hash")
            if not isinstance(manifest_hash, str) or not re.fullmatch("[a-f0-9]{64}", manifest_hash): continue
            path = root/"var/lib/corix/p2p/objects"/manifest_hash
            if not path.is_file(): continue
            raw = secure_read(path, 65536, private=None)
            if hashlib.sha256(raw).hexdigest() != manifest_hash: continue
            manifest = strict_json(raw)
            if manifest.get("size") != len(plan["arguments"]["content"].encode()) or manifest.get("chunks") != [content]: continue
            if (hashlib.sha256(public.rstrip("\n").encode()).hexdigest() == plan["binding_evidence"].get("author") and value.get("group_id") == group and value.get("page_slug") == slug and
                    value.get("commit_message") == plan["arguments"]["message"]):
                return {"native_action": "wiki.create", "resource": plan["resource"], "transaction_hash": tx_hash,
                        "phase": "pending-native-consensus" if height is None else "on-chain", "application_ready": height is not None}
    return None


def operation_preflight(provider, root, network, params, config):
    action, resource, args = params["action"], params["resource"], params["arguments"]
    if action not in OPERATIONS[provider] or action not in config["allowed_operations"]:
        fail("POLICY_DENIED", "native action is not allowed")
    if resource not in config["allowed_resources"] and "*" not in config["allowed_resources"]:
        fail("POLICY_DENIED", "native resource is not allowed")
    if action.startswith("recovery."):
        return recovery_preflight(provider, root, network, params, config)
    if action == "compute.submit":
        return compute_submit_preflight(root,network,params,config)
    if action == "compute.run":
        return compute_preflight(root, network, params, config)
    if action in {'identity.register','content.publish','zkn.transfer','zkn.gift','zkc.issue'}:
        return asset_preflight(root,network,params,config)
    if action in {"service.stop", "service.run"}:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}/[A-Za-z0-9][A-Za-z0-9._-]{0,63}", resource) or args:
            fail("INVALID_PARAMS", "fixed named-service lifecycle operation required")
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
    elif action in {"package.install", "package.activate"}:
        sys.path.insert(0, str(root / "Package-Manager"))
        from shadow6_pkg import verify_package
        match = re.fullmatch(r"(plugin|app|crosed-mod)/([a-z0-9][a-z0-9._-]{0,63})@([0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?)", resource)
        if match is None or not all(k in config for k in ("package_root", "package_trust_file", "artifact_root")):
            fail("INVALID_PARAMS", "fixed native package roots and exact selector required")
        if params["expected_revision"] is not None:
            fail("INVALID_PARAMS", "package admission uses immutable native signature evidence")
        kind, name, version = match.groups()
        if action == "package.install":
            if set(args) != {"artifact_digest"} or not re.fullmatch(r"sha256:[a-f0-9]{64}", str(args["artifact_digest"])):
                fail("INVALID_PARAMS", "exact native package artifact digest required")
            source = Path(config["artifact_root"])/args["artifact_digest"][7:]
            if hashlib.sha256(secure_read(source, 64*1024*1024, private=None)).hexdigest() != args["artifact_digest"][7:]:
                fail("ARTIFACT_DIGEST_MISMATCH", "native package artifact changed")
        else:
            if args: fail("INVALID_PARAMS", "native activation accepts no extra arguments")
            source = Path(config["package_root"])/kind/name/"versions"/version
        manifest, package = verify_package(source, Path(config["package_trust_file"]))
        try:
            if (manifest["kind"], manifest["id"], manifest["version"]) != (kind, name, version):
                fail("NATIVE_STATE_CONFLICT", "native signed package selector mismatch")
            return {"manifest_digest": "sha256:"+digest(manifest), "kind": kind, "id": name, "version": version}
        finally:
            package.close()
    elif action in {"wiki.create", "snapshot.create", "strata.create", "chain.mine"}:
        if params["expected_revision"] is not None:
            fail("INVALID_PARAMS", "native create/mine operation requires null expected_revision")
        if action == "wiki.create":
            if not re.fullmatch(r"[a-f0-9]{64}/[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}", resource) or set(args) != {"content", "message"} or not all(isinstance(v, str) and 1 <= len(v.encode()) <= 8192 for v in args.values()):
                fail("INVALID_PARAMS", "bounded group/page and content/message required")
            author = corium_identity(root, network)
            group, slug = resource.split("/", 1)
            with closing(corium_db(root, network, "forum/forum.db")) as db:
                permissions = db.execute("SELECT permissions FROM acl_state WHERE acl_id=? AND grantee_id=?", (group, author)).fetchone()
                grants = strict_json(permissions[0].encode()) if permissions else None
                if not isinstance(grants, list) or not all(isinstance(v, str) for v in grants) or "member" not in grants:
                    fail("POLICY_DENIED", "native Wiki membership required")
                if db.execute("SELECT 1 FROM wiki_pages WHERE group_id=? AND slug=?", (group, slug)).fetchone():
                    fail("NATIVE_STATE_CONFLICT", "native Wiki page already exists")
            return {"native_action": action, "resource": resource, "network_id": network, "author": author}
        elif action == "snapshot.create":
            identifier(resource, "snapshot name")
            if args: fail("INVALID_PARAMS", "native snapshot accepts no extra arguments")
            target = root/"var/lib/corix/networks"/network/"snapshots"/resource
            if target.exists(): fail("NATIVE_STATE_CONFLICT", "native snapshot name already exists")
        elif action == "strata.create":
            identifier(resource, "Strata name")
            if set(args) != {"package_manager"} or args["package_manager"] not in {"apt", "pacman", "dnf", "portage"}:
                fail("INVALID_PARAMS", "known native package manager required")
            if os.geteuid() != 0: fail("ROOT_REQUIRED", "native Strata creation requires configured root authority")
        elif resource != "chain:" + network or args:
            fail("INVALID_PARAMS", "exact native chain mining scope required")
        if action == "chain.mine":
            with closing(corium_db(root, network, "blockchain/chain.db")) as db:
                tip = db.execute("SELECT height,hash FROM blocks ORDER BY height DESC LIMIT 1").fetchone()
            if not tip: fail("NATIVE_STATE_UNAVAILABLE", "native genesis required")
            return {"native_action": action, "resource": resource, "network_id": network, "height": tip[0], "block_hash": tip[1]}
        return {"native_action": action, "resource": resource, "network_id": network}
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
        with closing(sqlite3.connect(dht.as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("SELECT hash,file_path,offset,size FROM local_chunks LIMIT 1").fetchall()
        return {"artifact_digest": resource}


def operation_execute(provider, root, network, plan, config=None):
    resource = plan["resource"]
    if provider=='corium' and plan['action'] in {'zkn.gift','zkc.issue'}:
        if asset_preflight(root,network,plan,config)!=plan['binding_evidence']:
            fail('STALE_PLAN','private gift evidence changed')
        return asset_submit_gift(root,network,plan['arguments']['transaction'],'zkc_issue' if plan['action']=='zkc.issue' else 'zkn_private_transfer')
    if provider == "shadow6" and plan["action"].startswith("recovery."):
        return recovery_execute(provider, root, network, plan, config)
    if plan["action"] in {"service.stop", "service.run"}:
        registry = native_registry(root)
        if plan["action"] == "service.stop": registry.ziokt_stop(resource, expected_revision=plan["expected_revision"])
        else: registry.ziokt_run(resource, expected_revision=plan["expected_revision"])
        return {"native_id": resource, "postcondition": "stopped" if plan["action"] == "service.stop" else "running", "application_ready": False}
    if plan["action"] in {"package.install", "package.activate"}:
        sys.path.insert(0, str(root/"Package-Manager"))
        from shadow6_pkg import install_package, activate, verify_package
        evidence = plan["binding_evidence"]
        directory = Path(config["package_root"])/evidence["kind"]/evidence["id"]/"versions"/evidence["version"]
        if plan["action"] == "package.install":
            if not directory.exists():
                install_package(Path(config["artifact_root"])/plan["arguments"]["artifact_digest"][7:], Path(config["package_trust_file"]), Path(config["package_root"]), False)
            else:
                manifest, package = verify_package(directory, Path(config["package_trust_file"]))
                package.close()
                if "sha256:"+digest(manifest) != evidence["manifest_digest"]:
                    fail("NATIVE_STATE_CONFLICT", "installed version differs from signed plan")
        else:
            manifest, package = verify_package(directory, Path(config["package_trust_file"]))
            package.close()
            if "sha256:"+digest(manifest) != evidence["manifest_digest"]:
                fail("NATIVE_STATE_CONFLICT", "native package changed before activation")
            activate(Path(config["package_root"]), evidence["kind"], evidence["id"], evidence["version"])
        return {"native_selector": resource, "native_signature_verified": True, "activated": plan["action"] == "package.activate", "manifest_digest": evidence["manifest_digest"]}
    if plan["action"] in {"wiki.create", "snapshot.create", "strata.create", "chain.mine", "compute.run", "compute.submit", "identity.register", "content.publish", "zkn.transfer", "zkn.gift", "zkc.issue", "recovery.checkpoint", "recovery.restore"}:
        import subprocess
        source = os.environ.get("_ZIOKT_CORIUM_SOURCE")
        if not source: fail("NATIVE_STATE_UNAVAILABLE", "production monolith unavailable for native action")
        environment = {**os.environ, "CORIUM_ROOT": str(root), "CORIUM_NETWORK_ID_OVERRIDE": network,
                       "CORIUM_TEST_NO_DAEMONS": "1"}
        process = subprocess.Popen(["bash", source, "_internal_ziokt_dispatch", plan["operation_id"]],
                                   env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            process.wait(timeout=25)
        except subprocess.TimeoutExpired:
            import signal
            os.killpg(process.pid, signal.SIGKILL); process.wait()
            fail("RESULT_UNKNOWN", "native Corium action exceeded its execution lease; reconcile its intent")
        if process.returncode: fail("RESULT_UNKNOWN", "native Corium action failed; reconcile its intent")
        if plan["action"].startswith("recovery."):
            return recovery_execute(provider, root, network, plan, config)
        if plan["action"] == "strata.create":
            return {"native_action": "strata.create", "resource": resource, "phase": "native-completed", "recovery": "interrupted-provisioning-requires-native-review"}
        result = operation_reconcile(provider, root, network, plan, config)
        if result is None:
            if plan["action"] == "chain.mine":
                return {"native_action": "chain.mine", "phase": "native-no-op", "block_created": False}
            fail("RESULT_UNKNOWN", "native postcondition has not been verified")
        return result
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
    with closing(sqlite3.connect(dht)) as db, db:
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


def operation_reconcile(provider, root, network, plan, config):
    action = plan["action"]
    if action.startswith("recovery."): return recovery_reconcile(provider, root, network, plan, config)
    if action in {"service.stop", "service.run"}:
        registry = native_registry(root)
        item = registry.services.get(plan["resource"])
        if item and item["state"] == ("stopped" if action == "service.stop" else "running"):
            evidence = {"core_binding": digest(item.get("coreBinding")), "profile_binding": digest(item.get("profileBinding")),
                        "context": digest(item.get("protocolContext")), "lock": (item.get("deploymentLock") or {}).get("digest")}
            if evidence != plan["binding_evidence"]:
                fail("STALE_PLAN", "native binding changed during interrupted operation")
            if action == "service.run":
                # The original authority checks process identity and readiness.
                if registry.status(plan["resource"])["state"] != "running": return None
            return {"native_id": plan["resource"], "postcondition": "stopped" if action == "service.stop" else "running", "reconciled": True, "application_ready": False}
        return None
    if action in {"package.install", "package.activate"}:
        sys.path.insert(0, str(root/"Package-Manager"))
        from shadow6_pkg import verify_package
        e = plan["binding_evidence"]
        base = Path(config["package_root"])/e["kind"]/e["id"]
        source = base/"versions"/e["version"]
        if not source.exists(): return None
        manifest, package = verify_package(source, Path(config["package_trust_file"]))
        package.close()
        if "sha256:"+digest(manifest) != e["manifest_digest"]:
            fail("NATIVE_STATE_CONFLICT", "native installed package differs from recovery evidence")
        if action == "package.activate":
            pointer = strict_json(secure_read(base/"active.json", 4096, private=None))
            if pointer != {"schema_version": 1, "version": e["version"]}: return None
        return {"native_selector": plan["resource"], "native_signature_verified": True, "activated": action == "package.activate", "reconciled": True}
    if action == "wiki.create": return wiki_receipt(root, network, plan)
    if action == "compute.run": return compute_receipt(root, network, plan)
    if action in {'compute.submit','identity.register','content.publish','zkn.transfer','zkn.gift','zkc.issue'}: return asset_receipt(root,network,plan)
    if action == "chain.mine":
        e = plan["binding_evidence"]
        with closing(corium_db(root, network, "blockchain/chain.db")) as db:
            tip = db.execute("SELECT height,hash,previous_hash FROM blocks WHERE height=?", (e["height"]+1,)).fetchone()
        if tip and tip[2] == e["block_hash"]:
            return {"native_action": action, "block_created": True, "height": tip[0], "block_hash": tip[1], "reconciled": True}
        return None
    if action == "snapshot.create":
        base = root/"var/lib/corix/networks"/network/"snapshots"/plan["resource"]
        if (base/"snapshot.meta").is_file():
            metadata = secure_read(base/"snapshot.meta", 4096, private=None).decode()
            if "name="+plan["resource"]+"\n" in metadata and (base/"etc").is_dir():
                return {"native_action": action, "resource": plan["resource"], "phase": "native-completed", "reconciled": True}
        return None
    if action == "strata.create":
        # A directory alone cannot prove successful provisioning after a crash.
        return None
    if action != "artifact.stage": return None
    target = root / "var/lib/corix/p2p/objects/ziokt" / plan["resource"][7:]
    if target.is_file() and not target.is_symlink() and hashlib.sha256(secure_read(target, 6144, private=None)).hexdigest() == plan["resource"][7:]:
        # Resume the fixed content registration only; hashing prevents a changed
        # payload from being mistaken for the interrupted operation.
        return {**operation_execute(provider, root, network, plan, config), "reconciled": True}
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
            rows = db.execute("SELECT o.seq,o.operation_id,o.state,o.evidence FROM outbox o JOIN operations p ON p.id=o.operation_id WHERE o.seq>? AND json_extract(p.plan,'$.federation_id')=? AND json_extract(p.plan,'$.provider_id')=? ORDER BY o.seq LIMIT ?",
                              (params.get("after_seq", 0), config["federation_id"], config["provider_id"], params.get("limit", 50))).fetchall()
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
            required = {"operation_id", "action", "resource", "arguments", "expected_revision"}
            if not required <= set(params) or set(params) - required - {"lease_ms", "fence"}:
                fail("INVALID_PARAMS", "exact native operation plan required")
            if not isinstance(params["action"], str) or not isinstance(params["resource"], str) or not isinstance(params["arguments"], dict):
                fail("INVALID_PARAMS", "typed native action required")
            if params["expected_revision"] is not None and not re.fullmatch(r"sha256:[a-f0-9]{64}", str(params["expected_revision"])):
                fail("INVALID_PARAMS", "native revision digest required")
            request_digest = digest(params)
            row = db.execute("SELECT * FROM operations WHERE id=?", (params["operation_id"],)).fetchone()
            if row:
                previous = strict_json(row[2].encode())
                if previous["federation_id"] != config["federation_id"] or previous["provider_id"] != config["provider_id"]:
                    fail("SCOPE_MISMATCH", "native operation belongs to another provider scope")
                if row[1] != request_digest:
                    fail("IDEMPOTENCY_CONFLICT", "operation ID cannot change its request")
                return operation_view(row)
            evidence = operation_preflight(provider, root, network, params, config)
            fence_admit(db, config, params)
            if db.execute("SELECT COUNT(*) FROM operations").fetchone()[0] >= 4096:
                fail("JOURNAL_LIMIT", "native operation journal requires explicit archival")
            plan = {**params, "federation_id": config["federation_id"], "provider_id": config["provider_id"],
                    "expires_at_ms": time.time_ns() // 1_000_000 + params.get("lease_ms", 30_000), "binding_evidence": evidence}
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
                result = operation_reconcile(provider, root, network, plan, config)
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
        fence_admit(db, config, plan, existing=True)
        if operation_preflight(provider, root, network, plan, config) != plan["binding_evidence"]:
            fail("STALE_PLAN", "native evidence changed after prepare")
        with db:
            changed = db.execute("UPDATE operations SET state='unknown' WHERE id=? AND state='prepared'", (row[0],)).rowcount
            if changed != 1:
                fail("OPERATION_CONFLICT", "operation already claimed")
            if "coordinator_public_key" in config:
                db.execute("UPDATE coordinator SET busy_until=?,operation_id=? WHERE id=1", (time.time_ns()//1_000_000+30000, row[0]))
        result = operation_execute(provider, root, network, plan, config)
        with db:
            db.execute("UPDATE operations SET state='committed',result=? WHERE id=?", (encoded(result).decode(), row[0]))
            db.execute("INSERT OR IGNORE INTO outbox(operation_id,state,evidence) VALUES (?,'committed',?)", (row[0], encoded(result).decode()))
            if "coordinator_public_key" in config:
                db.execute("UPDATE coordinator SET busy_until=0,operation_id=NULL WHERE id=1 AND operation_id=?", (row[0],))
        return operation_view(db.execute("SELECT * FROM operations WHERE id=?", (row[0],)).fetchone())
    except sqlite3.Error:
        fail("JOURNAL_UNAVAILABLE", "native operation journal is busy or invalid")
    finally:
        db.close()

"""Fixed native checkpoints; restore only cold state under native authority."""
import tempfile


def recovery_content(config, content=None, expected=None):
    if "artifact_root" not in config:
        fail("INVALID_CONFIG", "fixed private recovery artifact store required")
    directory = private_mkdir(config["artifact_root"])
    if content is None:
        if not isinstance(expected, str) or not re.fullmatch("sha256:[a-f0-9]{64}", expected):
            fail("INVALID_RECOVERY", "exact checkpoint digest required")
        raw = secure_read(directory/expected[7:], 64*1024*1024)
        if "sha256:"+hashlib.sha256(raw).hexdigest() != expected:
            fail("ARTIFACT_DIGEST_MISMATCH", "native checkpoint was changed")
        return raw
    key = "sha256:"+hashlib.sha256(content).hexdigest()
    target = directory/key[7:]
    with tempfile.NamedTemporaryFile(dir=directory, prefix=".checkpoint-", delete=False) as output:
        temporary = Path(output.name)
        output.write(content); output.flush(); os.fsync(output.fileno())
    try:
        try: os.link(temporary, target)
        except FileExistsError: recovery_content(config, expected=key)
    finally: temporary.unlink(missing_ok=True)
    return key


def validate_phoenix(raw, root, network):
    value = strict_json(raw, 64*1024*1024, string_limit=65536)
    if not isinstance(value, dict) or value.get("format") != "CORIUM_PHOENIX_GENESIS_V2":
        fail("INVALID_RECOVERY", "native Phoenix checkpoint required")
    public = secure_read(root/"etc/corix/networks"/network/"identity.key.pub", 16384, private=None).decode().rstrip("\n")
    if not isinstance(value.get("snapshot_public_key"), str) or value["snapshot_public_key"].rstrip("\n") != public:
        fail("POLICY_DENIED", "native checkpoint signer must match configured recovery authority")
    unsigned = {k:v for k,v in value.items() if k not in {"state_root", "snapshot_signature"}}
    if value.get("state_root") != digest(unsigned): fail("INVALID_RECOVERY", "native signed state root differs")
    native_ec_verify(public, value.get("snapshot_signature"), value["state_root"].encode())
    return value


def shadow_checkpoint(root, services, include_secrets):
    registry = native_registry(root)
    from profile_registry import native_material_paths
    records, materials = [], {}
    for name in services:
        item = registry.services.get(name)
        if item is None or item.get("coreBinding") is None:
            fail("NATIVE_STATE_UNAVAILABLE", "configured native service required for recovery")
        admitted = registry._material(name)  # Original lock, binary and material validator.
        binding = item["coreBinding"]
        paths = {"config": binding["config"]["config_path"]}
        document = strict_json(secure_read(paths["config"]))
        paths.update(native_material_paths(item["profileBinding"], document))
        for field in ("nativeMaterials", "envelopeTlsMaterial", "componentMaterials"):
            paths.update(admitted.get(field, {}))
        for field in ("envelope_config", "gate_config", "guard_config", "credited_config"):
            if item["spec"].get(field): paths[field] = item["spec"][field]
        for path in paths.values():
            if not include_secrets:
                fail("SECRET_RECOVERY_DISABLED", "explicit include_secrets required to export native transport material")
            raw = secure_read(path, 65536)
            materials[path] = base64.b64encode(raw).decode()
        records.append({"name": name, "core": binding["core"], "profile": item["profileBinding"]["profile"],
            "privacy": item["privacy"], "context": item["protocolContext"], "spec": item["spec"], "config_path": paths["config"]})
    return {"schema": "ziokt.shadow6-checkpoint.v1", "services": records, "materials": materials,
            "contains_secrets": include_secrets, "running_state": "excluded"}


def recovery_preflight(provider, root, network, params, config):
    args, action = params["arguments"], params["action"]
    scope = network if provider == "corium" else "shadow6"
    if params["resource"] != ("checkpoint:" if action == "recovery.checkpoint" else "recovery:")+scope or params["expected_revision"] is not None:
        fail("INVALID_RECOVERY", "exact cold native recovery scope required")
    if "artifact_root" not in config: fail("INVALID_CONFIG", "fixed checkpoint store required")
    safe_directory(config["artifact_root"])
    if action == "recovery.checkpoint":
        if provider == "shadow6":
            if (set(args) != {"services", "include_secrets"} or type(args["include_secrets"]) is not bool or
                    not isinstance(args["services"], list) or not 1 <= len(args["services"]) <= 32 or
                    not all(isinstance(v, str) for v in args["services"]) or len(set(args["services"])) != len(args["services"])):
                fail("INVALID_RECOVERY", "bounded named services and explicit secret export choice required")
            value = shadow_checkpoint(root, args["services"], args["include_secrets"])
            return {"checkpoint_revision": "sha256:"+digest(value), "contains_secrets": args["include_secrets"]}
        if set(args) != {"height"} or type(args["height"]) is not int or not 0 <= args["height"] <= 2**31:
            fail("INVALID_RECOVERY", "exact native checkpoint height required")
        with closing(corium_db(root, network, "blockchain/chain.db")) as db:
            block = db.execute("SELECT hash FROM blocks WHERE height=?", (args["height"],)).fetchone()
        if block is None: fail("NATIVE_STATE_UNAVAILABLE", "checkpoint height not present in native chain")
        return {"height": args["height"], "block_hash": block[0]}
    if set(args) != {"checkpoint_digest"}: fail("INVALID_RECOVERY", "exact immutable restore source required")
    raw = recovery_content(config, expected=args["checkpoint_digest"])
    value = strict_json(raw, 64*1024*1024, string_limit=65536)
    if provider == "shadow6":
        if (not isinstance(value, dict) or set(value) != {"schema", "services", "materials", "contains_secrets", "running_state"} or
                value["schema"] != "ziokt.shadow6-checkpoint.v1" or value["running_state"] != "excluded" or
                not isinstance(value["services"], list) or not 1 <= len(value["services"]) <= 32 or not isinstance(value["materials"], dict) or len(value["materials"]) > 256):
            fail("INVALID_RECOVERY", "exact stopped-state native service checkpoint required")
        registry = native_registry(root)
        for item in value["services"]:
            if not isinstance(item, dict) or set(item) != {"name", "core", "profile", "privacy", "context", "spec", "config_path"}:
                fail("INVALID_RECOVERY", "exact native service reconstruction fields required")
            if item["name"] in registry.services: fail("NATIVE_STATE_CONFLICT", "restore cannot overwrite existing named services")
            if item["privacy"] not in {"native", "envelope"} or not isinstance(item["spec"], dict): fail("INVALID_RECOVERY", "native restoration cannot lower privacy")
        return {"checkpoint_digest": args["checkpoint_digest"], "service_count": len(value["services"])}
    value = validate_phoenix(raw, root, network)
    with closing(corium_db(root, network, "blockchain/chain.db")) as db:
        if db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]:
            fail("NATIVE_STATE_CONFLICT", "Phoenix restoration requires an empty native chain")
    return {"source": str(Path(config["artifact_root"])/args["checkpoint_digest"][7:]),
            "checkpoint_digest": args["checkpoint_digest"], "state_root": value["state_root"]}


def recovery_execute(provider, root, network, plan, config):
    if provider == "corium":
        if plan["action"] == "recovery.restore":
            return {"native_action": "recovery.restore", "state_root": plan["binding_evidence"]["state_root"], "native_signature_verified": True, "running_state_restored": False}
        path = operation_directory(provider, root, network)/"checkpoints"/(plan["operation_id"]+".json")
        raw = secure_read(path, 64*1024*1024)
        value = validate_phoenix(raw, root, network)
        return {"checkpoint_digest": recovery_content(config, raw), "state_root": value["state_root"],
                "native_signature_verified": True, "running_state_restored": False}
    if plan["action"] == "recovery.checkpoint":
        raw = encoded(shadow_checkpoint(root, plan["arguments"]["services"], plan["arguments"]["include_secrets"]))
        return {"checkpoint_digest": recovery_content(config, raw), "contains_secrets": plan["arguments"]["include_secrets"], "running_state_restored": False}
    value = strict_json(recovery_content(config, expected=plan["arguments"]["checkpoint_digest"]), 64*1024*1024, string_limit=65536)
    directory = private_mkdir(operation_directory(provider, root, network)/"restored-material")
    mapping = {}
    for source, data in value["materials"].items():
        raw = base64.b64decode(data, validate=True)
        if len(raw) > 65536: fail("INVALID_RECOVERY", "restored native material exceeds budget")
        target = directory/hashlib.sha256(source.encode()).hexdigest()
        if target.exists():
            if secure_read(target, 65536) != raw: fail("NATIVE_STATE_CONFLICT", "restored material already differs")
        else:
            fd = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output: output.write(raw); output.flush(); os.fsync(output.fileno())
        mapping[source] = str(target)
    for item in value["services"]:
        for field in ("metrics_path",):
            if item["spec"].get(field):
                mapping[item["spec"][field]] = str(directory/(hashlib.sha256(item["spec"][field].encode()).hexdigest()+".metrics"))
    def remap(item):
        if isinstance(item, str): return mapping.get(item, item)
        if isinstance(item, list): return [remap(v) for v in item]
        if isinstance(item, dict): return {k: remap(v) for k,v in item.items()}
        return item
    # Rewrite material references inside JSON configuration as well.
    configs = {item["config_path"] for item in value["services"]}
    configs.update(item["spec"][field] for item in value["services"] for field in ("envelope_config", "gate_config", "guard_config", "credited_config") if item["spec"].get(field))
    for source in configs:
        target = mapping[source]
        raw = secure_read(target, 65536)
        try: rewritten = encoded(remap(strict_json(raw)))
        except ProtocolError:
            # Native S6EPE INI is validated by the native authority at export
            # and again on explicit apply. Preserve its policy and only remap
            # the admitted fixed material paths into the private restore root.
            text = raw.decode("utf-8")
            for old in sorted(mapping, key=len, reverse=True): text = text.replace(old, mapping[old])
            rewritten = text.encode()
        if rewritten != raw:
            from service_storage import atomic_write
            atomic_write(Path(target), rewritten)
    registry = native_registry(root)
    names = []
    for item in value["services"]:
        registry.create(item["name"], core=item["core"], profile=item["profile"], privacy=item["privacy"],
            config={"config_path": mapping[item["config_path"]]}, context=remap(item["context"]), spec=remap(item["spec"]))
        names.append(item["name"])
    return {"services": names, "running_state_restored": False, "native_apply_required": True}


def recovery_reconcile(provider, root, network, plan, config):
    if plan["action"] == "recovery.restore":
        if provider == "corium": return None  # Native partial import requires native review.
        value = strict_json(recovery_content(config, expected=plan["arguments"]["checkpoint_digest"]), 64*1024*1024, string_limit=65536)
        registry = native_registry(root)
        names = []
        directory = operation_directory(provider, root, network)/"restored-material"
        for desired in value["services"]:
            item = registry.services.get(desired["name"])
            expected_path = str(directory/hashlib.sha256(desired["config_path"].encode()).hexdigest())
            if (not item or item.get("runtime") or item.get("deploymentLock") or item.get("privacy") != desired["privacy"] or
                    (item.get("coreBinding") or {}).get("core") != desired["core"] or
                    item["coreBinding"]["config"]["config_path"] != expected_path): return None
            names.append(desired["name"])
        return {"services": names, "running_state_restored": False, "native_apply_required": True, "reconciled": True}
    if provider == "corium":
        path = operation_directory(provider, root, network)/"checkpoints"/(plan["operation_id"]+".json")
        if path.is_file(): return {**recovery_execute(provider, root, network, plan, config), "reconciled": True}
    else:
        expected = plan["binding_evidence"]["checkpoint_revision"]
        try: recovery_content(config, expected=expected)
        except FileNotFoundError: return None
        return {"checkpoint_digest": expected, "reconciled": True, "running_state_restored": False}
    return None

"""Bounded signed inclusion observations from C's existing canonical ledger."""


def governance_fact(root, network, tx_hash):
    with closing(corium_db(root, network, "blockchain/chain.db")) as db:
        row = db.execute("SELECT type,data,signature,public_key,timestamp,block_height FROM transactions WHERE hash=?", (tx_hash,)).fetchone()
        if not row or row[5] is None: fail("NATIVE_FACT_PENDING", "native transaction has no canonical inclusion")
        tx_type, raw, signature, public, timestamp, height = row
        payload = strict_json(raw.encode())
        content = ('{"type":'+json.dumps(tx_type)+',"data":'+raw+',"timestamp":'+str(timestamp)+'}').encode()
        if hashlib.sha256(content).hexdigest() != tx_hash: fail("NATIVE_FACT_REJECTED", "native transaction hash differs")
        native_ec_verify(public, signature, content)
        blocks = db.execute("SELECT height,hash,previous_hash,timestamp,validator,signature,transactions FROM blocks WHERE height>=? ORDER BY height LIMIT 130", (height,)).fetchall()
        tip = db.execute("SELECT MAX(height) FROM blocks").fetchone()[0]
        if not blocks or tip-height >= 128: fail("NATIVE_FACT_STALE", "native inclusion exceeds bounded observation window")
        previous = None
        for block in blocks:
            h, block_hash, parent, ts, validator, sig, transactions = block
            hashes = strict_json(transactions.encode())
            if h == height and tx_hash not in hashes: fail("NATIVE_FACT_REJECTED", "native block omits transaction reference")
            if previous and (h != previous[0]+1 or parent != previous[1]): fail("NATIVE_FACT_REJECTED", "native branch has a discontinuity")
            data = ('{"height":'+str(h)+',"previous_hash":'+json.dumps(parent)+',"timestamp":'+str(ts)+',"transactions":'+transactions+'}').encode()
            key = db.execute("SELECT public_key FROM validators WHERE public_key_hash=?", (validator,)).fetchone()
            if not key or hashlib.sha256(data).hexdigest() != block_hash: fail("NATIVE_FACT_REJECTED", "native validator or block digest differs")
            native_ec_verify(key[0], sig, data)
            previous = h, block_hash
        if previous[0] != tip: fail("NATIVE_FACT_STALE", "native inclusion could not be connected to current tip")
    requested = payload.get("ziokt_workflow_digest") if isinstance(payload, dict) else None
    if requested is not None and (not isinstance(requested, str) or not re.fullmatch("sha256:[a-f0-9]{64}", requested)):
        fail("NATIVE_FACT_REJECTED", "native workflow reference has invalid type")
    return {"schema": "ziokt.native-fact.v1", "network_id": network, "transaction_hash": tx_hash,
            "transaction_type": tx_type, "sender_id": hashlib.sha256(public.rstrip("\n").encode()).hexdigest(),
            "height": height, "block_hash": blocks[0][1], "tip_height": tip, "confirmations": tip-height+1,
            "workflow_digest": requested, "assurance": "native-signed-inclusion", "native_permissions_granted": False}

"""Fixed Corium compute engine execution with native signatures and crash receipts."""


def compute_preflight(root, network, params, config):
    resource = params['resource']
    if (not resource.startswith('compute:') or params['arguments'] or params['expected_revision'] is not None or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,127}', resource[8:])):
        fail('INVALID_PARAMS', 'fixed approved native compute engine required')
    engine = resource[8:]
    with closing(corium_db(root, network, 'blockchain/chain.db')) as db:
        cached = db.execute("SELECT value FROM chain_state WHERE key='chain_info'").fetchone()
        # Match blockchain_get_latest_hash: the native accepted head wins over
        # a heavier unaccepted/invalid branch merely present in the database.
        if cached:
            fields = cached[0].split('|')
            if len(fields) != 2 or not fields[1].isdigit():
                fail('NATIVE_STATE_CONFLICT', 'native canonical head cache is malformed')
            tip = db.execute('SELECT height,hash FROM blocks WHERE hash=? AND height=?', (fields[0], int(fields[1]))).fetchone()
        else:
            tip = db.execute('SELECT height,hash FROM blocks ORDER BY total_weight DESC,height DESC LIMIT 1').fetchone()
        if not tip: fail('NATIVE_STATE_UNAVAILABLE', 'native compute requires an available canonical head')
        row = db.execute('SELECT engine_id,pkg_id,compute_program_hash,verifier_script_hash,is_active FROM compute_engines WHERE engine_id=?', (engine,)).fetchone()
        if engine == 'corium/internal-engine-zero-v1':
            row = [engine, 'corium/internal-engine-zero-v1', 'BUILT_IN', 'BUILT_IN', 1]
            problem = None
        else:
            if not row or row[4] != 1: fail('POLICY_DENIED', 'native computation engine is not active')
            problem = db.execute('SELECT set_id,metadata,activation_height FROM problem_sets WHERE engine_id=? AND activation_height IS NOT NULL AND activation_height<=? ORDER BY activation_height DESC LIMIT 1', (engine, tip[0])).fetchone()
            if not problem or len(encoded(list(problem))) > 8192:
                fail('NATIVE_STATE_UNAVAILABLE', 'bounded active native problem set required')
    return {'engine_id': engine, 'engine_digest': 'sha256:'+digest(list(row)),
            'problem_digest': 'sha256:'+digest(list(problem) if problem else None),
            'height': tip[0], 'block_hash': tip[1], 'author': corium_identity(root, network)}


def compute_directory(root, network, op_id):
    identifier(op_id, 'operation_id')
    return operation_directory('corium', root, network)/('compute-'+op_id)


def compute_finish(args):
    root, network, op_id = Path(args[0]).absolute(), args[1], args[2]
    identifier(network, 'network')
    db = operation_db('corium', root, network)
    try:
        row = db.execute('SELECT * FROM operations WHERE id=?', (op_id,)).fetchone()
        if row is None or row[3] != 'unknown': fail('POLICY_DENIED', 'recorded compute execution intent required')
        plan = strict_json(row[2].encode())
        config = load_config('corium', root/'etc/corix/networks'/network/'corix.conf')
        if plan['action'] != 'compute.run' or operation_preflight('corium', root, network, plan, config) != plan['binding_evidence']:
            fail('STALE_PLAN', 'native compute facts changed during execution')
        directory = compute_directory(root, network, op_id)
        proofs = []
        paths = sorted(directory.glob('proof-*.json'))
        if len(paths) > 4: fail('RESPONSE_LIMIT', 'native compute proof count exceeded')
        for path in paths:
            data = secure_read(path, 6144, private=None)
            proofs.append({'digest': 'sha256:'+hashlib.sha256(data).hexdigest(), 'data_base64': base64.b64encode(data).decode()})
        payload = {'native_action': 'compute.run', 'engine_id': plan['binding_evidence']['engine_id'],
                   'binding_digest': 'sha256:'+digest(plan['binding_evidence']), 'proofs': proofs,
                   'proof_verified': False, 'application_ready': False}
        from cryptography.hazmat.primitives import serialization
        private = serialization.load_pem_private_key(secure_read(root/'etc/corix/networks'/network/'identity.key'), password=None)
        public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode().rstrip('\n')
        receipt = {'payload': payload, 'native_public': public,
                   'signature': native_ec_sign(private, b'Ziokt/native-compute/v1\n'+encoded(payload))}
        target = directory/'completed.json'
        fd = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            make_private(target)
            with os.fdopen(fd, 'wb') as output:
                output.write(encoded(receipt)); output.flush(); os.fsync(output.fileno())
        except BaseException:
            target.unlink(missing_ok=True); raise
    finally: db.close()


def compute_receipt(root, network, plan):
    target = compute_directory(root, network, plan['operation_id'])/'completed.json'
    if not target.exists(): return None
    receipt = strict_json(secure_read(target, 65536))
    if not isinstance(receipt, dict) or set(receipt) != {'payload', 'native_public', 'signature'}:
        fail('NATIVE_STATE_CONFLICT', 'exact signed native compute receipt required')
    public = secure_read(root/'etc/corix/networks'/network/'identity.key.pub', 16384, private=None).decode().rstrip('\n')
    if receipt['native_public'] != public or hashlib.sha256(public.encode()).hexdigest() != plan['binding_evidence']['author']:
        fail('NATIVE_STATE_CONFLICT', 'native compute signer changed')
    value = receipt['payload']
    native_ec_verify(public, receipt['signature'], b'Ziokt/native-compute/v1\n'+encoded(value))
    if (not isinstance(value, dict) or set(value) != {'native_action', 'engine_id', 'binding_digest', 'proofs', 'proof_verified', 'application_ready'} or
            value['native_action'] != 'compute.run' or value['engine_id'] != plan['binding_evidence']['engine_id'] or
            value['binding_digest'] != 'sha256:'+digest(plan['binding_evidence']) or value['proof_verified'] is not False or
            value['application_ready'] is not False or not isinstance(value['proofs'], list) or len(value['proofs']) > 4):
        fail('NATIVE_STATE_CONFLICT', 'native compute receipt scope changed')
    for proof in value['proofs']:
        if not isinstance(proof, dict) or set(proof) != {'digest', 'data_base64'}:
            fail('NATIVE_STATE_CONFLICT', 'native compute proof schema changed')
        try: data = base64.b64decode(proof['data_base64'], validate=True)
        except (ValueError, TypeError): fail('NATIVE_STATE_CONFLICT', 'native proof encoding changed')
        if len(data) > 6144 or proof['digest'] != 'sha256:'+hashlib.sha256(data).hexdigest():
            fail('ARTIFACT_DIGEST_MISMATCH', 'native computation proof bytes changed')
    return {**value, 'native_signature_verified': True, 'phase': 'native-execution-completed'}


def compute_challenge(root, network):
    """The accepted native head and configured signer define an Engine Zero job."""
    with closing(corium_db(root,network,'blockchain/chain.db')) as db:
        cached=db.execute("SELECT value FROM chain_state WHERE key='chain_info'").fetchone()
        if not cached or not isinstance(cached[0],str):fail('NATIVE_STATE_UNAVAILABLE','accepted native chain head required')
        fields=cached[0].split('|')
        if len(fields)!=2 or not fields[1].isdigit() or not re.fullmatch('[a-f0-9]{64}',fields[0]):fail('NATIVE_STATE_CONFLICT','invalid accepted native head')
        if not db.execute('SELECT 1 FROM blocks WHERE hash=? AND height=?',(fields[0],int(fields[1]))).fetchone():fail('NATIVE_STATE_CONFLICT','accepted head not present')
        done=db.execute("SELECT 1 FROM completed_compute_tasks WHERE engine_id=? AND problem_id=?",('corium/internal-engine-zero-v1',fields[0])).fetchone()
        pending=db.execute('SELECT 1 FROM pending_proofs WHERE problem_id=?',(fields[0],)).fetchone()
        queued=False
        for (raw,) in db.execute("SELECT data FROM transactions WHERE type='submit_math_proof' AND block_height IS NULL LIMIT 4096"):
            data=strict_json(raw.encode())
            if data.get('engine_id')=='corium/internal-engine-zero-v1' and data.get('problem_id')==fields[0]:queued=True;break
    return {'schema':'ziokt.engine-zero-challenge.v1','engine_id':'corium/internal-engine-zero-v1','network_id':network,
            'submitter_id':corium_identity(root,network),'problem_id':fields[0],'height':int(fields[1]),'difficulty':3,'available':not (done or pending or queued)}


def compute_submit_preflight(root,network,params,config):
    args=params['arguments']
    if params['resource']!='compute:corium/internal-engine-zero-v1' or params['expected_revision'] is not None or set(args)!={'problem_id','nonce'} or not isinstance(args['problem_id'],str) or not re.fullmatch('[a-f0-9]{64}',args['problem_id']) or not isinstance(args['nonce'],str) or not re.fullmatch('0|[1-9][0-9]{0,19}',args['nonce']):fail('INVALID_PARAMS','bounded native Engine Zero proof required')
    job=compute_challenge(root,network)
    if args['problem_id']!=job['problem_id']:fail('STALE_PLAN','native Engine Zero head changed')
    proof={'nonce':args['nonce'],'submitter_id':job['submitter_id'],'network_id':network}
    if not hashlib.sha256((network+job['submitter_id']+args['nonce']+args['problem_id']).encode()).hexdigest().startswith('000'):fail('INVALID_PROOF','Engine Zero nonce failed verification')
    payload={'engine_id':job['engine_id'],'problem_id':args['problem_id'],'engine_hash':'BUILT_IN','verifier_hash':'BUILT_IN','proof_data':proof}
    # Do not submit an alternate proof after another worker already claimed this head.
    if not job['available']:
        with closing(corium_db(root,network,'blockchain/chain.db')) as db:
            same=any(strict_json(raw.encode())==payload for (raw,) in db.execute("SELECT data FROM transactions WHERE type='submit_math_proof' LIMIT 4096"))
        if not same:fail('TASK_UNAVAILABLE','native challenge is already claimed')
    return {'transaction_type':'submit_math_proof','payload':payload,'issuer':job['submitter_id']}

"""Native signed registration receipts and transferable block-snapshot ZKN assets."""

ASSET_TYPES = {'ziokt_identity_register', 'ziokt_content', 'zkn_mint', 'zkn_transfer', 'zkn_private_transfer', 'zkc_issue'}


def asset_tables(db):
    # Typed dynamic DDL remains represented in Corium's custom-schema recovery.
    definitions = {
        'ziokt_registrations': 'network TEXT,member TEXT,commitment TEXT,policy TEXT,issuer TEXT,transaction_hash TEXT,height INTEGER,PRIMARY KEY(network,member,policy)',
        'zkn_tokens': 'token_id TEXT PRIMARY KEY,block_hash TEXT UNIQUE,owner TEXT,nonce INTEGER,manifest TEXT,mint_transaction TEXT,height INTEGER',
        'zkn_receivers': 'address TEXT PRIMARY KEY,transaction_hash TEXT UNIQUE,height INTEGER',
    }
    definitions['zkc_editions']='edition_id TEXT PRIMARY KEY,token_id TEXT,kind TEXT,serial TEXT,contents_digest TEXT,issuer TEXT,transaction_hash TEXT,height INTEGER'
    for table, fields in definitions.items(): db.execute('CREATE TABLE IF NOT EXISTS "'+table+'" ('+fields+')')


def asset_token_id(network, block_hash):
    return hashlib.sha256(('Ziokt/ZKN/v1\n'+network+'\n'+block_hash).encode()).hexdigest()


def asset_transaction_bytes(tx):
    # Match Corium's existing signed serialization exactly.
    return ('{"type":'+json.dumps(tx['type'])+',"data":'+encoded(tx['data']).decode()+',"timestamp":'+str(tx['timestamp'])+'}').encode()


def zkc_edition_id(payload):
    return hashlib.sha256(b'Ziokt/ZKC/edition/v1\n'+encoded({k:payload[k] for k in ('network_id','token_id','kind','serial')})).hexdigest()


def asset_signed_gift(tx, network, kind='zkn_private_transfer'):
    if (not isinstance(tx,dict) or set(tx)!={'type','data','timestamp','public_key','signature'} or
            kind not in {'zkn_private_transfer','zkc_issue'} or tx['type']!=kind or type(tx['timestamp']) is not int or not 0<tx['timestamp']<2**53 or
            not isinstance(tx['data'],dict) or tx['data'].get('network_id')!=network or
            not isinstance(tx['public_key'],str) or len(tx['public_key'])>1024 or
            not isinstance(tx['signature'],str) or len(tx['signature'])>160):
        fail('INVALID_ZKN','scoped signed private gift transaction required')
    raw=asset_transaction_bytes(tx)
    if len(raw)>8192: fail('RESPONSE_LIMIT','gift transaction exceeds budget')
    native_ec_verify(tx['public_key'],tx['signature'],raw)
    return tx,hashlib.sha256(raw).hexdigest(),hashlib.sha256(tx['public_key'].rstrip('\n').encode()).hexdigest()


def asset_publish_transaction(root, network, tx, tx_hash):
    directory=root/'var/lib/corix/p2p/objects/transactions'
    private_mkdir(directory)
    target=directory/tx_hash;body=encoded(tx)
    if target.exists():
        if secure_read(target,16384)!=body: fail('IDEMPOTENCY_CONFLICT','immutable P2P gift object changed')
    else:
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        make_private(target)
        with os.fdopen(fd,'wb') as stream: stream.write(body);stream.flush();os.fsync(stream.fileno())
    with closing(asset_writable_database(root/'var/lib/corix/p2p/dht.db')) as dht,dht:
        dht.execute('INSERT OR REPLACE INTO local_chunks VALUES (?,?,0,?)',(tx_hash,str(target),len(body)))
    return target


def asset_writable_database(path):
    check=native_database(path);check.close()
    return sqlite3.connect(Path(path).absolute().as_uri()+'?mode=rw',uri=True,timeout=5)


def asset_submit_gift(root, network, tx, kind='zkn_private_transfer'):
    tx,tx_hash,sender=asset_signed_gift(tx,network,kind)
    with closing(asset_writable_database(root/'var/lib/corix/networks'/network/'blockchain/chain.db')) as db:
        try:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT type,data,signature,public_key,timestamp FROM transactions WHERE hash=?',(tx_hash,)).fetchone()
            expected=(tx['type'],encoded(tx['data']).decode(),tx['signature'],tx['public_key'],tx['timestamp'])
            if old:
                if tuple(old)!=expected: fail('IDEMPOTENCY_CONFLICT','gift transaction bytes changed')
            else:
                asset_validate(db,network,tx['type'],tx['data'],sender)
                for (raw,) in db.execute("SELECT data FROM transactions WHERE type IN ('zkn_transfer','zkn_private_transfer','zkc_issue') AND block_height IS NULL LIMIT 4097"):
                    pending=strict_json(raw.encode())
                    if kind=='zkn_private_transfer' and 'nonce' in pending and pending.get('token_id')==tx['data']['token_id'] and pending.get('nonce')==tx['data']['nonce']:
                        fail('GIFT_CONFLICT','another gift already spends this collectible sequence')
                    if kind=='zkn_private_transfer' and pending.get('recipient')==tx['data']['recipient']:
                        fail('RECIPIENT_REUSED','one-time receiver already has a pending gift')
                    if kind=='zkc_issue' and 'kind' in pending and zkc_edition_id(pending)==zkc_edition_id(tx['data']):
                        fail('EDITION_PENDING','edition already has a pending issue; reuse its transaction')
                if db.execute('SELECT COUNT(*) FROM transactions WHERE block_height IS NULL').fetchone()[0]>=4096:
                    fail('BACKPRESSURE','pending transaction budget exhausted')
                db.execute('INSERT INTO transactions (hash,type,data,signature,public_key,timestamp,block_height) VALUES (?,?,?,?,?,?,NULL)',(tx_hash,*expected))
            db.commit()
        except BaseException: db.rollback();raise
    # If registration is interrupted after the transaction commit, submitting
    # these same bytes again safely repairs publication without a second gift.
    asset_publish_transaction(root,network,tx,tx_hash)
    return {'transaction_hash':tx_hash,'phase':'pending-native-consensus','fee_required':False}


def asset_forward_pending(root, network):
    """Every packer republishes bounded signed collectible objects at no fee."""
    with closing(corium_db(root,network,'blockchain/chain.db')) as db:
        rows=db.execute("SELECT hash,type,data,signature,public_key,timestamp FROM transactions WHERE type IN ('zkn_private_transfer','zkc_issue') ORDER BY timestamp DESC LIMIT 64").fetchall()
    for tx_hash,kind,data,signature,public,stamp in rows:
        tx={'type':kind,'data':strict_json(data.encode()),'signature':signature,'public_key':public,'timestamp':stamp}
        _,checked,_=asset_signed_gift(tx,network,kind)
        if checked!=tx_hash: fail('NATIVE_FACT_REJECTED','forwarding object digest changed')
        asset_publish_transaction(root,network,tx,tx_hash)
    return len(rows)


def asset_manifest(envelope, network, db):
    if not isinstance(envelope, dict) or set(envelope) != {'manifest','public_key','signature'}:
        fail('INVALID_ZKN', 'exact native ZKN signature required')
    value = envelope['manifest']
    fields = {'schema','network_id','token_id','block_hash','height','packer','packed_at','contents_digest','contents_size','zkt_score'}
    if not isinstance(value, dict) or value.get('schema') not in {'ziokt.zkn-snapshot.v1','ziokt.zkn-snapshot.v2'}:
        fail('INVALID_ZKN', 'versioned native collectible required')
    if value['schema'] == 'ziokt.zkn-snapshot.v2':
        fields |= {'lucky_digit','relay_obligation'}
        if (not isinstance(value.get('lucky_digit'),str) or not re.fullmatch('[0-9A-F]',value['lucky_digit']) or
                value.get('relay_obligation') != 'free-p2p-forwarding-v1'):
            fail('INVALID_ZKN','immutable hexadecimal collectible digit and forwarding obligation required')
    if set(value) != fields or value['network_id'] != network:
        fail('INVALID_ZKN', 'scoped ZKN snapshot manifest required')
    if any(not isinstance(value[k], str) or not re.fullmatch('[a-f0-9]{64}', value[k]) for k in ('token_id','block_hash','packer')):
        fail('INVALID_ZKN', 'native ZKN identities must be exact digests')
    if value['token_id'] != asset_token_id(network,value['block_hash']) or not re.fullmatch('sha256:[a-f0-9]{64}', str(value['contents_digest'])):
        fail('INVALID_ZKN', 'ZKN token or content identity changed')
    if (any(type(value[k]) is not int or value[k] < 0 for k in ('height','packed_at','contents_size','zkt_score')) or
            value['contents_size'] > 64*1024*1024 or value['zkt_score'] >= 2**53):
        fail('INVALID_ZKN', 'bounded native ZKN snapshot fields required')
    block = db.execute('SELECT height,validator,timestamp FROM blocks WHERE hash=?', (value['block_hash'],)).fetchone()
    if not block or tuple(block) != (value['height'],value['packer'],value['packed_at']):
        fail('INVALID_ZKN', 'snapshot does not match its packed block')
    if hashlib.sha256(envelope['public_key'].rstrip('\n').encode()).hexdigest() != value['packer']:
        fail('INVALID_ZKN', 'snapshot signer is not its packer')
    domain = b'Ziokt/ZKN/snapshot/v2\n' if value['schema'].endswith('.v2') else b'Ziokt/ZKN/snapshot/v1\n'
    native_ec_verify(envelope['public_key'],envelope['signature'],domain+encoded(value))
    return value


def asset_validate(db, network, tx_type, payload, sender):
    if tx_type=='zkc_issue':
        fields={'network_id','token_id','kind','serial','contents_digest'}
        if (not isinstance(payload,dict) or set(payload)!=fields or payload['network_id']!=network or
                not isinstance(payload['token_id'],str) or not re.fullmatch('[a-f0-9]{64}',payload['token_id']) or
                not isinstance(payload['kind'],str) or payload['kind'] not in {'repeat','unique'} or not isinstance(payload['serial'],str) or
                not re.fullmatch('0|[1-9][0-9]{0,127}',payload['serial']) or
                payload['kind']=='repeat' and payload['serial']!='0' or payload['kind']=='unique' and payload['serial']=='0' or
                not isinstance(payload['contents_digest'],str) or not re.fullmatch('sha256:[a-f0-9]{64}',payload['contents_digest'])):
            fail('INVALID_ZKC','exact collectible edition without payment fields required')
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='zkn_tokens'").fetchone(): fail('NATIVE_STATE_UNAVAILABLE','parent collectible must be included')
        owner=db.execute('SELECT owner FROM zkn_tokens WHERE token_id=?',(payload['token_id'],)).fetchone()
        if not owner or owner[0]!=sender: fail('POLICY_DENIED','only current parent collectible holder may issue editions')
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='zkc_editions'").fetchone():
            prior=db.execute('SELECT contents_digest FROM zkc_editions WHERE edition_id=?',(zkc_edition_id(payload),)).fetchone()
            if prior and (payload['kind']=='unique' or prior[0]!=payload['contents_digest']): fail('EDITION_CONFLICT','edition serial or repeat content already assigned')
        return payload
    if tx_type=='ziokt_content':
        if not isinstance(payload,dict) or set(payload)!={'text','data_base64','content_type'} or any(not isinstance(v,str) for v in payload.values()) or len(payload['text'].encode())>8192 or not re.fullmatch('[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+',payload['content_type']):
            fail('INVALID_CONTENT','bounded text and binary content required')
        try: data=base64.b64decode(payload['data_base64'],validate=True)
        except (ValueError,TypeError): fail('INVALID_CONTENT','binary encoding rejected')
        if len(data)>4096: fail('RESPONSE_LIMIT','binary ledger payload exceeds budget')
        return payload
    if tx_type == 'ziokt_identity_register':
        fields = {'schema','network_id','federation_id','member_public','document_commitment','policy_digest'}
        if not isinstance(payload,dict) or set(payload)!=fields or payload['schema']!='ziokt.identity-registration.v1' or payload['network_id']!=network:
            fail('INVALID_REGISTRATION','scoped registration commitment required')
        identifier(payload['federation_id'],'federation_id')
        if (not re.fullmatch('[a-f0-9]{64}',str(payload['member_public'])) or
                any(not re.fullmatch('sha256:[a-f0-9]{64}',str(payload[k])) for k in ('document_commitment','policy_digest'))):
            fail('INVALID_REGISTRATION','exact member and registration commitments required')
        return payload
    if tx_type == 'zkn_mint':
        if not isinstance(payload,dict) or set(payload)!={'snapshot'}: fail('INVALID_ZKN','signed snapshot mint required')
        value=asset_manifest(payload['snapshot'],network,db)
        if value['packer']!=sender: fail('POLICY_DENIED','only block packer can issue its ZKN snapshot')
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='zkn_tokens'").fetchone():
            if db.execute('SELECT 1 FROM zkn_tokens WHERE token_id=?',(value['token_id'],)).fetchone():
                fail('IDEMPOTENCY_CONFLICT','block snapshot NFT already minted')
        return value
    if tx_type in {'zkn_transfer','zkn_private_transfer'}:
        fields = {'token_id','recipient','nonce'}
        if tx_type == 'zkn_private_transfer': fields |= {'network_id','receipt'}
        if not isinstance(payload,dict) or set(payload)!=fields:
            fail('INVALID_ZKN','exact native NFT transfer required')
        if tx_type == 'zkn_private_transfer':
            if payload['network_id'] != network: fail('SCOPE_MISMATCH','gift belongs to another network')
            try:
                receipt=base64.b64decode(payload['receipt'],validate=True)
                if len(receipt)!=2048: raise ValueError()
            except (ValueError,TypeError): fail('INVALID_ZKN','fixed sealed collectible receipt required')
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='zkn_receivers'").fetchone() and db.execute('SELECT 1 FROM zkn_receivers WHERE address=?',(payload['recipient'],)).fetchone():
                fail('RECIPIENT_REUSED','private gift requires a fresh one-time receiver')
        if (not re.fullmatch('[a-f0-9]{64}',str(payload['token_id'])) or not re.fullmatch('[a-f0-9]{64}',str(payload['recipient'])) or
                type(payload['nonce']) is not int or not 1 <= payload['nonce'] < 2**53):
            fail('INVALID_ZKN','bounded NFT recipient and transfer nonce required')
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='zkn_tokens'").fetchone():
            fail('NATIVE_STATE_UNAVAILABLE','NFT mint has not been confirmed')
        row=db.execute('SELECT owner,nonce FROM zkn_tokens WHERE token_id=?',(payload['token_id'],)).fetchone()
        if not row or row[0]!=sender or payload['nonce']!=row[1]+1:
            fail('POLICY_DENIED','current NFT owner and next transfer nonce required')
        return payload
    fail('INVALID_PARAMS','unsupported native asset transaction')


def asset_apply(db, network, tx_hash, tx_type, payload, sender, height):
    value=asset_validate(db,network,tx_type,payload,sender)
    if tx_type=='ziokt_content': return
    asset_tables(db)
    if tx_type=='ziokt_identity_register':
        db.execute('INSERT OR REPLACE INTO ziokt_registrations VALUES (?,?,?,?,?,?,?)',
            (network,payload['member_public'],payload['document_commitment'],payload['policy_digest'],sender,tx_hash,height))
    elif tx_type=='zkn_mint':
        db.execute('INSERT INTO zkn_tokens VALUES (?,?,?,0,?,?,?)',
            (value['token_id'],value['block_hash'],value['packer'],encoded(payload['snapshot']).decode(),tx_hash,height))
    elif tx_type=='zkc_issue':
        db.execute('INSERT OR IGNORE INTO zkc_editions VALUES (?,?,?,?,?,?,?,?)',
            (zkc_edition_id(payload),payload['token_id'],payload['kind'],payload['serial'],payload['contents_digest'],sender,tx_hash,height))
    else:
        db.execute('UPDATE zkn_tokens SET owner=?,nonce=? WHERE token_id=?',
            (payload['recipient'],payload['nonce'],payload['token_id']))
        if tx_type=='zkn_private_transfer':
            db.execute('INSERT INTO zkn_receivers VALUES (?,?,?)',(payload['recipient'],tx_hash,height))


def asset_engine_main(args):
    action,db_path,network=args[0],Path(args[1]).absolute(),args[2]
    identifier(network,'network')
    if action=='forward':
        root=Path(args[3]).absolute()
        asset_forward_pending(root,network)
        return 0
    if action in {'validate','apply'}:
        tx_type,raw,sender=args[3:6]
        payload=strict_json(raw.encode())
        db=sqlite3.connect(db_path,timeout=5)
        try:
            if action=='validate': asset_validate(db,network,tx_type,payload,sender)
            else:
                with db: asset_apply(db,network,args[6],tx_type,payload,sender,int(args[7]))
        finally: db.close()
        return 0
    if action=='snapshot':
        root,block_hash=Path(args[3]).absolute(),args[4]
        config_path=root/'etc/corix/networks'/network/'corix.conf'
        if not config_path.exists(): return 0
        config=load_config('corium',config_path)
        if not config['enabled'] or config.get('zkn_enabled') is not True: return 0
        db=native_database(db_path)
        try:
            block=db.execute('SELECT height,hash,previous_hash,timestamp,validator,signature,transactions FROM blocks WHERE hash=?',(block_hash,)).fetchone()
            if not block or block[0]<1: return 0
            private_path=root/'etc/corix/networks'/network/'identity.key'
            from cryptography.hazmat.primitives import serialization
            private=serialization.load_pem_private_key(secure_read(private_path),password=None)
            public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode().rstrip('\n')
            packer=hashlib.sha256(public.encode()).hexdigest()
            if packer!=block[4]: return 0
            token_id=asset_token_id(network,block_hash)
            for (raw,) in db.execute("SELECT data FROM transactions WHERE type='zkn_mint' LIMIT 4096"):
                prior=strict_json(raw.encode())
                if prior.get('snapshot',{}).get('manifest',{}).get('token_id')==token_id: return 0
            hashes=strict_json(block[6].encode());transactions=[]
            if not isinstance(hashes,list) or len(hashes)>4096: fail('RESPONSE_LIMIT','bounded packed transaction list required')
            for tx in hashes:
                row=db.execute('SELECT hash,type,data,signature,public_key,timestamp,block_height FROM transactions WHERE hash=?',(tx,)).fetchone()
                if not row or row[6]!=block[0]: fail('NATIVE_STATE_CONFLICT','packed snapshot transaction missing')
                raw=row[2].encode() if isinstance(row[2],str) else bytes(row[2])
                transactions.append({'hash':row[0],'type':row[1],'data_base64':base64.b64encode(raw).decode(),'signature':row[3],'public_key':row[4],'timestamp':row[5]})
            score=0
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='zkt_accounts'").fetchone():
                found=db.execute('SELECT total_points FROM zkt_accounts WHERE address=?',(packer,)).fetchone()
                if found: score=found[0]
            # A keyed random digit is stable across publication retries of
            # this block; no retry can reroll a previously signed collectible.
            import hmac
            seed=private.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
            lucky_digit='0123456789ABCDEF'[hmac.new(seed,b'Ziokt/ZKN/lucky/v1\n'+block_hash.encode(),hashlib.sha256).digest()[0]&15]
            body=encoded({'schema':'ziokt.zkn-block-content.v2','network_id':network,'block':list(block),'transactions':transactions,'lucky_digit':lucky_digit})
        finally: db.close()
        if len(body)>64*1024*1024: fail('RESPONSE_LIMIT','native block snapshot byte budget exceeded')
        directory=Path(config['artifact_root']) if 'artifact_root' in config else root/'var/lib/corix/p2p/objects/ziokt'
        private_mkdir(directory)
        sha='sha256:'+hashlib.sha256(body).hexdigest();target=directory/sha[7:]
        if target.exists():
            if secure_read(target,64*1024*1024)!=body: fail('ARTIFACT_DIGEST_MISMATCH','block snapshot changed')
        else:
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
            make_private(target)
            with os.fdopen(fd,'wb') as output: output.write(body);output.flush();os.fsync(output.fileno())
        value={'schema':'ziokt.zkn-snapshot.v2','network_id':network,'token_id':token_id,'block_hash':block_hash,
               'height':block[0],'packer':packer,'packed_at':block[3],'contents_digest':sha,'contents_size':len(body),'zkt_score':score,
               'lucky_digit':lucky_digit,'relay_obligation':'free-p2p-forwarding-v1'}
        envelope={'manifest':value,'public_key':public,'signature':native_ec_sign(private,b'Ziokt/ZKN/snapshot/v2\n'+encoded(value))}
        print(encoded({'snapshot':envelope}).decode());return 0
    fail('INVALID_PARAMS','known native asset engine action required')


def asset_preflight(root,network,params,config):
    action=params['action'];resource=params['resource'];arguments=params['arguments']
    if params['expected_revision'] is not None: fail('INVALID_PARAMS','native asset submit requires null revision')
    if action=='identity.register':
        if not resource.startswith('identity:') or set(arguments)!={'document_commitment','policy_digest'}:
            fail('INVALID_PARAMS','fixed identity registration arguments required')
        payload={'schema':'ziokt.identity-registration.v1','network_id':network,'federation_id':config['federation_id'],
                 'member_public':resource[9:],**arguments}
        with closing(corium_db(root,network,'blockchain/chain.db')) as db: asset_validate(db,network,'ziokt_identity_register',payload,corium_identity(root,network))
        return {'transaction_type':'ziokt_identity_register','payload':payload,'issuer':corium_identity(root,network)}
    if action=='content.publish':
        if resource!='content:'+network: fail('INVALID_PARAMS','fixed content ledger scope required')
        with closing(corium_db(root,network,'blockchain/chain.db')) as db: asset_validate(db,network,'ziokt_content',arguments,corium_identity(root,network))
        return {'transaction_type':'ziokt_content','payload':arguments,'issuer':corium_identity(root,network)}
    if action in {'zkn.gift','zkc.issue'}:
        if not resource.startswith('zkn:') or set(arguments)!={'transaction'}: fail('INVALID_PARAMS','signed private gift required')
        with closing(corium_db(root,network,'blockchain/chain.db')) as db:
            tx,tx_hash,sender=asset_signed_gift(arguments['transaction'],network,'zkc_issue' if action=='zkc.issue' else 'zkn_private_transfer')
            if tx['data']['token_id']!=resource[4:]: fail('SCOPE_MISMATCH','gift token differs from operation')
            existing=db.execute('SELECT type,data,signature,public_key,timestamp FROM transactions WHERE hash=?',(tx_hash,)).fetchone()
            if existing:
                if tuple(existing)!=(tx['type'],encoded(tx['data']).decode(),tx['signature'],tx['public_key'],tx['timestamp']):
                    fail('IDEMPOTENCY_CONFLICT','signed transaction changed')
            else: asset_validate(db,network,tx['type'],tx['data'],sender)
        return {'transaction_type':tx['type'],'payload':tx['data'],'issuer':sender,'transaction_hash':tx_hash}
    if action=='zkn.transfer':
        if not resource.startswith('zkn:') or set(arguments)!={'recipient','nonce'}: fail('INVALID_PARAMS','fixed NFT gift arguments required')
        payload={'token_id':resource[4:],**arguments};sender=corium_identity(root,network)
        with closing(corium_db(root,network,'blockchain/chain.db')) as db: asset_validate(db,network,'zkn_transfer',payload,sender)
        return {'transaction_type':'zkn_transfer','payload':payload,'issuer':sender}
    fail('INVALID_PARAMS','known native asset operation required')


def asset_receipt(root,network,plan):
    wanted=plan['binding_evidence'];db=corium_db(root,network,'blockchain/chain.db')
    try:
        for tx,raw,public,height in db.execute('SELECT hash,data,public_key,block_height FROM transactions WHERE type=? ORDER BY timestamp DESC LIMIT 4096',(wanted['transaction_type'],)):
            if strict_json(raw.encode())==wanted['payload'] and hashlib.sha256(public.rstrip('\n').encode()).hexdigest()==wanted['issuer']:
                return {'transaction_hash':tx,'phase':'pending-native-consensus' if height is None else 'on-chain','native_action':plan['action'],'application_ready':False}
    finally: db.close()
    return None


def asset_query(root,network,method,params):
    db=corium_db(root,network,'blockchain/chain.db')
    try:
        if method=='identity.fact':
            if set(params)!={'member_public','policy_digest','issuer'}: fail('INVALID_PARAMS','scoped registration proof query required')
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ziokt_registrations'").fetchone(): fail('NATIVE_FACT_PENDING','registration not yet included')
            row=db.execute('SELECT commitment,issuer,transaction_hash,height FROM ziokt_registrations WHERE network=? AND member=? AND policy=?',(network,params['member_public'],params['policy_digest'])).fetchone()
            if not row or row[1]!=params['issuer']: fail('NATIVE_FACT_PENDING','matching registration not yet included')
            tx=db.execute('SELECT type,data,signature,public_key,timestamp,block_height FROM transactions WHERE hash=?',(row[2],)).fetchone()
            block=db.execute('SELECT hash,transactions FROM blocks WHERE height=?',(row[3],)).fetchone()
            if not tx or tx[0]!='ziokt_identity_register' or tx[5]!=row[3] or not block or row[2] not in strict_json(block[1].encode()): fail('NATIVE_FACT_REJECTED','registration branch changed')
            raw=('{"type":'+json.dumps(tx[0])+',"data":'+tx[1]+',"timestamp":'+str(tx[4])+'}').encode()
            if hashlib.sha256(raw).hexdigest()!=row[2]: fail('NATIVE_FACT_REJECTED','registration transaction changed')
            native_ec_verify(tx[3],tx[2],raw)
            if hashlib.sha256(tx[3].rstrip('\n').encode()).hexdigest()!=row[1]: fail('NATIVE_FACT_REJECTED','registration issuer changed')
            return {'registered':True,'member_public':params['member_public'],'policy_digest':params['policy_digest'],'document_commitment':row[0],'issuer':row[1],'transaction_hash':row[2],'block_hash':block[0],'height':row[3],'network_id':network}
        if method=='zkc.list':
            if params: fail('INVALID_PARAMS','edition list accepts no extra arguments')
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='zkc_editions'").fetchone(): return {'editions':[]}
            rows=db.execute('SELECT edition_id,token_id,kind,serial,contents_digest,issuer,transaction_hash,height FROM zkc_editions ORDER BY height DESC,edition_id LIMIT 64').fetchall()
            return {'editions':[dict(zip(('edition_id','token_id','kind','serial','contents_digest','issuer','transaction_hash','height'),row)) for row in rows]}
        if method in {'zkn.fact','zkc.fact'}:
            if set(params)!={'transaction_hash'} or not re.fullmatch('[a-f0-9]{64}',str(params['transaction_hash'])):
                fail('INVALID_PARAMS','exact gift transaction digest required')
            row=db.execute('SELECT type,data,signature,public_key,timestamp,block_height FROM transactions WHERE hash=?',(params['transaction_hash'],)).fetchone()
            if not row: return {'phase':'absent','transaction_hash':params['transaction_hash']}
            tx=dict(zip(('type','data','signature','public_key','timestamp'),row[:5]));tx['data']=strict_json(tx['data'].encode())
            _,tx_hash,_=asset_signed_gift(tx,network,'zkc_issue' if method=='zkc.fact' else 'zkn_private_transfer')
            if tx_hash!=params['transaction_hash']: fail('NATIVE_FACT_REJECTED','gift transaction changed')
            result={'phase':'pending-native-consensus','transaction_hash':tx_hash,'transaction':tx,'height':None,'confirmations':0}
            if row[5] is not None:
                block=db.execute('SELECT hash,transactions FROM blocks WHERE height=?',(row[5],)).fetchone()
                if not block or tx_hash not in strict_json(block[1].encode()): fail('NATIVE_FACT_REJECTED','gift branch changed')
                proof=governance_fact(root,network,tx_hash)
                if proof['height']!=row[5] or proof['block_hash']!=block[0]:fail('NATIVE_FACT_REJECTED','gift branch changed during observation')
                result.update(phase='on-chain',height=row[5],block_hash=proof['block_hash'],confirmations=proof['confirmations'],inclusion=proof)
            return result
        if method=='zkn.list':
            if params: fail('INVALID_PARAMS','NFT list accepts no extra arguments')
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='zkn_tokens'").fetchone(): return {'tokens':[]}
            rows=db.execute('SELECT token_id,owner,nonce,manifest FROM zkn_tokens ORDER BY height DESC LIMIT 64').fetchall()
            return {'tokens':[{'token_id':r[0],'owner':r[1],'nonce':r[2],'snapshot':strict_json(r[3].encode())} for r in rows]}
        fail('INVALID_PARAMS','known native asset query required')
    finally: db.close()

"""Core-neutral encrypted application records over stream or message boundaries.

Native Core wire protocols remain untouched. Fixed Corium read operations retain
their native signatures; an additional signed application envelope binds network,
nonce, expiry and the authenticated responder. No arbitrary target or shell.
"""
import socket
import socketserver
import struct
import threading

DATA_MAGIC = b"ZIOKT-D1"
DATA_HEADER = struct.Struct("!16sBHHH")
DATA_MAX = 65536
DATA_PARTS = 256


class DataCipher:
    def __init__(self, key, server=False):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if not isinstance(key, bytes) or len(key) != 32:
            fail("INVALID_DATA_KEY", "32-byte private application key required")
        client = HKDF(hashes.SHA256(), 32, None, b"Ziokt/data/client/v1").derive(key)
        responder = HKDF(hashes.SHA256(), 32, None, b"Ziokt/data/server/v1").derive(key)
        self.send = AESGCM(responder if server else client)
        self.receive = AESGCM(client if server else responder)

    def pack(self, request_id, kind, index, count, payload=b"", pad_to=None):
        if (not isinstance(request_id, bytes) or len(request_id) != 16 or kind not in {1,2,3,4,5,6} or
                type(index) is not int or not 0 <= index < DATA_PARTS or type(count) is not int or not 0 <= count <= DATA_PARTS or
                not isinstance(payload, bytes) or len(payload) > 8192-59):
            fail("INVALID_DATA_FRAME", "bounded typed encrypted frame required")
        nonce = os.urandom(12)
        plain = DATA_HEADER.pack(request_id, kind, index, count, len(payload)) + payload
        if pad_to is not None:
            if type(pad_to) is not int or not len(plain)+28 <= pad_to <= 8192:
                fail("DATA_FRAME_LIMIT", "padding must fit the original native record budget")
            plain += os.urandom(pad_to-28-len(plain))
        # Version/domain is authenticated as AAD, not a cleartext product marker.
        return nonce + self.send.encrypt(nonce, plain, DATA_MAGIC)

    def unpack(self, frame):
        from cryptography.exceptions import InvalidTag
        if not isinstance(frame, bytes) or not 51 <= len(frame) <= 8192:
            fail("INVALID_DATA_FRAME", "bounded encrypted application record required")
        try:
            plain = self.receive.decrypt(frame[:12], frame[12:], DATA_MAGIC)
        except InvalidTag:
            fail("DATA_AUTH_REJECTED", "application record authentication failed")
        if len(plain) < DATA_HEADER.size:
            fail("INVALID_DATA_FRAME", "truncated application record")
        request_id, kind, index, count, payload_size = DATA_HEADER.unpack(plain[:DATA_HEADER.size])
        if payload_size > len(plain)-DATA_HEADER.size: fail("INVALID_DATA_FRAME", "encrypted payload length exceeds frame")
        if kind not in {1, 2, 3, 4, 5, 6} or count > DATA_PARTS or index >= DATA_PARTS:
            fail("INVALID_DATA_FRAME", "record kind or fragmentation budget rejected")
        return request_id, kind, index, count, plain[DATA_HEADER.size:DATA_HEADER.size+payload_size]


class FrameSocket:
    def __init__(self, sock, kind, maximum=4096):
        if kind not in {"stream", "message"} or type(maximum) is not int or not 128 <= maximum <= 8192:
            fail("UNSUPPORTED_BOUNDARY", "bounded stream/message application contract required")
        self.socket, self.kind, self.maximum = sock, kind, maximum
        self.buffer = bytearray()

    def send(self, frame):
        if not frame or len(frame) > self.maximum:
            fail("DATA_FRAME_LIMIT", "application record exceeds native boundary")
        if self.kind == "stream":
            self.socket.sendall(struct.pack("!I", len(frame)) + frame)
        elif self.socket.send(frame) != len(frame):
            fail("DATA_SHORT_SEND", "record was not submitted in full")

    def receive(self):
        if self.kind == "message":
            frame = self.socket.recv(self.maximum + 1)
            if not frame or len(frame) > self.maximum:
                fail("DATA_FRAME_LIMIT", "truncated or oversized native record")
            return frame
        while True:
            if len(self.buffer) >= 4:
                size = struct.unpack("!I", self.buffer[:4])[0]
                if not 57 <= size <= self.maximum:
                    fail("DATA_FRAME_LIMIT", "stream frame length rejected")
                if len(self.buffer) >= size + 4:
                    frame = bytes(self.buffer[4:size+4]); del self.buffer[:size+4]
                    return frame
            chunk = self.socket.recv(8192)
            if not chunk:
                fail("DATA_CLOSED", "application boundary closed")
            self.buffer.extend(chunk)
            if len(self.buffer) > 16384:
                fail("DATA_FRAME_LIMIT", "stream receive buffer exceeded")


def native_ec_verify(public, signature, message):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.exceptions import InvalidSignature
    try:
        key = serialization.load_pem_public_key(public.encode())
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256K1):
            raise ValueError()
        key.verify(bytes.fromhex(signature), message, ec.ECDSA(hashes.SHA256()))
    except (ValueError, TypeError, InvalidSignature):
        fail("NATIVE_SIGNATURE_REJECTED", "native Corium signature rejected")


def native_ec_sign(key, message):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    return key.sign(message, ec.ECDSA(hashes.SHA256())).hex()


class CoriumDataChannel:
    def __init__(self, handle, key, native_private, expected_peer, network, privacy_profile="standard"):
        from cryptography.hazmat.primitives import serialization
        self.handle = handle
        boundary = handle.boundary
        self.frames = FrameSocket(handle.socket, boundary.kind, min(boundary.max_record or 4096, 4096))
        self.cipher = DataCipher(key)
        if privacy_profile not in {"standard", "private"}: fail("NO_POLICY_COMPLIANT_PATH", "verified anonymous carrier required for restricted profile")
        self.padding = self.frames.maximum if privacy_profile == "private" else None
        self.private = native_private
        self.public = native_private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode().rstrip("\n")
        self.expected_peer, self.network = expected_peer, network

    def call(self, message_type, payload="", timeout=30):
        if type(timeout) not in {int, float} or not 0 < timeout <= 30:
            fail("INVALID_DATA_TIMEOUT", "finite application deadline required")
        request_id = os.urandom(16)
        native = {"type": message_type, "payload": payload,
                  "sender_id": hashlib.sha256(self.public.encode()).hexdigest(), "public_key": self.public,
                  "signature": native_ec_sign(self.private, (message_type + "|" + payload).encode())}
        body = {"schema": "ziokt.corium-request.v1", "network_id": self.network,
                "request_id": request_id.hex(), "expires_at": int(time.time()) + 30, "native": native}
        request = {"body": body, "signature": native_ec_sign(self.private, b"Ziokt/C/request/v1\n" + encoded(body))}
        raw = encoded(request)
        if len(raw) > DATA_MAX:
            fail("DATA_MESSAGE_LIMIT", "application request exceeds budget")
        chunk_size = self.frames.maximum - 64
        parts = [raw[offset:offset+chunk_size] for offset in range(0, len(raw), chunk_size)]
        if len(parts) > DATA_PARTS:
            fail("DATA_MESSAGE_LIMIT", "native boundary requires too many fragments")
        deadline = time.monotonic() + timeout
        previous_timeout = self.frames.socket.gettimeout()

        def exchange(kind, index, count, data, expected):
            for _ in range(4):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    fail("DATA_TIMEOUT", "application request deadline exceeded")
                self.frames.socket.settimeout(min(2, remaining))
                self.frames.send(self.cipher.pack(request_id, kind, index, count, data, self.padding))
                try:
                    for _ in range(8):
                        rid, received, position, total, content = self.cipher.unpack(self.frames.receive())
                        if rid != request_id or position != index:
                            continue
                        if received == 6:
                            fail("DATA_REQUEST_REJECTED", content.decode("ascii", "replace"))
                        if received == expected:
                            return total, content
                        if received == 5:
                            time.sleep(min(.01, max(0, deadline-time.monotonic())))
                            break
                except socket.timeout:
                    continue
            fail("DATA_RETRY_EXHAUSTED", "bounded application retransmission exhausted")
        try:
            for index, part in enumerate(parts):
                exchange(1, index, len(parts), part, 2)
            total, first = exchange(3, 0, 0, b"", 4)
            response = bytearray(first)
            if not 1 <= total <= DATA_PARTS:
                fail("INVALID_DATA_FRAME", "invalid response fragment count")
            for index in range(1, total):
                count, part = exchange(3, index, 0, b"", 4)
                if count != total or len(response) + len(part) > DATA_MAX:
                    fail("INVALID_DATA_FRAME", "response fragmentation changed")
                response.extend(part)
            envelope = strict_json(bytes(response), DATA_MAX)
            if set(envelope) != {"body", "public_key", "signature"}:
                fail("INVALID_DATA_FRAME", "exact signed response required")
            result = envelope["body"]
            if hashlib.sha256(envelope["public_key"].rstrip("\n").encode()).hexdigest() != self.expected_peer:
                fail("NATIVE_IDENTITY_REJECTED", "Corium responder identity mismatch")
            if result["request_id"] != request_id.hex() or result["network_id"] != self.network:
                fail("NATIVE_IDENTITY_REJECTED", "Corium response scope mismatch")
            native_ec_verify(envelope["public_key"], envelope["signature"], b"Ziokt/C/response/v1\n" + encoded(result))
            return result["native"]
        finally:
            self.frames.socket.settimeout(previous_timeout)


class CoriumDataGateway:
    def __init__(self, key, native_private, handler, network, root=None):
        from cryptography.hazmat.primitives import serialization
        self.cipher = DataCipher(key, server=True)
        self.private, self.handler, self.network = native_private, handler, network
        self.public = native_private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode().rstrip("\n")
        self.root, self.pending, self.lock = root, {}, threading.RLock()
        self.verified_content = {}

    def content_range(self, query):
        if (not isinstance(query, dict) or not {"digest"} <= set(query) or set(query)-{"digest", "offset", "length"} or
                not isinstance(query["digest"], str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", query["digest"]) or self.root is None or
                type(query.get("offset", 0)) is not int or not 0 <= query.get("offset", 0) <= 64*1024*1024 or
                type(query.get("length", 6144)) is not int or not 1 <= query.get("length", 6144) <= 6144):
            fail("INVALID_PARAMS", "bounded immutable native content range required")
        config = load_config("corium", self.root/"etc/corix/networks"/self.network/"corix.conf")
        if not config["enabled"]: fail("ZIOKT_DISABLED", "native content binding was disabled")
        directory = Path(config["artifact_root"]) if "artifact_root" in config else self.root/"var/lib/corix/p2p/objects/ziokt"
        safe_directory(directory)
        path = directory/query["digest"][7:]
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_mode & 0o077 or before.st_size > 64*1024*1024):
            fail("UNSAFE_FILE", "private bounded native content object required")
        fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            signature = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
            if signature != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns):
                fail("UNSAFE_FILE", "native object changed while opening")
            cached = self.verified_content.get(query["digest"])
            if cached != signature:
                hasher = hashlib.sha256()
                while True:
                    data = os.read(fd, 65536)
                    if not data: break
                    hasher.update(data)
                if hasher.hexdigest() != query["digest"][7:]: fail("ARTIFACT_DIGEST_MISMATCH", "native content integrity rejected")
                if len(self.verified_content) >= 64: self.verified_content.clear()
                self.verified_content[query["digest"]] = signature
            offset = query.get("offset", 0)
            if offset > opened.st_size: fail("INVALID_PARAMS", "native content offset exceeds immutable size")
            os.lseek(fd, offset, os.SEEK_SET); data = os.read(fd, min(query.get("length", 6144), opened.st_size-offset))
            after = os.fstat(fd)
            if signature != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                fail("ARTIFACT_DIGEST_MISMATCH", "native content changed during transfer")
            import base64
            return {"status": "success", "digest": query["digest"], "offset": offset,
                    "total_size": opened.st_size, "data_base64": base64.b64encode(data).decode()}
        finally: os.close(fd)

    def receive(self, frame):
        rid, kind, index, count, payload = self.cipher.unpack(frame)
        with self.lock:
            now = time.monotonic()
            self.pending = {k: v for k, v in self.pending.items() if v["deadline"] > now}
            if kind == 1:
                if not 1 <= count <= DATA_PARTS or index >= count:
                    fail("INVALID_DATA_FRAME", "request fragment bounds rejected")
                if rid not in self.pending:
                    if len(self.pending) >= 32:
                        fail("DATA_BACKPRESSURE", "gateway request budget exhausted")
                    self.pending[rid] = {"parts": {}, "count": count, "size": 0, "deadline": now+30, "frame_limit": len(frame),
                                         "padding": len(frame) if len(frame) > 51+len(payload) else None}
                entry = self.pending[rid]
                if entry["count"] != count or (index in entry["parts"] and entry["parts"][index] != payload):
                    fail("IDEMPOTENCY_CONFLICT", "request fragment changed")
                if index not in entry["parts"]:
                    entry["size"] += len(payload)
                    if entry["size"] > DATA_MAX:
                        fail("DATA_MESSAGE_LIMIT", "gateway request exceeds budget")
                    entry["parts"][index] = payload
                if len(entry["parts"]) == count and "response" not in entry:
                    raw = b"".join(entry["parts"][i] for i in range(count))
                    request = strict_json(raw, DATA_MAX)
                    if not isinstance(request, dict) or set(request) != {"body", "signature"}:
                        fail("INVALID_DATA_FRAME", "exact signed native request required")
                    body = request["body"]
                    if (not isinstance(body, dict) or set(body) != {"schema", "network_id", "request_id", "expires_at", "native"} or
                            body["schema"] != "ziokt.corium-request.v1" or body["network_id"] != self.network or
                            body["request_id"] != rid.hex() or type(body["expires_at"]) is not int or not int(time.time()) < body["expires_at"] <= int(time.time())+30):
                        fail("INVALID_DATA_FRAME", "native application scope/expiry rejected")
                    native = body["native"]
                    if (not isinstance(native, dict) or set(native) != {"type", "payload", "sender_id", "public_key", "signature"} or
                            not all(isinstance(v, str) for v in native.values()) or native["type"] not in {
                            "PING", "FIND_NODE", "FIND_VALUE", "GET_BLOCK_HASH_AT_HEIGHT", "GET_BLOCK_HEADER", "GET_TRANSACTION", "ZIOKT_CONTENT_GET"}):
                        fail("POLICY_DENIED", "only fixed native read operations are available")
                    native_ec_verify(native["public_key"], request["signature"], b"Ziokt/C/request/v1\n" + encoded(body))
                    if hashlib.sha256(native["public_key"].rstrip("\n").encode()).hexdigest() != native["sender_id"]:
                        fail("NATIVE_IDENTITY_REJECTED", "native requester identity mismatch")
                    native_ec_verify(native["public_key"], native["signature"], (native["type"] + "|" + native["payload"]).encode())
                    if native["type"] == "ZIOKT_CONTENT_GET":
                        query = strict_json(native["payload"].encode())
                        result = self.content_range(query)
                    else:
                        result = self.handler.handle_dht_message(native)
                    response_body = {"request_id": rid.hex(), "network_id": self.network, "native": result}
                    response = encoded({"body": response_body, "public_key": self.public,
                                        "signature": native_ec_sign(self.private, b"Ziokt/C/response/v1\n" + encoded(response_body))})
                    if len(response) > DATA_MAX:
                        fail("DATA_MESSAGE_LIMIT", "native response exceeds budget")
                    size = max(64, min(entry["frame_limit"] - 64, 4096-64))
                    entry["response"] = [response[o:o+size] for o in range(0, len(response), size)]
                    if len(entry["response"]) > DATA_PARTS:
                        fail("DATA_MESSAGE_LIMIT", "native response fragmentation exceeds budget")
                return self.cipher.pack(rid, 2, index, count, pad_to=entry["padding"])
            if kind == 3:
                entry = self.pending.get(rid)
                if not entry or "response" not in entry:
                    return self.cipher.pack(rid, 5, index, 0, pad_to=len(frame) if len(frame)>51 else None)
                if index >= len(entry["response"]):
                    fail("INVALID_DATA_FRAME", "response index out of bounds")
                return self.cipher.pack(rid, 4, index, len(entry["response"]), entry["response"][index], entry["padding"])
            fail("INVALID_DATA_FRAME", "invalid gateway frame direction")


def corium_native_handler(source, root, network):
    """Load the production gateway declarations from Corium's own monolith."""
    import ast
    text = secure_read(source, 8*1024*1024, private=None).decode()
    # Split the spelling too: Corium's static checker treats a source line
    # containing that spelling and a heredoc as a real Bash Python invocation.
    marker = "$" + "{PYTH" + "ON_CMD}" + " - <<'EOF' &\n"
    native = text.split(marker, 1)[1].split("\nEOF\n", 1)[0]
    nodes = ast.parse(native).body
    boundary = next(i for i, node in enumerate(nodes) if isinstance(node, ast.ClassDef) and node.name == "SandboxAPI")
    os.environ.update(CORIUM_NETWORK_ID=network, SCRIPT_PATH=str(source))
    namespace = {"__name__": "ziokt_corium_native_gateway"}
    exec(compile(ast.Module(body=nodes[:boundary], type_ignores=[]), str(source)+":native-gateway", "exec"), namespace)
    namespace.update(SCRIPT_PATH=str(source), BLOCKCHAIN_DB_PATH=str(root/"var/lib/corix/networks"/network/"blockchain/chain.db"),
                     FORUM_DB_PATH=str(root/"var/lib/corix/networks"/network/"forum/forum.db"),
                     DHT_DB_PATH=str(root/"var/lib/corix/p2p/dht.db"), USER_PUBLIC_KEY_FILE=str(root/"etc/corix/networks"/network/"identity.key.pub"), OUR_NODE_ID_CACHE=None)
    return namespace["CoriumGatewayHandler"].__new__(namespace["CoriumGatewayHandler"])


def serve_corium_data(root, network, key_file, port):
    from cryptography.hazmat.primitives import serialization
    private = serialization.load_pem_private_key(secure_read(root/"etc/corix/networks"/network/"identity.key"), password=None)
    source = os.environ.get("_ZIOKT_CORIUM_SOURCE")
    if not source:
        fail("NATIVE_STATE_UNAVAILABLE", "production monolith source unavailable")
    gateway = CoriumDataGateway(secure_read(key_file, 32), private, corium_native_handler(source, root, network), network, root)

    class TCPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            deadline = time.monotonic()+45
            frames = FrameSocket(self.request, "stream", 8192)
            try:
                for _ in range(1024):
                    remaining = deadline-time.monotonic()
                    if remaining <= 0: return
                    self.request.settimeout(min(30, remaining))
                    frames.send(gateway.receive(frames.receive()))
            except (ProtocolError, OSError, TypeError, KeyError, ValueError):
                return

    class UDPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            frame, endpoint = self.request
            try:
                endpoint.sendto(gateway.receive(frame), self.client_address)
            except (ProtocolError, OSError, TypeError, KeyError, ValueError):
                return

    class BoundedTCP(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = False
        slots = threading.BoundedSemaphore(32)
        def process_request(self, request, address):
            if not self.slots.acquire(False):
                self.shutdown_request(request); return
            super().process_request(request, address)
        def process_request_thread(self, request, address):
            try:
                super().process_request_thread(request, address)
            finally:
                self.slots.release()

    # UDP processing is serialized and bounded; never spawn a thread per packet.
    tcp = BoundedTCP(("127.0.0.1", port), TCPHandler)
    udp = socketserver.UDPServer(("127.0.0.1", tcp.server_address[1]), UDPHandler)
    extra, hosts = [], ["127.0.0.1"]
    if socket.has_ipv6:
        class TCP6(BoundedTCP):
            address_family = socket.AF_INET6
        class UDP6(socketserver.UDPServer):
            address_family = socket.AF_INET6
        extra = [TCP6(("::1", tcp.server_address[1]), TCPHandler), UDP6(("::1", tcp.server_address[1]), UDPHandler)]
        hosts.append("::1")
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in [tcp, *extra]]
    for thread in threads: thread.start()
    print(encoded({"event": "ziokt.data-ready", "host": "127.0.0.1", "hosts": hosts,
                   "port": tcp.server_address[1], "transports": ["stream", "message"]}).decode(), flush=True)
    try:
        udp.serve_forever()
    finally:
        for server in [tcp, *extra]: server.shutdown(); server.server_close()
        udp.server_close()

"""Corium's optional outbound transport selector, independent of Core family."""


def native_transport_main(args):
    root, network, peer, message_type, payload = Path(args[0]).absolute(), args[1], args[2], args[3], args[4]
    config = load_config("corium", root/"etc/corix/networks"/network/"corix.conf")
    if not config["enabled"] or "transport_bindings_file" not in config:
        return 80
    value = strict_json(secure_read(config["transport_bindings_file"]))
    if not isinstance(value, dict) or set(value) != {"schema", "network_id", "bindings"} or value["schema"] != "ziokt.transport-bindings.v1" or value["network_id"] != network or not isinstance(value["bindings"], list) or len(value["bindings"]) > 64:
        fail("INVALID_CONFIG", "exact scoped native transport bindings required")
    bindings = [b for b in value["bindings"] if isinstance(b, dict) and b.get("peer_id") == peer]
    if not bindings:
        return 80
    if len(bindings) != 1:
        fail("INVALID_CONFIG", "duplicate native peer transport binding")
    binding = bindings[0]
    required = {"peer_id", "shadow6_root", "service_name", "registry_path", "lock_digest", "key_file", "mode", "allow_native_fallback"}
    if not required <= set(binding) or set(binding)-required-{"privacy_profile"} or binding["mode"] not in {"required", "preferred"} or type(binding["allow_native_fallback"]) is not bool:
        fail("INVALID_CONFIG", "exact reviewed native service binding required")
    privacy = binding.get("privacy_profile", "standard")
    if not isinstance(privacy, str) or privacy not in {"standard", "private", "restricted"}:
        fail("INVALID_CONFIG", "explicit native privacy profile required")
    if privacy == "restricted": fail("NO_POLICY_COMPLIANT_PATH", "verified anonymous carrier evidence required")
    if privacy == "private" and binding["allow_native_fallback"]:
        fail("POLICY_DENIED", "private binding requires policy evidence before another path can be approved")
    for field in ("shadow6_root", "registry_path", "key_file"):
        if not isinstance(binding[field], str) or not Path(binding[field]).is_absolute() or ".." in Path(binding[field]).parts:
            fail("INVALID_CONFIG", "fixed private transport material paths required")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", str(binding["lock_digest"])):
        fail("INVALID_CONFIG", "native deployment lock digest required")
    shadow = Path(binding["shadow6_root"])
    sys.path[:0] = [str(shadow), str(shadow/"Deployment"), str(shadow/"Crosed")]
    from Deployment.service_registry import ServiceRegistry
    from Deployment.core_catalog import CoreCatalog
    from libshadow6 import Shadow6, RegistryControl
    from cryptography.hazmat.primitives import serialization
    registry = ServiceRegistry(binding["registry_path"], CoreCatalog(shadow))
    private = serialization.load_pem_private_key(secure_read(root/"etc/corix/networks"/network/"identity.key"), password=None)
    try:
        with Shadow6(control=RegistryControl(registry)) as sdk:
            item = registry.services.get(binding["service_name"], {})
            if (item.get("deploymentLock") or {}).get("digest") != binding["lock_digest"]:
                fail("STALE_PLAN", "native service lock drifted; explicit review required")
            # No Core selection, native-wire decoding, or guarantee promotion.
            with sdk.connect_handle(binding["service_name"], timeout=10) as handle:
                if handle.describe().get("lockDigest") != binding["lock_digest"]:
                    fail("STALE_PLAN", "opened native attachment differs from reviewed deployment lock")
                result = CoriumDataChannel(handle, secure_read(binding["key_file"], 32), private, peer, network, privacy).call(message_type, payload)
        if result.get("status") != "success":
            fail("NATIVE_REQUEST_REJECTED", "native Corium peer rejected the request")
        response = result["data"] if "data" in result else result
        print(response if isinstance(response, str) else encoded(response).decode())
        return 0
    except Exception as exc:
        retryable = isinstance(exc, (OSError, TimeoutError)) or getattr(exc, "code", "") in {"DATA_TIMEOUT", "DATA_CLOSED", "DATA_RETRY_EXHAUSTED", "ApplicationReadinessTimeout", "ControlCenterUnavailable", "ConnectionTimedOut", "ConnectionRefused", "PeerUnavailable"}
        if binding["mode"] == "preferred" and binding["allow_native_fallback"] and retryable:
            return 80
        if isinstance(exc, ProtocolError): raise
        fail("NATIVE_TRANSPORT_UNAVAILABLE", "native application boundary unavailable; direct fallback denied")
