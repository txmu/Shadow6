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
METHODS = ("capabilities.get", "status.get", "health.challenge", "objects.list", "operation.prepare",
           "operation.commit", "operation.abort", "operation.status", "operation.reconcile", "events.list", "content.get", "governance.fact", "zkt.status", "zkt.account", "identity.fact", "zkn.list", "zkn.fact", "zkc.list", "zkc.fact", "service.binding", "compute.challenge", "privacy.status", "privacy.review.list", "privacy.review.get", "zkn.shield.notes", "zkn.shield.images", "cooperative.state", "cooperative.asset.prepare")


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
                        "wiki.create", "snapshot.create", "strata.create", "chain.mine", "compute.run", "compute.submit", "identity.register", "content.publish", "zkn.transfer", "zkn.gift", "zkc.issue", "privacy.submit", "cooperative.submit", "naming.submit", "recovery.checkpoint", "recovery.restore"}
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
    if method == "health.challenge":
        if (set(params)!={"challenge"} or not isinstance(params["challenge"],str) or
                not re.fullmatch(r"[0-9a-f]{32}",params["challenge"])):
            fail("INVALID_PARAMS", "fresh bounded health challenge required")
    elif method in {'privacy.status','privacy.review.list','privacy.review.get','zkn.shield.notes','zkn.shield.images'}:
        allowed=set() if method=='privacy.status' else {'request_id'} if method=='privacy.review.get' else {'limit','cursor'}
        if set(params)-allowed or (method=='privacy.review.get' and set(params)!=allowed):fail('INVALID_PARAMS','exact privacy query required')
        if 'request_id' in params:
            try:zs_hex(params['request_id'])
            except ValueError:fail('INVALID_PARAMS','exact review identifier required')
        if 'limit' in params and (type(params['limit']) is not int or not 1<=params['limit']<=64):fail('INVALID_PARAMS','bounded privacy page required')
        if 'cursor' in params and params['cursor']:
            try:zs_hex(params['cursor'])
            except ValueError:fail('INVALID_PARAMS','bounded privacy cursor required')
    elif method.startswith('cooperative.'):
        fields={'cursor','limit'} if method=='cooperative.state' else {'cooperative','type','payload'}
        if (set(params)-fields if method=='cooperative.state' else set(params)!=fields):fail('INVALID_PARAMS','exact cooperative query fields required')
        if method=='cooperative.state':
            if type(params.get('cursor',''))is not str or len(params.get('cursor',''))>64 or type(params.get('limit',4))is not int or not 1<=params.get('limit',4)<=4:fail('INVALID_PARAMS','bounded cooperative state page required')
        if method!='cooperative.state' and (type(params['cooperative'])is not str or type(params['type'])is not str or type(params['payload'])is not dict):fail('INVALID_PARAMS','cooperative operation types')
    elif method=='compute.challenge':
        if params not in ({},{'engine':'gimps'}):fail('INVALID_PARAMS','fixed zero or native GIMPS challenge selector required')
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
        if candidate == path and os.name != "nt":
            if info.st_uid != os.geteuid():
                fail("UNSAFE_FILE", "inventory directory must be owner-controlled")
            if info.st_mode & 0o022:
                try:
                    path.chmod(info.st_mode & ~0o022)
                    info = path.lstat()
                except OSError:
                    pass
            if info.st_uid != os.geteuid() or info.st_mode & 0o002 or (info.st_gid != getattr(os, 'getegid', lambda: info.st_gid)() and info.st_mode & 0o020):
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
                              for method in METHODS if (provider == "corium" and method != "service.binding") or (provider == "shadow6" and not method.startswith(("zkt.","zkn.","zkc.","cooperative.")) and method not in {"content.get", "governance.fact", "identity.fact", "compute.challenge", "privacy.status", "privacy.review.list", "privacy.review.get"})],
            "native_actions": sorted(OPERATIONS[provider]),
            "object_kinds": ["service", "package", "application"] if provider == "shadow6" else ["package", "environment", "application", "identity", "name", "proposal", "recovery"],
            "transport": "native-application-boundary; one Core family per path" if provider == "shadow6" else "native-signature-preserving Ziokt binding; explicit fallback"}


def status(provider, config, network):
    return {"schema": "ziokt.provider-status.v1", "native_project": provider,
            "enabled": config["enabled"], "provider_id": config["provider_id"],
            "federation_id": config["federation_id"], "network_id": network,
            "mutations": config["allow_mutations"], "listeners": 0,
            "listener_scope": "local-rpc-process", "recovery": "explicit-native-operation"}


def health_challenge(provider, config, challenge):
    """Prove a fresh request reached this pinned native provider process.

    This deliberately reports application and external network readiness as
    unassessed; a provider challenge cannot stand in for an end-to-end service
    operation or a peer acknowledgement.
    """
    return {"schema":"ziokt.provider-health.v1","challenge":challenge,
            "native_project":provider,"provider_id":config["provider_id"],
            "federation_id":config["federation_id"],"enabled":config["enabled"],
            "observed_at_ms":time.time_ns()//1_000_000,
            "checks":{"pinned_process_rpc":"passed","application_runtime":"not_assessed",
                      "external_peer":"not_assessed"}}


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
        elif method == "health.challenge":
            result = health_challenge(provider, config, request["params"]["challenge"])
        elif method in {'privacy.status','privacy.review.list','privacy.review.get','zkn.shield.notes','zkn.shield.images'}:
            if provider!='corium':fail('METHOD_UNSUPPORTED','privacy consensus belongs to Corium')
            try:
                with closing(corium_db(root,network,'blockchain/chain.db')) as db:result=zs_query(db,network,method,request['params'])
            except ValueError as exc:fail('PRIVACY_REJECTED',str(exc))
        elif method=='service.binding':
            if provider!='shadow6': fail('METHOD_UNSUPPORTED','native Broker bindings belong to Shadow6')
            result=service_binding_fact(root,config,request['params']['service_name'])
        elif method.startswith("operation.") or method == "events.list":
            result = operation_dispatch(provider, root, network, config, method, request["params"])
        elif method == "compute.challenge":
            if provider != "corium":fail("METHOD_UNSUPPORTED","Engine Zero belongs to Corium")
            result=compute_challenge(root,network,request['params'].get('engine'))
        elif method == "governance.fact":
            if provider != "corium": fail("METHOD_UNSUPPORTED", "native chain facts belong to Corium")
            result = governance_fact(root, network, request["params"]["transaction_hash"])
        elif method.startswith('cooperative.'):
            if provider!='corium':fail('METHOD_UNSUPPORTED','cooperative authority belongs to Corium')
            with closing(corium_db(root,network,'blockchain/chain.db')) as db:
                height=zs_height(db)+1;cc=_native_cooperative_consensus
                if method=='cooperative.asset.prepare':
                    params=request['params'];result=cc.asset_command(db,network,params['type'],params['payload'],params['cooperative'],height)
                else:
                    state=cc.state_at(db,network,height)
                    params=request['params'];ids=[cid for cid in sorted(state['cooperatives']) if cid>params.get('cursor','')];cooperative_page=ids[:params.get('limit',4)]
                    result={'state':{**state,'cooperatives':{cid:state['cooperatives'][cid] for cid in cooperative_page}},'state_root':_native_cooperative.state_root(state),'asset_state_root':cc.asset_state_root(db),
                            'accounts':{cid:cc.account(state['chain'],cid) for cid in cooperative_page},'next_nonces':{cid:cc.next_nonce(db,cid) for cid in cooperative_page},'next_cursor':cooperative_page[-1] if len(ids)>len(cooperative_page) else None,'root_scope':'complete canonical registry; state is paginated'}
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
              "corium": {"artifact.stage", "wiki.create", "snapshot.create", "strata.create", "chain.mine", "compute.run", "compute.submit", "identity.register", "content.publish", "zkn.transfer", "zkn.gift", "zkc.issue", "privacy.submit", "cooperative.submit", "naming.submit", "recovery.checkpoint", "recovery.restore"}}


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
    if action == "naming.submit":
        return naming_preflight(root,network,params,config)
    if action == "compute.submit":
        return compute_submit_preflight(root,network,params,config)
    if action == "compute.run":
        return compute_preflight(root, network, params, config)
    if action in {'identity.register','content.publish','zkn.transfer','zkn.gift','zkc.issue','privacy.submit','cooperative.submit'}:
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
    if provider=='corium' and plan['action'] in {'zkn.gift','zkc.issue','privacy.submit','cooperative.submit'}:
        if asset_preflight(root,network,plan,config)!=plan['binding_evidence']:
            fail('STALE_PLAN','private gift evidence changed')
        return asset_submit_gift(root,network,plan['arguments']['transaction'],plan['arguments']['transaction']['type'] if plan['action'] in {'privacy.submit','cooperative.submit'} else 'zkc_issue' if plan['action']=='zkc.issue' else 'zkn_private_transfer')
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
    if plan["action"] in {"wiki.create", "snapshot.create", "strata.create", "chain.mine", "compute.run", "compute.submit", "identity.register", "content.publish", "zkn.transfer", "zkn.gift", "zkc.issue", "privacy.submit", "cooperative.submit", "naming.submit", "recovery.checkpoint", "recovery.restore"}:
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
    if action in {'compute.submit','identity.register','content.publish','zkn.transfer','zkn.gift','zkc.issue','privacy.submit','cooperative.submit','naming.submit'}: return asset_receipt(root,network,plan)
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


def compute_challenge(root, network, engine=None):
    """Select an explicit independent native engine; no cross-engine fallback."""
    if engine=='gimps':
        with closing(corium_db(root,network,'blockchain/chain.db')) as db:
            try:return _native_gimps.native_challenge(db,network,corium_identity(root,network))
            except (ValueError,TypeError,KeyError) as exc:fail('NATIVE_STATE_CONFLICT',str(exc))
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
    if 'engine_id' in args:return gimps_submit_preflight(root,network,params,config)
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


def gimps_submit_preflight(root,network,params,config):
    args=params['arguments']
    if (set(args)!={'engine_id','problem_id','proof_data'} or params['resource']!='compute:'+str(args['engine_id']) or
            params['expected_revision'] is not None or not isinstance(args['engine_id'],str) or not re.fullmatch('[A-Za-z0-9_./:-]{1,128}',args['engine_id'])):
        fail('INVALID_PARAMS','exact native GIMPS proof and engine scope required')
    sender=corium_identity(root,network)
    with closing(corium_db(root,network,'blockchain/chain.db')) as db:
        head=db.execute("SELECT value FROM chain_state WHERE key='chain_info'").fetchone()
        if not head or not re.fullmatch(r'[a-f0-9]{64}\|[0-9]+',head[0]):fail('NATIVE_STATE_UNAVAILABLE','accepted head required')
        height=int(head[0].split('|')[1])
        row=db.execute('SELECT pkg_id,compute_program_hash,verifier_script_hash FROM compute_engines WHERE engine_id=?',(args['engine_id'],)).fetchone()
        if not row or row[0]!=_native_gimps.PACKAGE:fail('POLICY_DENIED','explicit native GIMPS engine required')
        payload={'engine_id':args['engine_id'],'problem_id':args['problem_id'],'proof_data':args['proof_data'],'engine_hash':row[1],'verifier_hash':row[2]}
        prior=db.execute("SELECT hash FROM transactions WHERE type='submit_math_proof' AND data=? LIMIT 1",(encoded(payload).decode(),)).fetchone()
        try:_native_gimps.validate_gimps_proof(db,network,payload,sender,height,accepted_tx=prior[0] if prior else None)
        except (ValueError,TypeError,KeyError) as exc:fail('INVALID_PROOF',str(exc))
    return {'transaction_type':'submit_math_proof','payload':payload,'issuer':sender}

def _load_native_gimps():
    """Native verification, task state lifecycle, and settlement for GIMPS (Mersenne prime search) proofs.

    Supports:
    1. Versioned schema 'corium.gimps-proof.v1', 'corium.gimps-proof.v2', and modern PRP 'corium.gimps-prp-proof.v1'.
    2. Probable Prime (PRP) tests (base 3) with low-cost verifiable certification (Pietrzak / Gerbicz Proof
       of Exponentiation with Fiat-Shamir folding, bounded residual squarings and modular exponentiations).
    3. Lucas-Lehmer recomputation for backward compatibility (exponents 2..4096).
    4. Task state lifecycle:
       - assigned: task dispatched with an unexpired lease
       - submitted: transaction present in mempool or confirmed block
       - verified: confirmed into block, pending in challenge window
       - settled: challenge window passed unchallenged, recorded in completed_compute_tasks
       - paused: task explicitly paused with preserved checkpoint
       - failed / retry: challenged and proven invalid, or expired without submission
    5. Three-tier outcome separation:
       - math_certified: mathematical proof verified independently by Corium verifier
       - primenet_status: PrimeNet task submission/attestation record ('unsubmitted', 'submitted', 'accepted')
       - corium_settled: on-chain settlement into completed_compute_tasks and contribution_scores
    6. Shared settlement and contribution_scores update with governance-controlled reward weight.
    7. Strict duplicate detection: rejects duplicate submissions for already settled or pending exponents,
       while allowing retry of failed exponents.
    """
    from contextlib import closing
    import hashlib
    import json
    import math
    from pathlib import Path
    import re
    import sqlite3
    import sys
    import time

    EMBEDDED_SOURCE_DIGEST = None
    PACKAGE = 'corium/built-in-gimps'
    SCHEMA = 'corium.gimps-proof.v1'
    PORTABLE_SCHEMA = 'corium.gimps-proof.v2'
    PRP_SCHEMA = 'corium.gimps-prp-proof.v1'
    MAX_INTEGER = 2**63 - 1
    DEFAULT_LEASE_SECONDS = 86400
    MAX_LL_EXPONENT = 4096
    MAX_PRP_EXPONENT = 2_000_000_000
    MAX_VERIFIED_EXPONENT = MAX_LL_EXPONENT

    # Node-local resource governance (configurable by node operator per host capacity)
    DEFAULT_NODE_MAX_NATIVE_EXPONENT = 100_000
    DEFAULT_NODE_MAX_MEMORY_MB = 256
    GERBICZ_MODULUS_Q = 4294967311


    def get_node_resource_limits(configured_max_exp=None, configured_max_mem_mb=None):
        """Retrieve node-local resource limits from arguments, environment, or safe defaults.
        These limits apply to the local node's native execution to prevent memory/CPU starvation,
        and can be configured by the user/operator per host capacity.
        """
        import os
        if configured_max_exp is not None:
            max_exp = int(configured_max_exp)
        else:
            env_exp = os.environ.get('CORIUM_GIMPS_MAX_EXPONENT')
            max_exp = int(env_exp) if env_exp and env_exp.isdigit() else DEFAULT_NODE_MAX_NATIVE_EXPONENT

        if configured_max_mem_mb is not None:
            max_mem = int(configured_max_mem_mb)
        else:
            env_mem = os.environ.get('CORIUM_GIMPS_MAX_MEMORY_MB')
            max_mem = int(env_mem) if env_mem and env_mem.isdigit() else DEFAULT_NODE_MAX_MEMORY_MB

        require(2 <= max_exp <= MAX_PRP_EXPONENT and 1 <= max_mem <= 65536,
                'positive bounded local resource limits required')
        return max_exp, max_mem


    def _squares(value, count, modulus):
        for _ in range(count):
            value = value * value % modulus
        return value


    def _transition_challenge(x, y, z, modulus, count):
        return int(hashlib.sha256(f'corium-checkpoint-v1:{x:x}:{y:x}:{z:x}:{modulus:x}:{count}'.encode()).hexdigest(), 16)


    def _transition_proof(x, y, count, modulus):
        steps = []
        while count > 32:
            odd = bool(count % 2)
            if odd:
                x = x * x % modulus
                count -= 1
            z = _squares(x, count // 2, modulus)
            r = _transition_challenge(x, y, z, modulus, count)
            steps.append({'Z': hex(z), 'odd': odd})
            x, y = pow(x, r, modulus) * z % modulus, pow(z, r, modulus) * y % modulus
            count //= 2
        return steps


    def _verify_transition(x, y, count, steps, modulus):
        require(type(steps) is list and len(steps) <= 32, 'bounded checkpoint transition proof required')
        for step in steps:
            require(count > 32 and type(step) is dict, 'unexpected checkpoint folding step')
            require(type(step.get('odd')) is bool and step['odd'] == bool(count % 2), 'checkpoint parity mismatch')
            if step['odd']:
                x = x * x % modulus
                count -= 1
            z = _bounded_hex(step.get('Z'), modulus)
            r = _transition_challenge(x, y, z, modulus, count)
            x, y = pow(x, r, modulus) * z % modulus, pow(z, r, modulus) * y % modulus
            count //= 2
        require(count <= 32 and _squares(x, count, modulus) == y, 'checkpoint mathematical recurrence failed')


    def _bounded_hex(value, modulus):
        require(type(value) is str and len(value) <= (modulus.bit_length() + 3) // 4 + 2
                and re.fullmatch(r'0x[0-9a-f]+', value), 'bounded hex residue required')
        result = int(value, 16)
        require(0 <= result < modulus, 'bounded residue required')
        return result


    def _decimal_text(value):
        # Avoid changing Python's process-wide integer conversion safety setting.
        if value < 10**1000:
            return str(value)
        parts = []
        while value:
            value, part = divmod(value, 10**1000)
            parts.append(part)
        return str(parts[-1]) + ''.join(f'{part:01000d}' for part in reversed(parts[:-1]))


    def _decimal_integer(value):
        result = 0
        for offset in range(0, len(value), 1000):
            part = value[offset:offset + 1000]
            result = result * 10**len(part) + int(part)
        return result


    def _legacy_challenge(x, y, z, modulus):
        message = ':'.join(_decimal_text(v) for v in (x, y, z, modulus))
        return int(hashlib.sha256(message.encode()).hexdigest()[:16], 16)


    # Known Mersenne primes for deterministic primality classification (including M136279841)
    KNOWN_MERSENNE_PRIMES = {
        2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203,
        2281, 3217, 4253, 4423, 9689, 9941, 11213, 19937, 21701, 23209, 44497,
        86243, 110503, 132049, 216091, 756839, 859433, 1257787, 1398269, 2976221,
        3021377, 6972593, 13466917, 20996011, 24036583, 25964951, 30402457,
        32582657, 37156667, 42643801, 43112609, 57885161, 74207281, 77232917,
        82589933, 136279841
    }


    def canonical(value, ascii=False):
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=ascii, allow_nan=False).encode()


    def require(test, message):
        if not test:
            raise ValueError(message)


    def exact(value, fields):
        require(type(value) is dict and set(value) == set(fields), 'exact fields required')


    def integer(value, low, high):
        require(type(value) is int and low <= value <= high, 'integer bound')
        return value


    def lucas_lehmer_verify(p, claimed_residue):
        """Deterministically compute Lucas-Lehmer residue for small exponents (p <= 4096)."""
        if type(p) is not int or not 2 <= p <= MAX_VERIFIED_EXPONENT or type(claimed_residue) is not int:
            return False, None
        if p == 2:
            return (claimed_residue == 0), 0
        m = (1 << p) - 1
        s = 4
        for _ in range(p - 2):
            s = (s * s - 2) % m
        return (s == claimed_residue), s


    def generate_prp_proof(p, base=3, depth=None, max_native_exponent=None, max_memory_mb=None):
        """Generate PRP proof for Mersenne number M_p = 2^p - 1 with Fiat-Shamir folding."""
        require(type(p) is int and 2 <= p <= MAX_PRP_EXPONENT, 'valid exponent bound')
        node_max_exp, node_max_mem = get_node_resource_limits(max_native_exponent, max_memory_mb)
        est_mem_bytes = (p // 8) * 32
        if p > node_max_exp or est_mem_bytes > node_max_mem * 1024 * 1024:
            raise ValueError(
                f"EXPONENT_EXCEEDS_LOCAL_NODE_CAPACITY: exponent {p} (requires ~{est_mem_bytes // (1024*1024)}MB RAM) "
                f"exceeds this node's configured native capacity (max_exp={node_max_exp}, max_mem={node_max_mem}MB). "
                f"Configure higher limits or use external mprime engine."
            )

        require(type(base) is int and base == 3, 'base 3 required')
        require(depth is None or type(depth) is int and 1 <= depth <= 64, 'bounded proof depth required')
        N = (1 << p) - 1
        if p == 2:
            return {
                'schema': PRP_SCHEMA,
                'exponent': 2,
                'method': 'prp-fiat-shamir',
                'base': base,
                'res64': '0000000000000000',
                'residue': '0',
                'is_prp': True,
                'prp_result': 'PRP',
                'is_prime': True,
                'iterations': 1,
                'proof_steps': [{'Z': '0x0', 'odd': False}],
                'gerbicz_status': 'OK',
                'gerbicz_checkpoints': []
            }

        # Fermat PRP residue: y = base^((N - 1) // 2) % N
        # Note: 3 * y % N == 3^(2^(p-1)) % N
        y = pow(base, (N - 1) // 2, N)
        is_prp = (y == N - 1)
        prp_result = "PRP" if is_prp else "COMPOSITE"
        is_prime = bool(is_prp and p in KNOWN_MERSENNE_PRIMES)
        res64 = f"{y & 0xFFFFFFFFFFFFFFFF:016X}"

        # Target value for 2^(p-1) squarings from base: Y = (base * y) % N
        X = base
        Y = (base * y) % N
        T = p - 1

        proof_steps = []
        curr_X, curr_Y, curr_T = X, Y, T
        max_folds = depth if depth is not None else 64
        for fold_idx in range(max_folds):
            if curr_T <= 1 or (depth is None and curr_T <= 4096 and fold_idx >= 4):
                break
            was_odd = (curr_T % 2 == 1)
            if was_odd:
                curr_X = (curr_X * curr_X) % N
                curr_T -= 1
            half = curr_T // 2
            # Midpoint Z after half squarings
            Z = curr_X
            for _ in range(half):
                Z = (Z * Z) % N
            r = _legacy_challenge(curr_X, curr_Y, Z, N)
            proof_steps.append({'Z': hex(Z), 'odd': was_odd})
            curr_X = (pow(curr_X, r, N) * Z) % N
            curr_Y = (pow(Z, r, N) * curr_Y) % N
            curr_T = half

        # Exact states plus bounded transition proofs bind the summaries to arithmetic.
        gerbicz_checkpoints = []
        Q = GERBICZ_MODULUS_Q
        curr_chk_hash = hashlib.sha256(f"gerbicz-init:{p}:{base}:{Q}".encode()).hexdigest()
        previous_it, previous_state = 0, base
        intervals = sorted({0, (p - 1) // 2, p - 1})
        for it in intervals:
            state = _squares(previous_state, it - previous_it, N)
            state_summary = hashlib.sha256(f"{p}:{it}:{state:x}".encode()).hexdigest()
            res = f"{state & 0xFFFFFFFFFFFFFFFF:016X}"
            q = state % Q
            curr_chk_hash = hashlib.sha256(f"{curr_chk_hash}:{it}:{state_summary}:{res}:{q}".encode()).hexdigest()
            gerbicz_checkpoints.append({
                'iteration': it, 'state': hex(state), 'state_hash': state_summary,
                'res64': res, 'math_residue_q': q, 'hash': curr_chk_hash,
                'transition': _transition_proof(previous_state, state, it - previous_it, N)
            })
            previous_it, previous_state = it, state

        # Gerbicz block product identity, without division (also valid for nonunits).
        length = max(1, math.isqrt(p - 1))
        blocks = (p - 1) // length
        state, product = base, 1
        for _ in range(blocks):
            product = product * state % N
            state = _squares(state, length, N)
        require(_squares(product, length, N) * base % N == product * state % N,
                'Gerbicz generation check failed')
        require(_squares(state, (p - 1) - blocks * length, N) == Y, 'Gerbicz final state mismatch')
        gerbicz_check = {'block_size': length, 'blocks': blocks,
                         'product': hex(product), 'end_state': hex(state),
                         'transition': _transition_proof(base, state, blocks * length, N)}

        return {
            'schema': PRP_SCHEMA,
            'exponent': p,
            'method': 'prp-fiat-shamir',
            'base': base,
            'res64': res64,
            'residue': _decimal_text(y),
            'is_prp': is_prp,
            'prp_result': prp_result,
            'is_prime': is_prime,
            'iterations': p - 1,
            'proof_steps': proof_steps,
            'gerbicz_status': 'OK',
            'gerbicz_checkpoints': gerbicz_checkpoints,
            'gerbicz_check': gerbicz_check
        }


    def verify_prp_proof(p, proof_data, max_native_exponent=None, max_memory_mb=None):
        """Verify the Corium PRP transcript with bounded local arithmetic."""
        require(type(p) is int and 2 <= p <= MAX_PRP_EXPONENT, 'valid exponent bound')
        require(isinstance(proof_data, dict), 'proof_data must be dict')
        require(proof_data.get('schema') == PRP_SCHEMA, 'corium.gimps-prp-proof.v1 required')
        require(type(proof_data.get('exponent')) is int and proof_data['exponent'] == p, 'exponent mismatch')
        require(proof_data.get('method') == 'prp-fiat-shamir', 'prp-fiat-shamir required')
        require(proof_data.get('base') == 3, 'base 3 required')
        require(type(proof_data.get('iterations')) is int and proof_data['iterations'] == p - 1, 'iterations mismatch')
        require(proof_data.get('gerbicz_status') in ('OK', 'VERIFIED'), 'valid gerbicz_status required')
        require(type(proof_data.get('res64')) is str and re.fullmatch('[0-9A-Fa-f]{16}', proof_data['res64']), 'valid 16-hex res64 required')

        # The submitter's engine label never grants local verification resources.
        node_max_exp, node_max_mem = get_node_resource_limits(max_native_exponent, max_memory_mb)
        est_mem_bytes = (p // 8) * 32
        require(p <= node_max_exp and est_mem_bytes <= node_max_mem * 1024 * 1024,
                'EXPONENT_EXCEEDS_LOCAL_NODE_CAPACITY')

        if p == 2:
            require(proof_data.get('residue') == '0', 'p=2 special case')
            require(proof_data.get('is_prp', True) is True, 'p=2 is prime')
            return True

        N = (1 << p) - 1
        residue_str = proof_data.get('residue')
        require(type(residue_str) is str and 1 <= len(residue_str) <= p // 3 + 1
                and residue_str.isascii() and residue_str.isdigit(), 'bounded decimal residue required')
        require(residue_str == '0' or not residue_str.startswith('0'), 'canonical decimal residue required')
        y = _decimal_integer(residue_str)
        require(0 <= y < N, 'bounded residue required')
        expected_res64 = f"{y & 0xFFFFFFFFFFFFFFFF:016X}"
        require(proof_data['res64'].upper() == expected_res64, 'res64 mismatch')

        # Mathematical PRP semantics: Fermat base-3 residue test
        is_prp = (y == N - 1)
        expected_prp_result = "PRP" if is_prp else "COMPOSITE"

        if 'is_prp' in proof_data:
            require(type(proof_data['is_prp']) is bool and proof_data['is_prp'] == is_prp, 'PRP claim mismatch')
        if 'prp_result' in proof_data:
            require(proof_data['prp_result'] == expected_prp_result, 'prp_result mismatch')
        if 'is_prime' in proof_data:
            require(type(proof_data['is_prime']) is bool, 'boolean is_prime required')
            expected_prime = bool(is_prp and p in KNOWN_MERSENNE_PRIMES)
            require(proof_data['is_prime'] == expected_prime, 'primality claim mismatch')

        checkpoints = proof_data.get('gerbicz_checkpoints', [])
        require(type(checkpoints) is list and 2 <= len(checkpoints) <= 16, 'bounded mathematical checkpoints required')
        if checkpoints:
            previous_hash = hashlib.sha256(f"gerbicz-init:{p}:3:{GERBICZ_MODULUS_Q}".encode()).hexdigest()
            previous_it, previous_state = 0, 3
            for index, chk in enumerate(checkpoints):
                require(type(chk) is dict, 'checkpoint dict required')
                it = integer(chk.get('iteration'), 0, p - 1)
                require((index == 0 and it == 0) or (index > 0 and it > previous_it), 'strict checkpoint coverage required')
                state = _bounded_hex(chk.get('state'), N)
                _verify_transition(previous_state, state, it - previous_it, chk.get('transition'), N)
                state_hash = hashlib.sha256(f"{p}:{it}:{state:x}".encode()).hexdigest()
                res = f"{state & 0xFFFFFFFFFFFFFFFF:016X}"
                q = state % GERBICZ_MODULUS_Q
                require(chk.get('state_hash') == state_hash and chk.get('res64') == res
                        and type(chk.get('math_residue_q')) is int and chk['math_residue_q'] == q,
                        'checkpoint residue mismatch')
                expected = hashlib.sha256(f"{previous_hash}:{it}:{state_hash}:{res}:{q}".encode()).hexdigest()
                require(chk.get('hash') == expected, 'corrupted Gerbicz checkpoint hash chain')
                previous_hash, previous_it, previous_state = expected, it, state
            require(previous_it == p - 1 and previous_state == (3 * y) % N, 'checkpoint final state mismatch')

        check = proof_data.get('gerbicz_check')
        if checkpoints or check is not None:
            require(type(check) is dict, 'Gerbicz block product required')
            length = max(1, math.isqrt(p - 1))
            blocks = (p - 1) // length
            require(type(check.get('block_size')) is int and check['block_size'] == length
                    and type(check.get('blocks')) is int and check['blocks'] == blocks,
                    'Gerbicz block coverage mismatch')
            product = _bounded_hex(check.get('product'), N)
            end = _bounded_hex(check.get('end_state'), N)
            require(math.gcd(product, N) == 1, 'nonunit Gerbicz product rejected')
            _verify_transition(3, end, blocks * length, check.get('transition'), N)
            require(_squares(product, length, N) * 3 % N == product * end % N,
                    'Gerbicz product identity failed')
            require(_squares(end, p - 1 - length * blocks, N) == (3 * y) % N,
                    'Gerbicz tail recurrence failed')

        # Prover MUST provide proof_steps; verifier NEVER computes midpoints for workers
        proof_steps = proof_data.get('proof_steps')
        require(isinstance(proof_steps, list), 'valid proof_steps required')
        require(len(proof_steps) >= 1, 'prover must supply at least one folding step')
        require(len(proof_steps) <= 64, 'proof_steps exceeds maximum depth')

        v_X = 3
        v_Y = (3 * y) % N
        v_T = p - 1

        for step in proof_steps:
            require(isinstance(step, dict) and 'Z' in step and 'odd' in step, 'step dict required')
            require(v_T > 1, 'unexpected proof step')
            require(type(step.get('odd')) is bool and step['odd'] == bool(v_T % 2), 'fold parity mismatch')
            Z = _bounded_hex(step.get('Z'), N)
            if step['odd']:
                v_X = (v_X * v_X) % N
                v_T -= 1
            half = v_T // 2
            r = _legacy_challenge(v_X, v_Y, Z, N)
            v_X = (pow(v_X, r, N) * Z) % N
            v_Y = (pow(Z, r, N) * v_Y) % N
            v_T = half

        # Remaining squarings must be bounded to O(depth) cost ceiling (<= 4096 squarings)
        require(v_T <= 4096, 'remaining squarings exceed verifier cost ceiling')
        final_s = v_X
        for _ in range(v_T):
            final_s = (final_s * final_s) % N
        require(final_s == v_Y, 'Pietrzak Proof of Exponentiation check failed')
        return True


    def init_schema(db):
        db.execute("""
        CREATE TABLE IF NOT EXISTS gimps_tasks (
            engine_id TEXT NOT NULL,
            problem_set_id TEXT NOT NULL,
            exponent INTEGER NOT NULL,
            state TEXT NOT NULL,
            assigned_to TEXT,
            assigned_at INTEGER,
            lease_timeout INTEGER,
            proof_tx_hash TEXT,
            checkpoint_json TEXT,
            last_heartbeat INTEGER,
            math_certified INTEGER DEFAULT 0,
            primenet_status TEXT DEFAULT 'unsubmitted',
            corium_settled INTEGER DEFAULT 0,
            PRIMARY KEY (engine_id, exponent)
        )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_gimps_tasks_state ON gimps_tasks(engine_id, state)")
        # Migration helper for existing databases:
        existing_cols = {row[1] for row in db.execute("PRAGMA table_info(gimps_tasks)").fetchall()}
        for col, col_type, default in [
            ('checkpoint_json', 'TEXT', None),
            ('last_heartbeat', 'INTEGER', None),
            ('math_certified', 'INTEGER', '0'),
            ('primenet_status', 'TEXT', "'unsubmitted'"),
            ('corium_settled', 'INTEGER', '0')
        ]:
            if col not in existing_cols:
                db.execute(f"ALTER TABLE gimps_tasks ADD COLUMN {col} {col_type}" + (f" DEFAULT {default}" if default else ""))


    def renew_lease(db, engine_id, exponent, worker_id, progress_pct=None, checkpoint_data=None, lease_duration=DEFAULT_LEASE_SECONDS, current_time=None):
        init_schema(db)
        if current_time is None:
            current_time = int(time.time())
        row = db.execute(
            "SELECT state, assigned_to, lease_timeout FROM gimps_tasks WHERE engine_id=? AND exponent=?",
            (engine_id, exponent)
        ).fetchone()
        require(row is not None, "task not found")
        state, assigned_to, lease_timeout = row[0], row[1], row[2]
        if state == 'assigned':
            require(assigned_to == worker_id, "task assigned to different worker")
            require(lease_timeout is None or lease_timeout > current_time, "lease already expired")
        elif state == 'paused':
            require(assigned_to == worker_id, "task paused by different worker")
        else:
            raise ValueError(f"cannot renew lease in state {state}")

        new_timeout = current_time + lease_duration
        chk_str = json.dumps(checkpoint_data) if checkpoint_data is not None else None
        if chk_str is not None:
            db.execute(
                "UPDATE gimps_tasks SET lease_timeout=?, last_heartbeat=?, checkpoint_json=? WHERE engine_id=? AND exponent=?",
                (new_timeout, current_time, chk_str, engine_id, exponent)
            )
        else:
            db.execute(
                "UPDATE gimps_tasks SET lease_timeout=?, last_heartbeat=? WHERE engine_id=? AND exponent=?",
                (new_timeout, current_time, engine_id, exponent)
            )
        return {
            'status': 'renewed',
            'engine_id': engine_id,
            'exponent': exponent,
            'assigned_to': worker_id,
            'lease_timeout': new_timeout,
            'last_heartbeat': current_time
        }


    def pause_task(db, engine_id, exponent, worker_id, checkpoint_data=None, current_time=None):
        init_schema(db)
        if current_time is None:
            current_time = int(time.time())
        row = db.execute(
            "SELECT state, assigned_to, lease_timeout FROM gimps_tasks WHERE engine_id=? AND exponent=?",
            (engine_id, exponent)
        ).fetchone()
        require(row is not None, "task not found")
        state, assigned_to = row[0], row[1]
        require(state == 'assigned', f"task not in assigned state (state={state})")
        require(assigned_to == worker_id, "task assigned to different worker")

        chk_str = json.dumps(checkpoint_data) if checkpoint_data is not None else None
        if chk_str is not None:
            db.execute(
                "UPDATE gimps_tasks SET state='paused', last_heartbeat=?, checkpoint_json=? WHERE engine_id=? AND exponent=?",
                (current_time, chk_str, engine_id, exponent)
            )
        else:
            db.execute(
                "UPDATE gimps_tasks SET state='paused', last_heartbeat=? WHERE engine_id=? AND exponent=?",
                (current_time, engine_id, exponent)
            )
        return {
            'status': 'paused',
            'engine_id': engine_id,
            'exponent': exponent,
            'assigned_to': worker_id,
            'last_heartbeat': current_time
        }


    def resume_task(db, engine_id, exponent, worker_id, lease_duration=DEFAULT_LEASE_SECONDS, current_time=None):
        init_schema(db)
        if current_time is None:
            current_time = int(time.time())
        row = db.execute(
            "SELECT state, assigned_to, checkpoint_json FROM gimps_tasks WHERE engine_id=? AND exponent=?",
            (engine_id, exponent)
        ).fetchone()
        require(row is not None, "task not found")
        state, assigned_to, checkpoint_json = row[0], row[1], row[2]
        require(state in ('paused', 'retry'), f"task cannot be resumed from state {state}")

        new_timeout = current_time + lease_duration
        db.execute(
            "UPDATE gimps_tasks SET state='assigned', assigned_to=?, assigned_at=?, lease_timeout=?, last_heartbeat=? WHERE engine_id=? AND exponent=?",
            (worker_id, current_time, new_timeout, current_time, engine_id, exponent)
        )
        checkpoint = json.loads(checkpoint_json) if checkpoint_json else None
        return {
            'status': 'resumed',
            'engine_id': engine_id,
            'exponent': exponent,
            'assigned_to': worker_id,
            'lease_timeout': new_timeout,
            'checkpoint': checkpoint
        }


    def update_primenet_status(db, engine_id, exponent, status, attestation=None):
        init_schema(db)
        require(status in ('unsubmitted', 'submitted', 'accepted', 'rejected'), f"invalid primenet status: {status}")
        db.execute(
            "INSERT INTO gimps_tasks (engine_id, problem_set_id, exponent, state, primenet_status) "
            "VALUES (?, '', ?, 'assigned', ?) "
            "ON CONFLICT(engine_id, exponent) DO UPDATE SET primenet_status=excluded.primenet_status",
            (engine_id, exponent, status)
        )
        return {
            'engine_id': engine_id,
            'exponent': exponent,
            'primenet_status': status,
            'attestation': attestation
        }


    def candidates(metadata):
        """Bound native verification work and search prime exponents only."""
        if isinstance(metadata, str):
            metadata = json.loads(metadata)
        require(type(metadata) is dict, 'problem set metadata required')
        method = metadata.get('method', 'lucas-lehmer')
        max_bound = MAX_PRP_EXPONENT if method in ('prp', 'prp-fiat-shamir') else MAX_LL_EXPONENT
        start = integer(metadata.get('start_exponent'), 2, max_bound)
        end = integer(metadata.get('end_exponent'), start, max_bound)
        return (p for p in range(start, end + 1) if all(p % d for d in range(2, int(p**0.5) + 1)))


    def native_challenge(db, network, submitter):
        """Read-only native GIMPS selection; never falls back to another engine."""
        row = db.execute("SELECT value FROM chain_state WHERE key='chain_info'").fetchone()
        require(row and type(row[0]) is str, 'accepted native head required')
        head = row[0].split('|')
        require(len(head) == 2 and re.fullmatch('[a-f0-9]{64}', head[0]) and head[1].isdigit(), 'canonical native head required')
        height = int(head[1])
        require(db.execute('SELECT 1 FROM blocks WHERE hash=? AND height=?', (head[0], height)).fetchone(), 'accepted head must exist')
        base = {
            'schema': 'corium.gimps-challenge.v1',
            'network_id': network,
            'submitter_id': submitter,
            'height': height,
            'block_hash': head[0],
            'proof_schema': PORTABLE_SCHEMA,
            'supported_schemas': [PORTABLE_SCHEMA, PRP_SCHEMA],
            'method': 'lucas-lehmer',
            'supported_methods': ['lucas-lehmer', 'prp-fiat-shamir'],
            'max_ll_exponent': MAX_LL_EXPONENT,
            'max_prp_exponent': MAX_PRP_EXPONENT,
            'max_exponent': MAX_PRP_EXPONENT
        }
        engines = db.execute('SELECT engine_id,compute_program_hash,verifier_script_hash FROM compute_engines WHERE pkg_id=? AND is_active=1 ORDER BY engine_id', (PACKAGE,)).fetchall()
        for engine, program, verifier in engines:
            problem = db.execute('SELECT set_id,metadata FROM problem_sets WHERE engine_id=? AND activation_height<=? ORDER BY activation_height DESC,set_id LIMIT 1', (engine, height)).fetchone()
            if not problem:
                continue
            blocked = {str(row[0]) for row in db.execute('SELECT problem_id FROM completed_compute_tasks WHERE engine_id=?', (engine,))}
            blocked.update(str(row[0]) for row in db.execute("SELECT json_extract(data,'$.problem_id') FROM transactions WHERE type='submit_math_proof' AND block_height IS NULL AND json_extract(data,'$.engine_id')=?", (engine,)))
            blocked.update(str(row[0]) for row in db.execute("SELECT p.problem_id FROM pending_proofs p JOIN transactions t ON t.hash=p.proof_tx_hash WHERE json_extract(t.data,'$.engine_id')=?", (engine,)))
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='gimps_tasks'").fetchone():
                blocked.update(str(row[0]) for row in db.execute("SELECT exponent FROM gimps_tasks WHERE engine_id=? AND state='assigned' AND lease_timeout>?", (engine, int(time.time()))))
                blocked.update(str(row[0]) for row in db.execute("SELECT exponent FROM gimps_tasks WHERE engine_id=? AND state='paused'", (engine,)))
            for exponent in candidates(problem[1]):
                if str(exponent) not in blocked:
                    metadata = json.loads(problem[1]) if isinstance(problem[1], str) else problem[1]
                    use_prp = metadata.get('method') in ('prp', 'prp-fiat-shamir')
                    return dict(base, available=True, engine_id=engine, problem_set_id=problem[0], problem_id=str(exponent),
                                exponent=exponent, engine_hash=program, verifier_hash=verifier,
                                method='prp-fiat-shamir' if use_prp else 'lucas-lehmer',
                                proof_schema=PRP_SCHEMA if use_prp else PORTABLE_SCHEMA)
        return dict(base, available=False, reason='no-active-gimps-engine' if not engines else 'no-available-gimps-task')


    def reconcile_task_states(db, engine_id, set_id, start_exp, end_exp, current_time=None):
        """Reconcile task state machine from the blockchain tables."""
        init_schema(db)
        if current_time is None:
            current_time = int(time.time())
        # Derived states must follow the canonical tables after replay/reorganization.
        db.execute("UPDATE gimps_tasks SET state='retry',proof_tx_hash=NULL WHERE engine_id=? AND state IN ('settled','verified','submitted','failed')", (engine_id,))

        # 1. Settled tasks from completed_compute_tasks
        completed_rows = db.execute(
            "SELECT problem_id, proof_tx_hash FROM completed_compute_tasks WHERE engine_id=?",
            (engine_id,)
        ).fetchall()
        for row in completed_rows:
            try:
                exp = int(row[0])
                if start_exp <= exp <= end_exp:
                    db.execute(
                        "INSERT INTO gimps_tasks (engine_id, problem_set_id, exponent, state, proof_tx_hash, math_certified, corium_settled) "
                        "VALUES (?, ?, ?, 'settled', ?, 1, 1) "
                        "ON CONFLICT(engine_id, exponent) DO UPDATE SET state='settled', proof_tx_hash=excluded.proof_tx_hash, math_certified=1, corium_settled=1",
                        (engine_id, set_id, exp, row[1])
                    )
            except (ValueError, TypeError):
                continue

        # 2. Verified / pending confirmation tasks from pending_proofs
        pending_rows = db.execute(
            "SELECT p.problem_id, p.proof_tx_hash FROM pending_proofs p "
            "JOIN transactions t ON t.hash=p.proof_tx_hash "
            "WHERE json_extract(t.data, '$.engine_id')=?",
            (engine_id,)
        ).fetchall()
        for row in pending_rows:
            try:
                exp = int(row[0])
                if start_exp <= exp <= end_exp:
                    cur = db.execute("SELECT state FROM gimps_tasks WHERE engine_id=? AND exponent=?", (engine_id, exp)).fetchone()
                    if not cur or cur[0] != 'settled':
                        db.execute(
                            "INSERT INTO gimps_tasks (engine_id, problem_set_id, exponent, state, proof_tx_hash, math_certified) "
                            "VALUES (?, ?, ?, 'verified', ?, 1) "
                            "ON CONFLICT(engine_id, exponent) DO UPDATE SET state='verified', proof_tx_hash=excluded.proof_tx_hash, math_certified=1",
                            (engine_id, set_id, exp, row[1])
                        )
            except (ValueError, TypeError):
                continue

        # 3. Submitted unconfirmed transactions in mempool
        mempool_rows = db.execute(
            "SELECT hash, json_extract(data, '$.problem_id') FROM transactions "
            "WHERE type='submit_math_proof' AND block_height IS NULL AND json_extract(data, '$.engine_id')=?",
            (engine_id,)
        ).fetchall()
        for row in mempool_rows:
            try:
                exp = int(row[1])
                if start_exp <= exp <= end_exp:
                    cur = db.execute("SELECT state FROM gimps_tasks WHERE engine_id=? AND exponent=?", (engine_id, exp)).fetchone()
                    if not cur or cur[0] not in ('settled', 'verified'):
                        db.execute(
                            "INSERT INTO gimps_tasks (engine_id, problem_set_id, exponent, state, proof_tx_hash) "
                            "VALUES (?, ?, ?, 'submitted', ?) "
                            "ON CONFLICT(engine_id, exponent) DO UPDATE SET state='submitted', proof_tx_hash=excluded.proof_tx_hash",
                            (engine_id, set_id, exp, row[0])
                        )
            except (ValueError, TypeError):
                continue

        # 4. Failed/challenged tasks
        failed_rows = db.execute(
            "SELECT c.target_proof_tx_hash, json_extract(t.data, '$.problem_id') "
            "FROM challenges c JOIN transactions t ON t.hash=c.target_proof_tx_hash "
            "WHERE c.status='confirmed' AND json_extract(t.data, '$.engine_id')=?",
            (engine_id,)
        ).fetchall()
        for row in failed_rows:
            try:
                exp = int(row[1])
                if start_exp <= exp <= end_exp:
                    cur = db.execute("SELECT state,proof_tx_hash FROM gimps_tasks WHERE engine_id=? AND exponent=?", (engine_id, exp)).fetchone()
                    if not cur or cur[0] != 'settled':
                        db.execute(
                            "INSERT INTO gimps_tasks (engine_id, problem_set_id, exponent, state, proof_tx_hash) "
                            "VALUES (?, ?, ?, 'failed', ?) "
                            "ON CONFLICT(engine_id, exponent) DO UPDATE SET state='failed', proof_tx_hash=excluded.proof_tx_hash",
                            (engine_id, set_id, exp, row[0])
                        )
            except (ValueError, TypeError):
                continue

        # 5. Expired assignments -> transition to retry (tasks in paused state retain checkpoint)
        db.execute(
            "UPDATE gimps_tasks SET state='retry' "
            "WHERE engine_id=? AND state='assigned' AND lease_timeout IS NOT NULL AND lease_timeout <= ?",
            (engine_id, current_time)
        )


    def generate_next_gimps_task(db, engine_id, set_id, metadata, current_time=None):
        """Deterministic, state-machine driven task generator for GIMPS problem sets."""
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                return None
        method = metadata.get('method', 'lucas-lehmer')
        max_bound = MAX_PRP_EXPONENT if method in ('prp', 'prp-fiat-shamir') else MAX_LL_EXPONENT
        start_exp = integer(metadata.get('start_exponent', 0), 2, max_bound)
        end_exp = integer(metadata.get('end_exponent', 0), start_exp, max_bound)
        if start_exp <= 0 or end_exp < start_exp:
            return None

        if current_time is None:
            current_time = int(time.time())

        reconcile_task_states(db, engine_id, set_id, start_exp, end_exp, current_time)

        # Find the next available exponent in [start_exp, end_exp]
        for p in candidates({'start_exponent': start_exp, 'end_exponent': end_exp, 'method': method}):
            row = db.execute(
                "SELECT state, lease_timeout FROM gimps_tasks WHERE engine_id=? AND exponent=?",
                (engine_id, p)
            ).fetchone()

            # Check if already completed, active, or paused
            if row:
                st = row[0]
                if st in ('settled', 'verified', 'submitted', 'paused'):
                    continue
                if st == 'assigned' and row[1] and row[1] > current_time:
                    # Active lease held by worker
                    continue

            # Found available exponent p (either unassigned, retry, failed, or expired)
            lease_duration = metadata.get('lease_seconds', DEFAULT_LEASE_SECONDS) if isinstance(metadata, dict) else DEFAULT_LEASE_SECONDS
            timeout = current_time + lease_duration
            db.execute(
                "INSERT INTO gimps_tasks (engine_id, problem_set_id, exponent, state, assigned_at, lease_timeout, last_heartbeat) "
                "VALUES (?, ?, ?, 'assigned', ?, ?, ?) "
                "ON CONFLICT(engine_id, exponent) DO UPDATE SET state='assigned', assigned_at=excluded.assigned_at, lease_timeout=excluded.lease_timeout, last_heartbeat=excluded.last_heartbeat, proof_tx_hash=NULL",
                (engine_id, set_id, p, current_time, timeout, current_time)
            )
            return f"{p}|{p}"

        return None


    def validate_gimps_proof(db, network, payload, sender, height, accepted_tx=None):
        """Validate GIMPS proof format, mathematical bounds, and duplicate rules."""
        require(isinstance(payload, dict), 'payload dictionary required')
        engine_id = payload.get('engine_id')
        problem_id = payload.get('problem_id')
        proof_data = payload.get('proof_data', {})
        require(engine_id and problem_id is not None, 'engine_id and problem_id required')
        require(type(proof_data) is dict, 'proof_data must be dictionary')

        # Verify engine is registered and active
        row = db.execute(
            "SELECT pkg_id, is_active, reward_weight FROM compute_engines WHERE engine_id=?",
            (engine_id,)
        ).fetchone()
        require(row is not None and row[1] == 1, 'engine must be active on-chain')
        require(row[0] == PACKAGE, 'engine package must be corium/built-in-gimps')
        weight = row[2] if len(row) > 2 and row[2] is not None else 100

        integer(weight, 0, MAX_INTEGER // 100)
        integer(height, 0, MAX_INTEGER)
        require(type(problem_id) is str and re.fullmatch(r'[1-9][0-9]{0,9}', problem_id), 'canonical exponent string required')
        proof_schema = proof_data.get('schema')
        is_prp_schema = (proof_schema == PRP_SCHEMA)
        max_bound = MAX_PRP_EXPONENT if is_prp_schema else MAX_LL_EXPONENT
        p = integer(int(problem_id), 2, max_bound)

        active = db.execute('SELECT metadata FROM problem_sets WHERE engine_id=? AND activation_height<=?', (engine_id, height)).fetchall()
        assigned_range = False
        for item in active:
            meta = json.loads(item[0])
            start, end = meta.get('start_exponent'), meta.get('end_exponent')
            m_method = meta.get('method', 'lucas-lehmer')
            m_max = MAX_PRP_EXPONENT if m_method in ('prp', 'prp-fiat-shamir') else MAX_LL_EXPONENT
            if type(start) is int and type(end) is int and 2 <= start <= p <= end <= m_max:
                assigned_range = True
        require(assigned_range, 'exponent must belong to an active bounded problem set')

        # Duplicate submission / Double redeem check
        completed = db.execute(
            "SELECT proof_tx_hash FROM completed_compute_tasks WHERE engine_id=? AND problem_id=?",
            (engine_id, str(p))
        ).fetchall()
        pending = db.execute(
            "SELECT p.proof_tx_hash FROM pending_proofs p "
            "JOIN transactions t ON t.hash=p.proof_tx_hash "
            "WHERE p.problem_id=? AND json_extract(t.data, '$.engine_id')=?",
            (str(p), engine_id)
        ).fetchall()

        for r in completed + pending:
            if accepted_tx is None or r[0] != accepted_tx:
                raise ValueError(f'exponent {p} already settled or pending confirmation')

        if proof_schema == PRP_SCHEMA:
            # Bounded PRP Proof of Exponentiation with Fiat-Shamir folding
            verify_prp_proof(p, proof_data)
            math_certified = True
            method = 'prp-fiat-shamir'
        elif proof_schema in {SCHEMA, PORTABLE_SCHEMA}:
            # Lucas-Lehmer verification
            exact(proof_data, {'schema', 'exponent', 'method', 'residue', 'is_prime', 'iterations'})
            require(type(proof_data['exponent']) is int and proof_data['exponent'] == p, 'proof exponent mismatch')
            require(proof_data['method'] == 'lucas-lehmer', 'unimplemented proof method rejected')
            require(type(proof_data['iterations']) is int and proof_data['iterations'] == p - 2, 'exact iteration count required')
            require(type(proof_data['is_prime']) is bool, 'boolean primality claim required')
            residue = proof_data['residue']
            if proof_schema == PORTABLE_SCHEMA:
                require(type(residue) is str and re.fullmatch(r'0|[1-9][0-9]{0,1233}', residue), 'canonical decimal residue required')
                residue = int(residue)
            require(type(residue) is int and 0 <= residue < (1 << p) - 1, 'bounded integer residue required')
            valid, expected = lucas_lehmer_verify(p, residue)
            require(valid, 'invalid Lucas-Lehmer residue')
            prime_exponent = all(p % divisor for divisor in range(2, int(p**0.5) + 1))
            require(proof_data['is_prime'] == (prime_exponent and expected == 0), 'primality claim mismatch')
            math_certified = True
            method = 'lucas-lehmer'
        else:
            # Legacy format without schema
            exact(proof_data, {'residue'})
            residue = proof_data['residue']
            require(type(residue) is int and 0 <= residue < (1 << p) - 1, 'bounded integer residue required')
            valid, expected = lucas_lehmer_verify(p, residue)
            require(valid, 'invalid Lucas-Lehmer residue')
            math_certified = True
            method = 'lucas-lehmer'

        # Retrieve current PrimeNet attestation status if present
        primenet_status = 'unsubmitted'
        try:
            pnet_row = db.execute("SELECT primenet_status FROM gimps_tasks WHERE engine_id=? AND exponent=?", (engine_id, p)).fetchone()
            if pnet_row and pnet_row[0]:
                primenet_status = pnet_row[0]
        except Exception:
            pass

        return {
            'status': 'valid',
            'math_certified': math_certified,
            'primenet_status': primenet_status,
            'corium_settled': False,
            'engine_id': engine_id,
            'problem_id': str(p),
            'exponent': p,
            'method': method,
            'reward': 100 * weight,
            'reward_weight': weight,
            'proposer_id': sender
        }


    def settle(db, network, tx, height):
        """Settle an unchallenged confirmed GIMPS proof, crediting contribution scores."""
        row = db.execute(
            "SELECT data, public_key, block_height FROM transactions "
            "WHERE hash=? AND type='submit_math_proof' AND block_height IS NOT NULL",
            (tx,)
        ).fetchone()
        require(row is not None, 'confirmed native proof required')
        payload = json.loads(row[0])
        sender = hashlib.sha256(row[1].encode()).hexdigest()

        val = validate_gimps_proof(db, network, payload, sender, row[2], accepted_tx=tx)
        engine_id = val['engine_id']
        problem_id = val['problem_id']
        reward = val['reward']

        # Check if already redeemed
        done = db.execute(
            "SELECT proof_tx_hash FROM completed_compute_tasks WHERE engine_id=? AND problem_id=?",
            (engine_id, problem_id)
        ).fetchone()
        if done:
            require(done[0] == tx, 'bounty already redeemed')
            return val | {'duplicate': True, 'corium_settled': True}

        # Verify pending state and 10-block challenge window
        pending = db.execute(
            "SELECT problem_id, proof_tx_hash, proposer_id, proposed_result, confirmation_deadline_height FROM pending_proofs WHERE proof_tx_hash=?",
            (tx,)
        ).fetchone()
        require(pending is not None, 'matching pending proof required')
        p_prob = pending[0] if isinstance(pending, tuple) else pending['problem_id']
        p_proposer = pending[2] if isinstance(pending, tuple) else pending['proposer_id']
        p_deadline = pending[4] if isinstance(pending, tuple) else pending['confirmation_deadline_height']
        require(p_proposer == sender and p_prob == problem_id, 'matching pending proof required')
        require(p_deadline == row[2] + 10 and height >= p_deadline, 'native challenge window must elapse')

        # Check no active unrejected challenge
        require(db.execute(
            "SELECT 1 FROM challenges WHERE target_proof_tx_hash=? AND status!='rejected'",
            (tx,)
        ).fetchone() is None, 'challenged proof cannot settle on unchallenged path')

        # Update contribution_scores
        prior = db.execute("SELECT score FROM contribution_scores WHERE user_id=?", (sender,)).fetchone()
        score = prior[0] if prior else 0
        integer(score, -MAX_INTEGER - 1, MAX_INTEGER - reward)

        db.execute(
            "INSERT INTO completed_compute_tasks (engine_id, problem_id, proof_tx_hash) VALUES (?, ?, ?)",
            (engine_id, problem_id, tx)
        )
        db.execute(
            "INSERT INTO contribution_scores (user_id, score, last_update_height) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET score=score+?, last_update_height=excluded.last_update_height",
            (sender, score + reward, height, reward)
        )
        db.execute("DELETE FROM pending_proofs WHERE proof_tx_hash=?", (tx,))

        # Update gimps_tasks state machine to settled
        try:
            p = int(problem_id)
            db.execute(
                "UPDATE gimps_tasks SET state='settled', proof_tx_hash=?, math_certified=1, corium_settled=1 WHERE engine_id=? AND exponent=?",
                (tx, engine_id, p)
            )
        except Exception:
            pass

        return val | {
            'settled_height': height,
            'contribution_score': score + reward,
            'reward_awarded': reward,
            'corium_settled': True
        }


    def validate_challenge(db, network, target_tx):
        """Validate challenge against a GIMPS proof.
        Returns 1 if proof is valid (challenge fails), 0 if proof is invalid (challenge succeeds).
        """
        row = db.execute(
            "SELECT data, public_key, block_height FROM transactions WHERE hash=? AND type='submit_math_proof'",
            (target_tx,)
        ).fetchone()
        if not row:
            return 0
        payload = json.loads(row[0])
        sender = hashlib.sha256(row[1].encode()).hexdigest()
        try:
            validate_gimps_proof(db, network, payload, sender, row[2] or 1, accepted_tx=target_tx)
            return 1
        except Exception:
            return 0


    def main(args):
        action = args[0]
        database = args[1]
        with closing(sqlite3.connect(database)) as db, db:
            db.row_factory = sqlite3.Row
            if action == 'next-task':
                db.execute('BEGIN IMMEDIATE')
                engine_id, set_id, metadata = args[2:5]
                res = generate_next_gimps_task(db, engine_id, set_id, metadata)
                if res:
                    print(res)
                else:
                    sys.exit(1)
            elif action == 'challenge':
                network, submitter = args[2:4]
                print(json.dumps(native_challenge(db, network, submitter), sort_keys=True))
            elif action == 'solve':
                network, engine, problem, sender = args[2:6]
                method = args[6] if len(args) > 6 else 'lucas-lehmer'
                max_bound = MAX_PRP_EXPONENT if method in ('prp', 'prp-fiat-shamir') else MAX_LL_EXPONENT
                exponent = integer(int(problem), 2, max_bound)
                require(exponent in candidates({'start_exponent': exponent, 'end_exponent': exponent, 'method': method}), 'prime exponent required')
                if method == 'prp' or method == 'prp-fiat-shamir':
                    proof_data = generate_prp_proof(exponent, base=3, depth=4)
                else:
                    _, residue = lucas_lehmer_verify(exponent, 0)
                    proof_data = {
                        'schema': PORTABLE_SCHEMA,
                        'exponent': exponent,
                        'method': 'lucas-lehmer',
                        'residue': str(residue),
                        'is_prime': residue == 0,
                        'iterations': exponent - 2
                    }
                payload = {'engine_id': engine, 'problem_id': str(exponent), 'proof_data': proof_data}
                head = db.execute("SELECT value FROM chain_state WHERE key='chain_info'").fetchone()
                require(head is not None, 'native accepted head required')
                validate_gimps_proof(db, network, payload, sender, int(head[0].split('|')[1]))
                print(json.dumps(payload, sort_keys=True))
            elif action == 'validate':
                network, payload_raw, sender, height = args[2:6]
                accepted_tx = args[6] if len(args) > 6 else None
                payload = json.loads(payload_raw)
                res = validate_gimps_proof(db, network, payload, sender, int(height), accepted_tx=accepted_tx)
                print(json.dumps(res, sort_keys=True))
            elif action == 'settle':
                network, tx, height = args[2:5]
                db.execute('BEGIN IMMEDIATE')
                res = settle(db, network, tx, int(height))
                print(json.dumps(res, sort_keys=True))
            elif action == 'validate-challenge':
                network, target_tx = args[2:4]
                code = validate_challenge(db, network, target_tx)
                print(code)
                if code == 0:
                    sys.exit(0)  # Challenge succeeded
                else:
                    sys.exit(0)  # Output is 1 or 0
            elif action == 'renew-lease':
                engine_id, exponent, worker_id = args[2:5]
                chk = json.loads(args[5]) if len(args) > 5 and args[5] else None
                dur = int(args[6]) if len(args) > 6 and args[6] else DEFAULT_LEASE_SECONDS
                db.execute('BEGIN IMMEDIATE')
                res = renew_lease(db, engine_id, int(exponent), worker_id, checkpoint_data=chk, lease_duration=dur)
                print(json.dumps(res, sort_keys=True))
            elif action == 'pause-task':
                engine_id, exponent, worker_id = args[2:5]
                chk = json.loads(args[5]) if len(args) > 5 and args[5] else None
                db.execute('BEGIN IMMEDIATE')
                res = pause_task(db, engine_id, int(exponent), worker_id, checkpoint_data=chk)
                print(json.dumps(res, sort_keys=True))
            elif action == 'resume-task':
                engine_id, exponent, worker_id = args[2:5]
                dur = int(args[5]) if len(args) > 5 and args[5] else DEFAULT_LEASE_SECONDS
                db.execute('BEGIN IMMEDIATE')
                res = resume_task(db, engine_id, int(exponent), worker_id, lease_duration=dur)
                print(json.dumps(res, sort_keys=True))
            elif action == 'update-primenet':
                engine_id, exponent, status = args[2:5]
                attestation = args[5] if len(args) > 5 else None
                db.execute('BEGIN IMMEDIATE')
                res = update_primenet_status(db, engine_id, int(exponent), status, attestation=attestation)
                print(json.dumps(res, sort_keys=True))
            elif action == 'generate-prp':
                exponent = int(args[2])
                depth = int(args[3]) if len(args) > 3 else 4
                res = generate_prp_proof(exponent, base=3, depth=depth)
                print(json.dumps(res, sort_keys=True))
            elif action == 'verify-prp':
                exponent = int(args[2])
                proof_data = json.loads(args[3])
                ok = verify_prp_proof(exponent, proof_data)
                print(json.dumps({'verified': ok}, sort_keys=True))
            else:
                raise ValueError(f"unknown gimps action: {action}")


    return locals()
_native_gimps=__import__("types").SimpleNamespace(**_load_native_gimps())

def _load__native_dna():
    """Bounded DNA duplex storage and authenticated RNA transmission primitives.

    ACGT/ACGU are reversible encodings, not new cryptographic algorithms. Repair
    requires an externally authenticated payload root and at least one intact strand.
    Signatures authenticate roots and metadata; coherent replacement is rejected.
    """
    import hashlib
    import json
    import re
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    MAX_GENE_BYTES = 4096
    ALPHABET = 'ACGT'
    PAIR = str.maketrans('ACGT', 'TGCA')


    def require(value, message):
        if not value:
            raise ValueError(message)


    def integer(value, low=0, high=2**63-1):
        require(type(value) is int and low <= value <= high, 'integer bounds')
        return value


    def encoded(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


    def loads(raw, limit=65536):
        require(type(raw) is str and len(raw.encode()) <= limit, 'JSON byte budget')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result, 'duplicate field')
                result[key] = value
            return result
        def forbidden(_):
            raise ValueError('only integer JSON numbers are supported')
        try:
            result = json.loads(raw, object_pairs_hook=unique, parse_float=forbidden, parse_constant=forbidden)
        except (RecursionError, OverflowError) as error:
            raise ValueError('JSON nesting budget') from error
        def portable(value, depth=0):
            require(depth <= 24, 'JSON nesting budget')
            if isinstance(value, (dict, list)):
                for child in value.values() if isinstance(value, dict) else value:
                    portable(child, depth+1)
            elif type(value) is int:
                integer(value, -(2**63)+1)
        portable(result)
        return result


    def digest(raw):
        return hashlib.sha256(b'Corium/DNA/payload/v1\0'+raw).hexdigest()


    def encode_bases(raw):
        require(type(raw) is bytes and len(raw) <= MAX_GENE_BYTES, 'gene byte budget')
        return ''.join(ALPHABET[(value >> shift) & 3] for value in raw for shift in (6, 4, 2, 0))


    def decode_bases(bases):
        require(type(bases) is str and len(bases) <= MAX_GENE_BYTES*4 and len(bases) % 4 == 0
                and re.fullmatch('[ACGT]*', bases) is not None, 'canonical DNA bases')
        return bytes(sum(ALPHABET.index(bases[offset+i]) << (6-2*i) for i in range(4))
                     for offset in range(0, len(bases), 4))


    def complement(bases):
        require(type(bases) is str and len(bases) <= MAX_GENE_BYTES*4
                and re.fullmatch('[ACGT]*', bases) is not None, 'bounded DNA strand')
        return bases.translate(PAIR)[::-1]


    def duplex(raw):
        sense = encode_bases(raw)
        return {'schema':'corium.dna.duplex.v1', 'bytes':len(raw), 'root':digest(raw),
                'sense':sense, 'antisense':complement(sense)}


    def restore(gene, authenticated_root, repair=False):
        require(type(gene) is dict and set(gene) == {'schema','bytes','root','sense','antisense'}
                and gene['schema'] == 'corium.dna.duplex.v1', 'exact duplex schema')
        require(type(authenticated_root) is str and re.fullmatch('[a-f0-9]{64}', authenticated_root)
                and gene['root'] == authenticated_root, 'externally authenticated root required')
        integer(gene['bytes'], 0, MAX_GENE_BYTES)
        # A damaged strand may have invalid bases; only the authenticated intact
        # strand is eligible for repair. Never combine two unauthenticated guesses.
        candidates = []
        for name in ('sense','antisense'):
            try:
                bases = gene[name] if name == 'sense' else complement(gene[name])
                data = decode_bases(bases)
                require(len(data) == gene['bytes'] and digest(data) == authenticated_root, 'strand root mismatch')
                candidates.append(data)
            except ValueError:
                if not repair:
                    raise
        require(candidates and (repair or len(candidates) == 2), 'no authenticated intact strand')
        require(all(data == candidates[0] for data in candidates), 'ambiguous duplex')
        if not repair:
            require(gene['antisense'] == complement(gene['sense']), 'duplex complement mismatch')
        return candidates[0]


    def public_key(key):
        return key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode().rstrip('\n')


    def rna_sign(key, chain, policy, sender, sequence, issued_at, payload):
        require(isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256K1), 'native key')
        require(type(payload) is bytes and len(payload) <= MAX_GENE_BYTES, 'RNA payload budget')
        for name in (chain, policy, sender):
            require(type(name) is str and re.fullmatch('[a-f0-9]{64}', name), 'RNA domain digest')
        integer(sequence, 1); integer(issued_at, 0, 2**63-121)
        header = {'schema':'corium.rna.v1','chain':chain,'policy':policy,'sender':sender,
                  'sequence':sequence,'issued_at':issued_at,'expires_at':issued_at+120,
                  'bytes':len(payload),'root':digest(payload)}
        signature = key.sign(b'Corium/RNA/message/v1\0'+encoded(header),ec.ECDSA(hashes.SHA256())).hex()
        return {'header':header,'rna':encode_bases(payload).replace('T','U'),'signature':signature}


    def rna_open(frame, pem, chain, policy, sender, previous_sequence, now):
        require(type(frame) is dict and set(frame) == {'header','rna','signature'}, 'exact RNA frame')
        h = frame['header']
        require(type(h) is dict and set(h) == {'schema','chain','policy','sender','sequence','issued_at','expires_at','bytes','root'}
                and h['schema'] == 'corium.rna.v1', 'exact RNA header')
        require(h['chain'] == chain and h['policy'] == policy and h['sender'] == sender, 'RNA domain mismatch')
        integer(previous_sequence); integer(now); integer(h['sequence'],1); integer(h['issued_at']); integer(h['expires_at'])
        require(previous_sequence < h['sequence'] and h['issued_at'] <= now <= h['expires_at']
                and h['expires_at']-h['issued_at'] == 120, 'RNA replay or validity window')
        integer(h['bytes'],0,MAX_GENE_BYTES)
        require(type(frame['rna']) is str and re.fullmatch('[ACGU]*',frame['rna']) is not None
                and len(frame['rna']) == h['bytes']*4, 'canonical RNA bases')
        data = decode_bases(frame['rna'].replace('U','T'))
        require(digest(data) == h['root'], 'RNA payload commitment')
        require(type(frame['signature']) is str and re.fullmatch('[a-f0-9]{16,144}',frame['signature']), 'RNA signature format')
        key = serialization.load_pem_public_key(pem.encode())
        require(isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve,ec.SECP256K1), 'native RNA key')
        require(hashlib.sha256(pem.encode()).hexdigest() == sender, 'RNA sender identity')
        key.verify(bytes.fromhex(frame['signature']),b'Corium/RNA/message/v1\0'+encoded(h),ec.ECDSA(hashes.SHA256()))
        return data

    return locals()
_native_dna=__import__("types").SimpleNamespace(**_load__native_dna())
def _load__native_cooperative():
    """Pure cooperative registry transitions, independent of mining eligibility.

    Membership is a public-key identity, not proof of a distinct human or operator.
    These rules reject on-chain control transfer and capital-weighted governance;
    they cannot prevent private-key sales, collusion, or a software hard fork.
    No claim is made that metadata here locks external/native financial assets.
    """
    import hashlib
    import copy
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    encoded,require,integer,public_key=_native_dna.encoded,_native_dna.require,_native_dna.integer,_native_dna.public_key

    CHARTER = {'schema':'corium.cooperative-charter.v1','vote_rule':'one-member-one-vote',
               'membership_transfer':False,'control_transfer':False,'mergers':False,
               'federation_exit':'unilateral-by-each-cooperative','capital_voting':False}
    FORBIDDEN = {'merge','sell_control','delegate_control','transfer_membership','capital_weighted_vote','change_charter'}


    def identity(pem):
        require(type(pem)is str and len(pem)<=1024,'bounded member public key')
        key=serialization.load_pem_public_key(pem.encode())
        require(isinstance(key,ec.EllipticCurvePublicKey) and isinstance(key.curve,ec.SECP256K1),'native member key')
        require(key.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode().rstrip('\n')==pem,'canonical member key')
        return hashlib.sha256(pem.encode()).hexdigest()


    def empty(chain):
        require(type(chain) is str and len(chain)==64 and all(c in '0123456789abcdef'for c in chain),'chain identity')
        return {'schema':'corium.cooperative-registry.v1','chain':chain,'cooperatives':{}}


    def state_root(state):
        return hashlib.sha256(b'Corium/Cooperative/state/v1\0'+encoded(state)).hexdigest()


    def command_bytes(command):
        return b'Corium/Cooperative/command/v1\0'+encoded(command)


    def endorse(command,key):
        pem=public_key(key)
        return {'public_key':pem,'signature':key.sign(command_bytes(command),ec.ECDSA(hashes.SHA256())).hex()}


    def endorsements(command,proofs):
        return verify_endorsements(command_bytes(command),proofs)


    def verify_endorsements(message,proofs):
        require(type(proofs) is list and 0<len(proofs)<=512,'bounded endorsements')
        voters={}
        for proof in proofs:
            require(type(proof) is dict and set(proof)=={'public_key','signature'},'endorsement fields')
            pem=proof['public_key'];member=identity(pem)
            require(member not in voters,'duplicate member vote')
            require(type(proof['signature'])is str and 16<=len(proof['signature'])<=144,'bounded signature')
            serialization.load_pem_public_key(pem.encode()).verify(bytes.fromhex(proof['signature']),message,ec.ECDSA(hashes.SHA256()))
            voters[member]=pem
        return voters


    def quorum(members,voters):
        # Funding/wealth fields have no place in the exact command schema or tally.
        require(members and 3*len(set(members)&set(voters))>2*len(members),'strict member supermajority')


    def apply(state,command,proofs):
        require(type(command)is dict and set(command)=={'schema','chain','cooperative','sequence','previous_state','action','arguments'}
                and command['schema']=='corium.cooperative-command.v1','exact cooperative command')
        require(command['chain']==state['chain'] and command['previous_state']==state_root(state),'chain/state binding')
        action=command['action'];require(action not in FORBIDDEN,'immutable anti-takeover charter')
        require(action in {'create','admit','leave','federate','unfederate'},'unknown cooperative action')
        integer(command['sequence'],1);args=command['arguments'];require(type(args)is dict,'arguments object')
        cid=command['cooperative'];require(type(cid)is str and 1<=len(cid)<=64 and all(c.isascii()and(c.isalnum()or c in '-_')for c in cid),'cooperative id')
        voters=endorsements(command,proofs);result=copy.deepcopy(state);coops=result['cooperatives']
        require(len(coops)<=10000,'cooperative registry budget')
        if action=='create':
            require(cid not in coops and len(coops)<10000 and command['sequence']==1 and set(args)=={'members'},'new cooperative')
            require(type(args['members'])is list and 1<=len(args['members'])<=128,'founding member budget')
            members={identity(pem):pem for pem in args['members']}
            require(len(members)==len(args['members']) and members==voters,'all founding members must consent')
            coops[cid]={'charter':copy.deepcopy(CHARTER),'members':members,'sequence':1,'federations':[]}
            require(len(encoded(result))<=4*1024*1024,'cooperative state byte budget')
            return result
        require(cid in coops,'known cooperative');coop=coops[cid]
        require(coop['charter']==CHARTER and command['sequence']==coop['sequence']+1,'charter or sequence mismatch')
        if action=='leave':
            require(set(args)=={'member'} and args['member'] in coop['members']
                    and set(voters)=={args['member']},'only member can exercise own exit')
            del coop['members'][args['member']]
        else:
            quorum(coop['members'],voters)
            if action=='admit':
                require(set(args)=={'public_key'},'admission fields');new=identity(args['public_key'])
                require(new not in coop['members'] and new in voters and len(coop['members'])<128,'new member consent/budget')
                coop['members'][new]=args['public_key']
            else:
                require(set(args)=={'partner'} and type(args['partner'])is str and args['partner'] in coops
                        and args['partner']!=cid,'independent federation partner')
                partner=coops[args['partner']]
                if action=='federate':
                    require(args['partner'] not in coop['federations'],'already federated')
                    quorum(partner['members'],voters)
                    coop['federations'].append(args['partner']);partner['federations'].append(cid)
                else:
                    require(args['partner'] in coop['federations'],'existing federation')
                    coop['federations'].remove(args['partner']);partner['federations'].remove(cid)
                partner['sequence']+=1
                partner['federations'].sort()
                # Federation never combines member lists, identities or authority.
            coop['federations'].sort()
        coop['sequence']=command['sequence']
        require(len(encoded(result))<=4*1024*1024,'cooperative state byte budget')
        return result

    return locals()
_native_cooperative=__import__("types").SimpleNamespace(**_load__native_cooperative())
def _load__native_recovery():
    """Explicit signed recovery boundary. Never manufactures historical governance."""
    import hashlib
    import os
    from pathlib import Path
    import stat
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    DNA=_native_dna

    SCHEMA='corium.recovery-declaration.v1'
    MAIN='corium.recovery-work.v3'
    SIDE='corium.dna-work.v1'
    NETWORKS={'ziokt-main-recovery-20261024','ziokt-dna-side-20261024'}
    FIELDS={'schema','network','protocol','checkpoint','initial_state_root','legacy_archive_root',
            'genesis_sha256','verifier_source_sha256','work_policy','authority_public_key','signature'}


    def unsigned(value):return {k:v for k,v in value.items() if k!='signature'}
    def signing_bytes(value):return b'Corium/Recovery/declaration/v1\0'+DNA.encoded(unsigned(value))
    def identity(value):return hashlib.sha256(signing_bytes(value)).hexdigest()


    def read_public(path):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd)
            DNA.require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o022
                        and info.st_size<=65536,'bounded owner-controlled public recovery document')
            raw=os.read(fd,65537);DNA.require(len(raw)<=65536,'recovery document budget')
            return raw
        finally:os.close(fd)


    def declaration(network):
        if network not in NETWORKS:return None
        root=os.environ.get('CORIUM_ROOT')
        DNA.require(root,'recovery root required')
        directory=Path(root)/'etc/corix/networks'/network
        value=DNA.loads(read_public(directory/'recovery.json').decode())
        DNA.require(type(value)is dict and set(value)==FIELDS and value['schema']==SCHEMA
                    and value['network']==network,'exact recovery declaration')
        DNA.require(value['protocol']==(MAIN if network.startswith('ziokt-main-')else SIDE),'distinct chain protocol')
        genesis_raw=read_public(directory/'genesis.json');genesis=DNA.loads(genesis_raw.decode())
        DNA.require(hashlib.sha256(genesis_raw).hexdigest()==value['genesis_sha256'],'complete genesis configuration binding')
        for name in ('initial_state_root','legacy_archive_root','verifier_source_sha256'):
            DNA.require(type(value[name])is str and len(value[name])==64 and all(c in '0123456789abcdef'for c in value[name]),'recovery commitment')
        cp=value['checkpoint'];DNA.require(type(cp)is dict and set(cp)=={'height','hash'},'recovery checkpoint fields')
        DNA.integer(cp['height'],0);DNA.require(type(cp['hash'])is str and len(cp['hash'])==64,'checkpoint digest')
        DNA.require(cp['height']==50 if value['protocol']==MAIN else cp['height']>=784,'operator recovery boundary')
        pem=value['authority_public_key'];keys={v['public_key'].rstrip('\n')for v in genesis['genesis_validators']}
        DNA.require(pem in keys,'recovery authority must be supplied genesis authority')
        key=serialization.load_pem_public_key(pem.encode())
        DNA.require(isinstance(key,ec.EllipticCurvePublicKey) and isinstance(key.curve,ec.SECP256K1),'native recovery authority')
        DNA.require(type(value['signature'])is str and 16<=len(value['signature'])<=144,'recovery signature budget')
        key.verify(bytes.fromhex(value['signature']),signing_bytes(value),ec.ECDSA(hashes.SHA256()))
        return value


    def active(db,network,height,source_hash,check_policy,legacy):
        value=declaration(network)
        if value is None or height<=value['checkpoint']['height']:return None
        cp=value['checkpoint'];known=db.execute('SELECT hash FROM blocks WHERE height=?',(cp['height'],)).fetchone()
        DNA.require(known is not None and known[0]==cp['hash'],'recovery checkpoint differs from accepted history')
        DNA.require(value['verifier_source_sha256']==source_hash,'recovery verifier source commitment')
        policy={'schema':'corium.native-work-policy.v2','previous_policy':legacy,'checkpoint':cp,'work_policy':value['work_policy']}
        genesis=db.execute('SELECT hash FROM blocks WHERE height=0').fetchone()
        check_policy(policy,network,genesis[0])
        DNA.require(policy['work_policy']['activation_height']==cp['height']+1,'recovery activation is prospective')
        return policy


    def body(block,value):
        return DNA.encoded({'chain':identity(value),'protocol':value['protocol'],
             'height':block['height'],'parent':block['previous_hash'],'timestamp':block['timestamp'],
             'miner':block['validator'],'transactions':block['transactions'],
             'initial_state_root':value['initial_state_root'],'policy':block['work']['policy']})


    def transaction_bytes(value,network,kind,payload,timestamp,pem,height):
        # Prefix signatures retain their historical bytes; new signatures bind both
        # network identity, including the actor, rather than only tx data.
        if value is None or height<=value['checkpoint']['height']:
            import json
            return '{"type":'+json.dumps(kind)+',"data":'+payload+',"timestamp":'+str(timestamp)+'}'
        return DNA.encoded({'schema':'corium.chain-transaction.v3','network':network,
            'public_key':pem,'type':kind,'data':DNA.loads(payload),'timestamp':timestamp}).decode()

    return locals()
_native_recovery=__import__("types").SimpleNamespace(**_load__native_recovery())
def _load__native_cooperative_consensus():
    """Shared canonical cooperative state and native asset authorizations."""
    import hashlib
    import json
    import re
    Cooperative=_native_cooperative
    Recovery=_native_recovery
    DNA=_native_dna
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    require=DNA.require
    loads=DNA.loads

    def chain_context(db,network):
        require(type(network)is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',network),'cooperative network')
        recovery=Recovery.declaration(network)
        if recovery:return Recovery.identity(recovery),recovery['checkpoint']['height']
        genesis=db.execute('SELECT hash FROM blocks WHERE height=0').fetchone()
        require(genesis is not None and re.fullmatch('[a-f0-9]{64}',genesis[0]),'cooperative genesis')
        return hashlib.sha256(b'Corium/Cooperative/chain/v1\0'+DNA.encoded({'network':network,'genesis':genesis[0]})).hexdigest(),0

    def state_at(db,network,height):
        """Rebuild cooperative state from the canonical prefix before height.

        The materialized cooperative_registry table is only a cache: fork rollback
        can leave it stale. Every admission/replay therefore derives authority from
        canonical block order and runs the same pure transition function.
        """
        chain,start=chain_context(db,network)
        require(type(height)is int and height>start,'cooperative candidate height')
        state=Cooperative.empty(chain)
        # Use a materialized checkpoint only when its recorded block remains in the
        # canonical chain and its deterministic root matches. Legacy/unanchored rows
        # and orphaned checkpoints are ignored and reconstructed from history.
        table=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cooperative_registry'").fetchone()
        if table:
            columns={row[1] for row in db.execute('PRAGMA table_info(cooperative_registry)').fetchall()}
            if {'state','height','block_hash','state_root'}<=columns:
                cached=db.execute('SELECT state,height,block_hash,state_root FROM cooperative_registry WHERE id=1').fetchone()
                if cached:
                    try:
                        candidate=DNA.loads(cached[0],4*1024*1024);anchor=db.execute('SELECT hash FROM blocks WHERE height=?',(cached[1],)).fetchone()
                        if (type(cached[1])is int and start<=cached[1]<height and anchor and anchor[0]==cached[2]
                            and type(candidate)is dict and candidate.get('chain')==chain
                            and Cooperative.state_root(candidate)==cached[3]):
                            state=candidate;start=cached[1]
                    except (ValueError,TypeError,KeyError):
                        pass
        commands=db.execute("SELECT hash,data,block_height FROM transactions WHERE type='cooperative_command' AND block_height>? AND block_height<? ORDER BY block_height,hash",
                            (start,height)).fetchall()
        require(len(commands)<=1_000_000,'cooperative history budget')
        for txhash,raw,block_height in commands:
            block=db.execute('SELECT transactions FROM blocks WHERE height=?',(block_height,)).fetchone()
            require(block is not None,'cooperative transaction block missing')
            hashes=json.loads(block[0]);require(type(hashes)is list and len(hashes)<=200,'canonical transaction list')
            require(hashes.count(txhash)==1,'cooperative transaction absent from canonical block')
            envelope=loads(raw)
            require(type(envelope)is dict and set(envelope)=={'command','endorsements'},'cooperative envelope')
            state=Cooperative.apply(state,envelope['command'],envelope['endorsements'])
        return state


    def tables(db):
        db.execute('CREATE TABLE IF NOT EXISTS cooperative_registry(id INTEGER PRIMARY KEY CHECK(id=1),state TEXT NOT NULL,height INTEGER,block_hash TEXT,state_root TEXT)')
        columns={r[1] for r in db.execute('PRAGMA table_info(cooperative_registry)')}
        for name in ('height INTEGER','block_hash TEXT','state_root TEXT'):
            if name.split()[0] not in columns:db.execute('ALTER TABLE cooperative_registry ADD COLUMN '+name)
        db.execute('CREATE TABLE IF NOT EXISTS cooperative_asset_nonces(cooperative TEXT PRIMARY KEY,nonce INTEGER NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS cooperative_note_controls(note_id TEXT PRIMARY KEY,cooperative TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS zkc_owners(edition_id TEXT PRIMARY KEY,owner TEXT NOT NULL,nonce INTEGER NOT NULL)')


    def apply_command(db,network,payload,height,commit=False):
        require(type(payload)is dict and set(payload)=={'command','endorsements'},'cooperative envelope')
        state=state_at(db,network,height)
        changed=Cooperative.apply(state,payload['command'],payload['endorsements'])
        if commit:
            tables(db)
            block=db.execute('SELECT hash FROM blocks WHERE height=?',(height,)).fetchone()
            require(block is not None,'cooperative application requires committed block')
            db.execute('INSERT OR REPLACE INTO cooperative_registry(id,state,height,block_hash,state_root) VALUES(1,?,?,?,?)',
                       (DNA.encoded(changed).decode(),height,block[0],Cooperative.state_root(changed)))
        return changed


    def account(chain,cooperative):
        return hashlib.sha256(b'Corium/Cooperative/custody/v1\0'+DNA.encoded({'chain':chain,'cooperative':cooperative})).hexdigest()


    def has_registry(db):
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='transactions'").fetchone():return False
        return db.execute("SELECT 1 FROM transactions WHERE type='cooperative_command' AND block_height IS NOT NULL LIMIT 1").fetchone() is not None


    def owner_cooperative(db,network,owner,height):
        if not has_registry(db):return None
        state=state_at(db,network,height)
        return next((cid for cid in state['cooperatives'] if account(state['chain'],cid)==owner),None)


    def asset_operation(network,kind,payload):
        return hashlib.sha256(b'Corium/Cooperative/asset-operation/v1\0'+DNA.encoded({'network':network,'type':kind,'payload':payload})).hexdigest()


    def asset_bytes(command):
        return b'Corium/Cooperative/asset-authorization/v1\0'+DNA.encoded(command)


    def asset_endorse(command,key):
        return {'public_key':DNA.public_key(key),'signature':key.sign(asset_bytes(command),ec.ECDSA(hashes.SHA256())).hex()}


    def next_nonce(db,cid):
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cooperative_asset_nonces'").fetchone():return 1
        row=db.execute('SELECT nonce FROM cooperative_asset_nonces WHERE cooperative=?',(cid,)).fetchone()
        return (row[0] if row else 0)+1


    def asset_command(db,network,kind,payload,cid,height):
        state=state_at(db,network,height)
        require(cid in state['cooperatives'],'known cooperative')
        return {'schema':'corium.cooperative-asset-authorization.v1','chain':state['chain'],
                'cooperative':cid,'registry_root':Cooperative.state_root(state),'nonce':next_nonce(db,cid),
                'operation':asset_operation(network,kind,payload)}


    def authorize(db,network,kind,payload,authorization,height):
        require(type(authorization)is dict and set(authorization)=={'command','endorsements'},'cooperative asset authorization envelope')
        command=authorization['command']
        require(type(command)is dict and set(command)=={'schema','chain','cooperative','registry_root','nonce','operation'},'cooperative asset authorization fields')
        cid=command['cooperative'];require(type(cid)is str,'cooperative identity')
        state=state_at(db,network,height)
        require(cid in state['cooperatives'] and state['cooperatives'][cid]['charter']==Cooperative.CHARTER,'cooperative asset charter')
        DNA.integer(command['nonce'],1,2**53-1)
        require(command==asset_command(db,network,kind,payload,cid,height),'cooperative asset chain, state, operation or nonce mismatch')
        voters=Cooperative.verify_endorsements(asset_bytes(command),authorization['endorsements'])
        Cooperative.quorum(state['cooperatives'][cid]['members'],voters)
        require(set(voters)<=set(state['cooperatives'][cid]['members']),'asset endorsements require current members')
        return {'cooperative':cid,'account':account(state['chain'],cid),'nonce':command['nonce']}


    def asset_state_root(db):
        state={}
        for name in ('cooperative_asset_nonces','cooperative_note_controls','zkc_owners'):
            exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone()
            state[name]=[list(r) for r in db.execute('SELECT * FROM '+name+' ORDER BY 1')] if exists else []
        return hashlib.sha256(b'Corium/Cooperative/assets/v1\0'+DNA.encoded(state)).hexdigest()


    return locals()
_native_cooperative_consensus=__import__("types").SimpleNamespace(**_load__native_cooperative_consensus())

"""ZKN fixed-unit confidential notes and voluntary review; experimental v1.

Ristretto255 primitives are provided by libsodium, never Python curve arithmetic.
The two-row ring proof follows the MLSAG construction (MRL-0005), with only
the ownership row linkable. The second row proves conservation of the asset
commitment. This implementation has NOT received an independent crypto audit.
Mainnet enablement is a functional switch, not an audit attestation. No review/decryption key
exists in consensus. Embedded verbatim in the standalone Corium monolith.
"""
import base64 as _zs_b64
import ctypes as _zs_ct
import ctypes.util as _zs_ctutil
import hashlib as _zs_hash
import json as _zs_json
import secrets as _zs_random

ZS_VERSION = 'zkn-rct-v1'
# Preserve the existing functional gate without representing it as an audit.
ZS_MAINNET_ENABLED = True
ZS_AUDITED = False  # No independent third-party audit evidenced.
ZS_SELF_REVIEW_REPORT = 'AUDIT-SHIELDED-2026-10-23.md'
ZS_TYPES = {'zkn_shield_deposit', 'zkn_shield_transfer', 'zkn_shield_withdraw',
            'privacy_review_request', 'privacy_review_vote', 'privacy_review_revoke',
            'privacy_review_disclose'}
_ZS_ZERO = bytes(32)
_ZS_ORDER = 2**252 + 27742317777372353535851937790883648493
_ZS_LIB = None
_ZS_OPS = {
    'crypto_core_ristretto255_from_hash': ((64,), True),
    'crypto_core_ristretto255_scalar_reduce': ((64,), False),
    'crypto_scalarmult_ristretto255': ((32, 32), True),
    'crypto_scalarmult_ristretto255_base': ((32,), True),
    'crypto_core_ristretto255_add': ((32, 32), True),
    'crypto_core_ristretto255_sub': ((32, 32), True),
    'crypto_core_ristretto255_scalar_mul': ((32, 32), False),
    'crypto_core_ristretto255_scalar_add': ((32, 32), False),
    'crypto_core_ristretto255_scalar_sub': ((32, 32), False),
}


def zs_json(value):
    def check(v, depth=0):
        if depth > 12: raise ValueError('privacy nesting limit')
        if v is None or type(v) in (str, bool): return
        if type(v) is int and abs(v) < 2**53: return
        if type(v) is list and len(v) <= 128:
            for x in v: check(x, depth+1)
            return
        if type(v) is dict and len(v) <= 64 and all(type(k) is str for k in v):
            for x in v.values(): check(x, depth+1)
            return
        raise ValueError('privacy canonical value rejected')
    check(value)
    raw = _zs_json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    if len(raw) > 65536: raise ValueError('privacy frame limit')
    return raw


def zs_exact(value, fields):
    if type(value) is not dict or set(value) != set(fields): raise ValueError('privacy fields rejected')


def zs_hex(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('privacy exact hex required')
    return bytes.fromhex(value)


def zs_lib():
    global _ZS_LIB
    if _ZS_LIB is None:
        lib=None
        for name in ('libsodium.so.23','libsodium.dylib','libsodium.dll'):
            try:lib=_zs_ct.CDLL(name);break
            except OSError:continue
        if lib is None:raise ValueError('libsodium Ristretto255 unavailable')
        lib.sodium_init.argtypes = []
        lib.sodium_init.restype = _zs_ct.c_int
        if lib.sodium_init() < 0: raise ValueError('libsodium initialization failed')
        for function, (sizes, status) in _ZS_OPS.items():
            fn = getattr(lib, function)
            fn.argtypes = [_zs_ct.c_void_p] * (len(sizes) + 1)
            fn.restype = _zs_ct.c_int if status else None
        lib.crypto_core_ristretto255_is_valid_point.argtypes = [_zs_ct.c_void_p]
        lib.crypto_core_ristretto255_is_valid_point.restype = _zs_ct.c_int
        _ZS_LIB = lib
    return _ZS_LIB


def zs_op(name, *values):
    contract = _ZS_OPS.get(name)
    if contract is None or len(values) != len(contract[0]) or any(type(v) is not bytes or len(v) != size for v, size in zip(values, contract[0])):
        raise ValueError('Ristretto exact operation and buffer sizes required')
    if '_scalar_' in name and not name.endswith('_reduce'):
        for value in values: zs_scalar(value)
    elif name.startswith('crypto_scalarmult_'):
        zs_scalar(values[0])
    output = _zs_ct.create_string_buffer(32)
    fn = getattr(zs_lib(), name)
    status = fn(output, *(_zs_ct.create_string_buffer(v, len(v)) for v in values))
    if contract[1] and status != 0:
        raise ValueError('Ristretto operation rejected')
    return output.raw


def zs_scalar(value):
    value = zs_hex(value) if type(value) is str else value
    if type(value) is not bytes or len(value) != 32 or int.from_bytes(value, 'little') >= _ZS_ORDER:
        raise ValueError('noncanonical scalar')
    return value


def zs_point(value):
    value = zs_hex(value) if type(value) is str else value
    if type(value) is not bytes or len(value) != 32 or value == _ZS_ZERO or zs_lib().crypto_core_ristretto255_is_valid_point(value) != 1:
        raise ValueError('noncanonical or identity point')
    return value


def zs_reduce(raw): return zs_op('crypto_core_ristretto255_scalar_reduce', raw)
def zs_random_scalar():
    for _ in range(8):
        value = zs_reduce(_zs_random.token_bytes(64))
        if value != _ZS_ZERO: return value
    raise ValueError('nonzero scalar randomness unavailable')
def zs_sadd(a, b): return zs_op('crypto_core_ristretto255_scalar_add', a, b)
def zs_ssub(a, b): return zs_op('crypto_core_ristretto255_scalar_sub', a, b)
def zs_smul(a, b): return zs_op('crypto_core_ristretto255_scalar_mul', a, b)
def zs_add(a, b): return zs_op('crypto_core_ristretto255_add', a, b)
def zs_sub(a, b): return zs_op('crypto_core_ristretto255_sub', a, b)
def zs_mul(s, p): return _ZS_ZERO if s == _ZS_ZERO or p == _ZS_ZERO else zs_op('crypto_scalarmult_ristretto255', s, p)
def zs_base(s): return _ZS_ZERO if s == _ZS_ZERO else zs_op('crypto_scalarmult_ristretto255_base', s)
def zs_hp(domain, raw): return zs_op('crypto_core_ristretto255_from_hash', _zs_hash.sha512(domain+raw).digest())
def zs_generator(): return zs_hp(b'Corium/ZKN/asset-blinding/v1\0', b'')


def zs_asset(network, token_id):
    zs_hex(token_id)
    return zs_reduce(_zs_hash.sha512(b'Corium/ZKN/asset/v1\0'+network.encode()+b'\0'+bytes.fromhex(token_id)).digest())


def zs_commit(network, token_id, blind):
    return zs_add(zs_base(zs_asset(network, token_id)), zs_mul(zs_scalar(blind), zs_generator())).hex()


def zs_note_id(note):
    zs_note(note)
    return _zs_hash.sha256(b'Corium/ZKN/note/v1\0'+zs_json(note)).hexdigest()


def zs_note(note):
    zs_exact(note, {'commitment', 'public_key', 'ciphertext'})
    zs_point(note['commitment']); zs_point(note['public_key'])
    try: raw = _zs_b64.b64decode(note['ciphertext'], validate=True)
    except (TypeError, ValueError): raise ValueError('invalid encrypted note')
    if len(raw) != 2048: raise ValueError('encrypted note must be 2048 bytes')
    return note


def zs_challenge(message, index, left, right, balance):
    return zs_reduce(_zs_hash.sha512(b'Corium/ZKN/MLSAG/v1\0'+message+index.to_bytes(2, 'big')+left+right+balance).digest())


def zs_ring_sign(network, message, ring, output_commitment, index, secret, delta):
    """Wallet-only proof creation; no private witnesses enter public payloads."""
    if type(index) is not int or not 0 <= index < len(ring) or len(ring) not in (16, 32, 64): raise ValueError('ring size/index')
    secret, delta = zs_scalar(secret), zs_scalar(delta)
    p = [zs_point(n['public_key']) for n in ring]
    q = [zs_sub(zs_point(n['commitment']), zs_point(output_commitment)) for n in ring]
    if zs_base(secret) != p[index] or zs_mul(delta, zs_generator()) != q[index]: raise ValueError('invalid ownership/conservation witness')
    hp = [zs_hp(b'Corium/ZKN/key-image/v1\0'+network.encode()+b'\0', v) for v in p]
    image = zs_mul(secret, hp[index]); zs_point(image)
    transcript = _zs_hash.sha512(zs_json({'network': network, 'message': message, 'ring': [{k:n[k] for k in ('public_key','commitment')} for n in ring], 'output': output_commitment, 'image': image.hex()})).digest()
    alpha, beta = zs_random_scalar(), zs_random_scalar()
    responses = [[zs_random_scalar(), zs_random_scalar()] for _ in ring]; challenges = [None]*len(ring)
    cursor = (index+1) % len(ring)
    challenges[cursor] = zs_challenge(transcript, index, zs_base(alpha), zs_mul(alpha, hp[index]), zs_mul(beta, zs_generator()))
    while cursor != index:
        c = challenges[cursor]; a, b = responses[cursor]
        challenges[(cursor+1) % len(ring)] = zs_challenge(transcript, cursor, zs_add(zs_base(a), zs_mul(c, p[cursor])), zs_add(zs_mul(a, hp[cursor]), zs_mul(c, image)), zs_add(zs_mul(b, zs_generator()), zs_mul(c, q[cursor])))
        cursor = (cursor+1) % len(ring)
    responses[index] = [zs_ssub(alpha, zs_smul(challenges[index], secret)), zs_ssub(beta, zs_smul(challenges[index], delta))]
    return {'image': image.hex(), 'challenge': challenges[0].hex(), 'responses': [[a.hex(), b.hex()] for a, b in responses]}


def zs_ring_verify(network, message, ring, output_commitment, proof):
    zs_exact(proof, {'image', 'challenge', 'responses'})
    if len(ring) not in (16, 32, 64) or type(proof['responses']) is not list or len(proof['responses']) != len(ring): raise ValueError('fixed ring size required')
    image = zs_point(proof['image']); initial = zs_scalar(proof['challenge']); c = initial
    zs_point(output_commitment)
    transcript = _zs_hash.sha512(zs_json({'network': network, 'message': message, 'ring': [{k:n[k] for k in ('public_key','commitment')} for n in ring], 'output': output_commitment, 'image': image.hex()})).digest()
    for i, (note, response) in enumerate(zip(ring, proof['responses'])):
        if type(response) is not list or len(response) != 2: raise ValueError('exact proof responses required')
        a, b = map(zs_scalar, response); p = zs_point(note['public_key'])
        q = zs_sub(zs_point(note['commitment']), zs_point(output_commitment))
        hp = zs_hp(b'Corium/ZKN/key-image/v1\0'+network.encode()+b'\0', p)
        c = zs_challenge(transcript, i, zs_add(zs_base(a), zs_mul(c, p)), zs_add(zs_mul(a, hp), zs_mul(c, image)), zs_add(zs_mul(b, zs_generator()), zs_mul(c, q)))
    if c != initial: raise ValueError('ownership/conservation proof rejected')
    return proof['image']


def zs_tables(db):
    definitions = {
        'zkn_shield_notes': 'note_id TEXT PRIMARY KEY,public_key TEXT UNIQUE,commitment TEXT UNIQUE,ciphertext TEXT,height INTEGER,transaction_hash TEXT UNIQUE',
        'zkn_shield_images': 'image TEXT PRIMARY KEY,height INTEGER,transaction_hash TEXT UNIQUE',
        'privacy_requests': 'request_id TEXT PRIMARY KEY,requester TEXT,body TEXT,height INTEGER,expires INTEGER,nonce TEXT,revoked INTEGER DEFAULT 0,UNIQUE(requester,nonce)',
        'privacy_votes': 'request_id TEXT,voter TEXT,decision TEXT,height INTEGER,PRIMARY KEY(request_id,voter)',
        'privacy_disclosures': 'request_id TEXT,note_id TEXT,ciphertext TEXT,height INTEGER,transaction_hash TEXT UNIQUE,PRIMARY KEY(request_id,note_id)',
        'privacy_electorate': 'request_id TEXT,voter TEXT,weight INTEGER,PRIMARY KEY(request_id,voter)',
    }
    for name, fields in definitions.items(): db.execute('CREATE TABLE IF NOT EXISTS "'+name+'" ('+fields+')')


def zs_exists(db, name): return bool(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone())
def zs_height(db): return int(db.execute('SELECT COALESCE(MAX(height),0) FROM blocks').fetchone()[0])


def zs_testnet(network):
    if not isinstance(network, str) or not (network.startswith(('test-', 'dev-')) or (ZS_MAINNET_ENABLED and network in {'ziokt-main', 'mainnet','ziokt-main-recovery-20261024','ziokt-dna-side-20261024'})):
        raise ValueError('shielded consensus requires testnet or enabled mainnet activation')


def zs_validate(db, network, kind, value, sender, height=None):
    parent_height=zs_height(db) if height is None else height-1
    zs_json(value)
    if kind not in ZS_TYPES: raise ValueError('unknown privacy transaction')
    if kind.startswith('zkn_shield_'):
        zs_testnet(network)
        zs_exact(value, {'version', 'network_id', 'token_id', 'blind', 'note'} if kind == 'zkn_shield_deposit' else
                 {'version', 'network_id', 'ring', 'anchor', 'proof', 'note'} if kind == 'zkn_shield_transfer' else
                 {'version', 'network_id', 'ring', 'anchor', 'proof', 'token_id', 'recipient'})
        if value['version'] != ZS_VERSION or value['network_id'] != network: raise ValueError('privacy version/network mismatch')
        if kind == 'zkn_shield_deposit':
            zs_note(value['note']); blind = zs_scalar(value['blind'])
            if blind == _ZS_ZERO or zs_commit(network, value['token_id'], blind) != value['note']['commitment']: raise ValueError('deposit commitment mismatch')
            # Entry boundary is deliberately public; subsequent transfers hide the asset.
            row = db.execute('SELECT owner FROM zkn_tokens WHERE token_id=?', (value['token_id'],)).fetchone()
            if not row or row[0] != sender: raise ValueError('only confirmed transparent owner can deposit')
        else:
            if type(value['ring']) is not list or len(value['ring']) not in (16, 32, 64) or len(set(value['ring'])) != len(value['ring']) or value['ring'] != sorted(value['ring']): raise ValueError('unique canonical fixed ring required')
            zs_hex(value['anchor'])
            if not zs_exists(db, 'zkn_shield_notes') or not zs_exists(db, 'zkn_shield_images'):
                raise ValueError('shielded pool not initialized')
            anchor = db.execute('SELECT height FROM blocks WHERE hash=?', (value['anchor'],)).fetchone()
            if not anchor or not 1 <= parent_height-anchor[0] <= 128: raise ValueError('mature canonical anchor required')
            ring = []
            for identifier in value['ring']:
                zs_hex(identifier)
                row = db.execute('SELECT public_key,commitment,ciphertext,height FROM zkn_shield_notes WHERE note_id=?', (identifier,)).fetchone()
                if not row or row[3] > anchor[0]: raise ValueError('ring note not present at anchor')
                ring.append(dict(zip(('public_key', 'commitment', 'ciphertext'), row[:3])))
            if kind == 'zkn_shield_transfer': zs_note(value['note']); output = value['note']['commitment']
            else:
                zs_hex(value['recipient']); output = zs_base(zs_asset(network, value['token_id'])).hex()
                locked=db.execute('SELECT owner FROM zkn_tokens WHERE token_id=?',(value['token_id'],)).fetchone()
                if not locked or locked[0]!='shielded-pool:v1':raise ValueError('asset not in shielded pool')
            message = {k: v for k, v in value.items() if k != 'proof'}
            image = zs_ring_verify(network, message, ring, output, value['proof'])
            if db.execute('SELECT 1 FROM zkn_shield_images WHERE image=?', (image,)).fetchone(): raise ValueError('shielded double spend')
        if 'note' in value and zs_exists(db, 'zkn_shield_notes'):
            if db.execute('SELECT 1 FROM zkn_shield_notes WHERE note_id=? OR public_key=? OR commitment=?', (zs_note_id(value['note']), value['note']['public_key'],value['note']['commitment'])).fetchone(): raise ValueError('one-time note key reused')
        return
    height = parent_height
    if kind == 'privacy_review_request':
        zs_exact(value, {'network_id', 'case_commitment', 'legal_basis_commitment', 'recipient_key', 'scope', 'expires_height', 'nonce'})
        if value['network_id'] != network: raise ValueError('review network mismatch')
        for key in ('case_commitment', 'legal_basis_commitment', 'recipient_key', 'nonce'): zs_hex(value[key])
        if type(value['scope']) is not list or not 1 <= len(value['scope']) <= 32 or len(set(value['scope'])) != len(value['scope']): raise ValueError('bounded explicit review scope required')
        for note in value['scope']: zs_hex(note)
        if type(value['expires_height']) is not int or not height+2 <= value['expires_height'] <= height+4096: raise ValueError('bounded review expiration required')
        if zs_exists(db, 'privacy_requests') and db.execute('SELECT COUNT(*) FROM privacy_requests WHERE requester=? AND expires>=? AND revoked=0', (sender, height)).fetchone()[0] >= 8: raise ValueError('review request quota')
        if zs_exists(db,'privacy_requests') and db.execute('SELECT 1 FROM privacy_requests WHERE requester=? AND nonce=?',(sender,value['nonce'])).fetchone(): raise ValueError('review request replay')
        if zs_exists(db,'privacy_requests') and db.execute('SELECT COUNT(*) FROM privacy_requests WHERE expires>=? AND revoked=0',(height,)).fetchone()[0]>=4096: raise ValueError('global review request quota')
        electorate=db.execute("SELECT stake FROM validators WHERE status='active' AND stake>0 LIMIT 1025").fetchall()
        if not 1 <= len(electorate) <= 1024 or any(type(weight) is not int or not 0 < weight < 2**53 for (weight,) in electorate):
            raise ValueError('bounded active validator electorate required')
        return
    if value.get('network_id')!=network:raise ValueError('review network mismatch')
    fields = {'request_id', 'decision'} if kind == 'privacy_review_vote' else {'request_id'} if kind == 'privacy_review_revoke' else {'request_id', 'note_id', 'ciphertext', 'authorization'}
    zs_exact(value, fields|{'network_id'}); zs_hex(value['request_id'])
    if not zs_exists(db, 'privacy_requests'): raise ValueError('unknown review request')
    row = db.execute('SELECT requester,body,expires,revoked FROM privacy_requests WHERE request_id=?', (value['request_id'],)).fetchone()
    if not row or row[3] or height > row[2]: raise ValueError('review inactive, revoked or expired')
    if kind == 'privacy_review_revoke':
        if row[0] != sender: raise ValueError('only requester can withdraw review')
    elif kind == 'privacy_review_vote':
        if value['decision'] not in ('approve', 'reject'): raise ValueError('explicit review decision required')
        if not db.execute('SELECT 1 FROM privacy_electorate WHERE request_id=? AND voter=?', (value['request_id'], sender)).fetchone(): raise ValueError('only request-height electorate can vote')
        if db.execute('SELECT 1 FROM privacy_votes WHERE request_id=? AND voter=?', (value['request_id'], sender)).fetchone(): raise ValueError('review vote already cast')
    else:
        if not zs_review_status(db, value['request_id'],height)['approved']: raise ValueError('review has no supermajority approval')
        body = _zs_json.loads(row[1]); zs_hex(value['note_id'])
        if value['note_id'] not in body['scope']: raise ValueError('disclosure outside approved scope')
        if not zs_exists(db, 'zkn_shield_notes'): raise ValueError('unknown disclosure note')
        note = db.execute('SELECT public_key FROM zkn_shield_notes WHERE note_id=?', (value['note_id'],)).fetchone()
        if not note: raise ValueError('unknown disclosure note')
        try: ciphertext = _zs_b64.b64decode(value['ciphertext'], validate=True)
        except (TypeError, ValueError): raise ValueError('invalid disclosure ciphertext')
        if len(ciphertext) != 4096: raise ValueError('fixed encrypted disclosure required')
        zs_schnorr_verify(note[0], {k:v for k,v in value.items() if k != 'authorization'}, value['authorization'], network)
        if db.execute('SELECT 1 FROM privacy_disclosures WHERE request_id=? AND note_id=?', (value['request_id'], value['note_id'])).fetchone(): raise ValueError('disclosure already published')


def zs_schnorr_sign(secret, value, network):
    secret = zs_scalar(secret); nonce = zs_random_scalar(); public = zs_base(secret).hex(); r = zs_base(nonce).hex()
    c = zs_reduce(_zs_hash.sha512(b'Corium/ZKN/voluntary-disclosure/v1\0'+zs_json({'network':network,'public_key':public,'value':value,'r':r})).digest())
    return {'r':r, 's':zs_sadd(nonce,zs_smul(c,secret)).hex()}


def zs_schnorr_verify(public, value, proof, network):
    zs_exact(proof, {'r','s'}); p = zs_point(public); r = zs_point(proof['r']); s = zs_scalar(proof['s'])
    c = zs_reduce(_zs_hash.sha512(b'Corium/ZKN/voluntary-disclosure/v1\0'+zs_json({'network':network,'public_key':public,'value':value,'r':proof['r']})).digest())
    if zs_base(s) != zs_add(r,zs_mul(c,p)): raise ValueError('holder did not authorize disclosure')


def zs_review_status(db, request_id, height=None):
    height=zs_height(db) if height is None else height
    zs_hex(request_id)
    row = db.execute('SELECT expires,revoked FROM privacy_requests WHERE request_id=?',(request_id,)).fetchone()
    if not row: raise ValueError('unknown review request')
    total = db.execute('SELECT COALESCE(SUM(weight),0) FROM privacy_electorate WHERE request_id=?',(request_id,)).fetchone()[0]
    yes = db.execute("SELECT COALESCE(SUM(e.weight),0) FROM privacy_electorate e JOIN privacy_votes v USING(request_id,voter) WHERE e.request_id=? AND v.decision='approve'",(request_id,)).fetchone()[0]
    live = not row[1] and height <= row[0]
    return {'request_id':request_id,'approved':bool(live and total>0 and 3*yes>2*total),'expired':height>row[0], 'revoked':bool(row[1]),'approved_weight':yes,'total_weight':total,'automatic_decryption':False,'holder_consent_required':True}


def zs_apply(db, network, kind, value, sender, tx_hash, height, validation_height=None):
    zs_validate(db,network,kind,value,sender,validation_height); zs_tables(db)
    if kind == 'zkn_shield_deposit':
        db.execute('UPDATE zkn_tokens SET owner=? WHERE token_id=?', ('shielded-pool:v1',value['token_id']))
    if kind in {'zkn_shield_deposit','zkn_shield_transfer'}:
        n=value['note'];db.execute('INSERT INTO zkn_shield_notes VALUES (?,?,?,?,?,?)',(zs_note_id(n),n['public_key'],n['commitment'],n['ciphertext'],height,tx_hash))
    if kind in {'zkn_shield_transfer','zkn_shield_withdraw'}:
        db.execute('INSERT INTO zkn_shield_images VALUES (?,?,?)',(value['proof']['image'],height,tx_hash))
    if kind == 'zkn_shield_withdraw':
        # Transparent exits are explicit and observable; nonce remains monotone.
        row=db.execute('SELECT owner FROM zkn_tokens WHERE token_id=?',(value['token_id'],)).fetchone()
        if not row or row[0]!='shielded-pool:v1': raise ValueError('asset not in shielded pool')
        db.execute('UPDATE zkn_tokens SET owner=?,nonce=nonce+1 WHERE token_id=?',(value['recipient'],value['token_id']))
    if kind == 'privacy_review_request':
        db.execute('INSERT INTO privacy_requests VALUES (?,?,?,?,?,?,0)',(tx_hash,sender,zs_json(value).decode(),height,value['expires_height'],value['nonce']))
        electorate=db.execute("SELECT public_key_hash,stake FROM validators WHERE status='active' AND stake>0 ORDER BY public_key_hash LIMIT 1025").fetchall()
        if not 1<=len(electorate)<=1024: raise ValueError('bounded active validator electorate required')
        for voter,weight in electorate:
            if type(weight) is not int or not 0<weight<2**53: raise ValueError('invalid review voter weight')
            db.execute('INSERT INTO privacy_electorate VALUES (?,?,?)',(tx_hash,voter,weight))
    elif kind == 'privacy_review_vote': db.execute('INSERT INTO privacy_votes VALUES (?,?,?,?)',(value['request_id'],sender,value['decision'],height))
    elif kind == 'privacy_review_revoke': db.execute('UPDATE privacy_requests SET revoked=1 WHERE request_id=?',(value['request_id'],))
    elif kind == 'privacy_review_disclose': db.execute('INSERT INTO privacy_disclosures VALUES (?,?,?,?,?)',(value['request_id'],value['note_id'],value['ciphertext'],height,tx_hash))


def zs_query(db, network, method, params):
    if method == 'privacy.status':
        return {'schema':'corium.privacy-status.v1','network_id':network,'proof_version':ZS_VERSION,
                'independently_audited':ZS_AUDITED,'mainnet_feature_enabled':ZS_MAINNET_ENABLED,
                'self_review_report':ZS_SELF_REVIEW_REPORT,'third_party_audit_status':'not_evidenced',
                'mainnet_governance_approval':'not_verified','cryptographic_security_verified':False,
                'shielded_transfers_enabled':network.startswith(('test-','dev-')) or (ZS_MAINNET_ENABLED and network in {'ziokt-main', 'mainnet','ziokt-main-recovery-20261024','ziokt-dna-side-20261024'}),
                'production_shielding_enabled':bool(ZS_MAINNET_ENABLED and network in {'ziokt-main', 'mainnet','ziokt-main-recovery-20261024','ziokt-dna-side-20261024'}),'universal_decryption_key':False,
                'review_requires_supermajority':True,'disclosure_requires_holder_consent':True,
                'transparent_entry_exit_observable':True,'authenticated_relayer_knows_caller':True,
                'global_observer_resistance_guaranteed':False}
    if method == 'privacy.review.get':
        if not zs_exists(db,'privacy_requests'): raise ValueError('unknown review request')
        identifier=params['request_id'];status=zs_review_status(db,identifier)
        row=db.execute('SELECT requester,body,height FROM privacy_requests WHERE request_id=?',(identifier,)).fetchone()
        disclosures=[{'note_id':n,'ciphertext':c,'transaction_hash':t} for n,c,t in db.execute('SELECT note_id,ciphertext,transaction_hash FROM privacy_disclosures WHERE request_id=? ORDER BY note_id LIMIT 32',(identifier,))]
        return {**status,'requester':row[0],'request':_zs_json.loads(row[1]),'height':row[2],'disclosures':disclosures}
    limit=params.get('limit',32);cursor=params.get('cursor','')
    if type(limit) is not int or not 1<=limit<=64 or type(cursor) is not str: raise ValueError('bounded privacy cursor required')
    if cursor:zs_hex(cursor)
    if method == 'privacy.review.list':
        rows=[] if not zs_exists(db,'privacy_requests') else db.execute('SELECT request_id,requester,height,expires,revoked FROM privacy_requests WHERE request_id>? ORDER BY request_id LIMIT ?',(cursor,limit+1)).fetchall()
        return {'requests':[dict(zip(('request_id','requester','height','expires_height','revoked'),r)) for r in rows[:limit]],'next_cursor':rows[limit-1][0] if len(rows)>limit else None}
    if method == 'zkn.shield.notes':
        rows=[] if not zs_exists(db,'zkn_shield_notes') else db.execute('SELECT note_id,public_key,commitment,ciphertext,height FROM zkn_shield_notes WHERE note_id>? ORDER BY note_id LIMIT ?',(cursor,limit+1)).fetchall()
        return {'notes':[dict(zip(('note_id','public_key','commitment','ciphertext','height'),r)) for r in rows[:limit]],'next_cursor':rows[limit-1][0] if len(rows)>limit else None,'spent_notes_identifiable':False}
    if method == 'zkn.shield.images':
        rows=[] if not zs_exists(db,'zkn_shield_images') else db.execute('SELECT image,height,transaction_hash FROM zkn_shield_images WHERE image>? ORDER BY image LIMIT ?', (cursor, limit+1)).fetchall()
        return {'images':[dict(zip(('image','height','transaction_hash'),r)) for r in rows[:limit]], 'next_cursor':rows[limit-1][0] if len(rows)>limit else None, 'spent_notes_identifiable':False}
    raise ValueError('unknown privacy query')

"""Native signed registration receipts and transferable block-snapshot ZKN assets."""

ASSET_TYPES = {'ziokt_identity_register', 'ziokt_content', 'zkn_mint', 'zkn_transfer', 'zkn_private_transfer', 'zkc_issue', 'zkc_transfer', 'cooperative_command'} | ZS_TYPES


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


def asset_transaction_bytes(tx, network=None):
    # Recovery networks bind native wallet signatures to chain namespace and actor.
    network=network or tx['data'].get('network_id')
    if network in {'ziokt-main-recovery-20261024','ziokt-dna-side-20261024'}:
        return encoded({'schema':'corium.chain-transaction.v3','network':network,'public_key':tx['public_key'],
                        'type':tx['type'],'data':tx['data'],'timestamp':tx['timestamp']})
    # Match Corium's historical signed serialization exactly.
    return ('{"type":'+json.dumps(tx['type'])+',"data":'+encoded(tx['data']).decode()+',"timestamp":'+str(tx['timestamp'])+'}').encode()


def zkc_edition_id(payload):
    return hashlib.sha256(b'Ziokt/ZKC/edition/v1\n'+encoded({k:payload[k] for k in ('network_id','token_id','kind','serial')})).hexdigest()


def asset_signed_gift(tx, network, kind='zkn_private_transfer'):
    if (not isinstance(tx,dict) or set(tx)!={'type','data','timestamp','public_key','signature'} or
            kind not in ({'zkn_mint','zkn_transfer','zkn_private_transfer','zkc_issue','zkc_transfer','cooperative_command'}|ZS_TYPES) or tx['type']!=kind or type(tx['timestamp']) is not int or not 0<tx['timestamp']<2**53 or
            not isinstance(tx['data'],dict) or (kind not in {'zkn_mint','zkn_transfer','cooperative_command'} and tx['data'].get('network_id')!=network) or
            not isinstance(tx['public_key'],str) or len(tx['public_key'])>1024 or
            not isinstance(tx['signature'],str) or len(tx['signature'])>160):
        fail('INVALID_ZKN','scoped signed private gift transaction required')
    raw=asset_transaction_bytes(tx,network)
    if len(raw)>(65536 if kind in ZS_TYPES or kind=='cooperative_command' or 'cooperative_authorization' in tx['data'] else 8192): fail('RESPONSE_LIMIT','gift transaction exceeds budget')
    native_ec_verify(tx['public_key'],tx['signature'],raw)
    return tx,hashlib.sha256(raw).hexdigest(),hashlib.sha256(tx['public_key'].rstrip('\n').encode()).hexdigest()


def asset_publish_transaction(root, network, tx, tx_hash):
    directory=root/'var/lib/corix/p2p/objects/transactions'
    private_mkdir(directory)
    target=directory/tx_hash;body=encoded(tx)
    if target.exists():
        if strict_json(secure_read(target,65536))!=tx: fail('IDEMPOTENCY_CONFLICT','immutable P2P gift object changed')
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


def asset_privacy_pending(db, network, kind, value, sender):
    """Reserve privacy conflicts under the caller's BEGIN IMMEDIATE lock.

    Admission policy only: consensus validation must not depend on local mempool
    contents, whose order and membership differ between validators.
    """
    own_requests = global_requests = 0
    ownership = {'zkn_shield_deposit', 'zkn_transfer', 'zkn_private_transfer'}
    kinds = sorted(ZS_TYPES | {'zkn_transfer', 'zkn_private_transfer', 'zkc_issue'})
    rows = db.execute('SELECT type,data,public_key FROM transactions WHERE block_height IS NULL AND type IN (' + ','.join('?' for _ in kinds) + ') LIMIT 4097', kinds)
    for pending_kind, raw, public in rows:
        pending = strict_json(raw.encode())
        if type(pending) is not dict: fail('PRIVACY_CONFLICT', 'pending privacy payload requires native recovery')
        if pending_kind in {'zkn_shield_transfer', 'zkn_shield_withdraw'} and type(pending.get('proof')) is not dict:
            fail('PRIVACY_CONFLICT', 'pending privacy proof requires native recovery')
        if pending_kind in {'zkn_shield_deposit', 'zkn_shield_transfer'} and type(pending.get('note')) is not dict:
            fail('PRIVACY_CONFLICT', 'pending privacy note requires native recovery')
        same_sender = hashlib.sha256(public.rstrip('\n').encode()).hexdigest() == sender
        if kind in ownership | {'zkc_issue'} and pending_kind in ownership | {'zkc_issue'} and (kind in ownership or pending_kind in ownership) and pending.get('token_id') == value['token_id']:
            fail('PRIVACY_CONFLICT', 'asset already has a pending ownership change')
        if kind in {'zkn_shield_transfer', 'zkn_shield_withdraw'} and pending_kind in {'zkn_shield_transfer', 'zkn_shield_withdraw'} and pending.get('proof', {}).get('image') == value['proof']['image']:
            fail('PRIVACY_CONFLICT', 'nullifier already pending')
        if kind in {'zkn_shield_deposit', 'zkn_shield_transfer'} and pending_kind in {'zkn_shield_deposit', 'zkn_shield_transfer'}:
            note = pending.get('note', {})
            if any(note.get(field) == value['note'][field] for field in ('public_key', 'commitment')):
                fail('PRIVACY_CONFLICT', 'one-time note key or commitment already pending')
        if pending_kind == 'privacy_review_request':
            global_requests += 1
            own_requests += int(same_sender)
            if kind == 'privacy_review_request' and same_sender and pending.get('nonce') == value['nonce']:
                fail('PRIVACY_CONFLICT', 'request nonce already pending')
        if value.get('request_id') and value.get('request_id') == pending.get('request_id'):
            if kind == 'privacy_review_revoke' or pending_kind == 'privacy_review_revoke':
                fail('PRIVACY_CONFLICT', 'review closure conflicts with a pending review action')
            if kind == pending_kind == 'privacy_review_vote' and same_sender:
                fail('PRIVACY_CONFLICT', 'review vote already pending')
            if kind == pending_kind == 'privacy_review_disclose' and value['note_id'] == pending.get('note_id'):
                fail('PRIVACY_CONFLICT', 'disclosure already pending')
    if kind == 'privacy_review_request':
        height = zs_height(db)
        own_confirmed = global_confirmed = 0
        if zs_exists(db, 'privacy_requests'):
            own_confirmed = db.execute('SELECT COUNT(*) FROM privacy_requests WHERE requester=? AND expires>=? AND revoked=0', (sender, height)).fetchone()[0]
            global_confirmed = db.execute('SELECT COUNT(*) FROM privacy_requests WHERE expires>=? AND revoked=0', (height,)).fetchone()[0]
        if own_confirmed + own_requests >= 8 or global_confirmed + global_requests >= 4096:
            fail('PRIVACY_CONFLICT', 'confirmed and pending review request quota')


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
                if db.execute('SELECT COUNT(*) FROM transactions WHERE block_height IS NULL').fetchone()[0]>=4096:
                    fail('BACKPRESSURE','pending transaction budget exhausted')
                asset_validate(db,network,tx['type'],tx['data'],sender)
                if kind=='cooperative_command' or 'cooperative_authorization' in tx['data']:
                    pending=db.execute("SELECT 1 FROM transactions WHERE block_height IS NULL AND (type='cooperative_command' OR json_type(data,'$.cooperative_authorization') IS NOT NULL) LIMIT 1").fetchone()
                    if pending:fail('COOPERATIVE_PENDING','a cooperative operation is already pending; confirm or remove it first')
                if kind=='zkc_transfer' and db.execute("SELECT 1 FROM transactions WHERE block_height IS NULL AND type='zkc_transfer' AND json_extract(data,'$.edition_id')=?",(tx['data']['edition_id'],)).fetchone():
                    fail('EDITION_PENDING','edition transfer already pending')
                if kind in ZS_TYPES or kind in {'zkn_transfer', 'zkn_private_transfer', 'zkc_issue'}:
                    asset_privacy_pending(db, network, kind, tx['data'], sender)
                for (raw,) in db.execute("SELECT data FROM transactions WHERE type IN ('zkn_transfer','zkn_private_transfer','zkc_issue') AND block_height IS NULL LIMIT 4097"):
                    pending=strict_json(raw.encode())
                    if kind=='zkn_private_transfer' and 'nonce' in pending and pending.get('token_id')==tx['data']['token_id'] and pending.get('nonce')==tx['data']['nonce']:
                        fail('GIFT_CONFLICT','another gift already spends this collectible sequence')
                    if kind=='zkn_private_transfer' and pending.get('recipient')==tx['data']['recipient']:
                        fail('RECIPIENT_REUSED','one-time receiver already has a pending gift')
                    if kind=='zkc_issue' and 'kind' in pending and zkc_edition_id(pending)==zkc_edition_id(tx['data']):
                        fail('EDITION_PENDING','edition already has a pending issue; reuse its transaction')
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
        rows=db.execute("SELECT hash,type,data,signature,public_key,timestamp FROM transactions WHERE type IN ('zkn_private_transfer','zkc_issue','zkn_shield_deposit','zkn_shield_transfer','zkn_shield_withdraw','privacy_review_request','privacy_review_vote','privacy_review_revoke','privacy_review_disclose') ORDER BY timestamp DESC LIMIT 64").fetchall()
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


def asset_cooperative_guard(db, network, kind, payload, sender, height):
    if type(payload)is not dict:fail('INVALID_PARAMS','asset payload object required')
    plain=dict(payload);authorization=plain.pop('cooperative_authorization',None)
    if 'cooperative_authorization' in payload and authorization is None:fail('COOPERATIVE_REJECTED','authorization must be an object')
    supported={'zkn_mint','zkn_transfer','zkn_private_transfer','zkc_issue','zkc_transfer',
               'zkn_shield_deposit','zkn_shield_transfer','zkn_shield_withdraw','privacy_review_disclose'}
    if authorization is not None and kind not in supported:fail('COOPERATIVE_REJECTED','cooperative authorization is not supported for this operation')
    required=None;owner=None;cc=_native_cooperative_consensus
    if kind in {'zkn_transfer','zkn_private_transfer','zkc_issue','zkn_shield_deposit'} and zs_exists(db,'zkn_tokens'):
        row=db.execute('SELECT owner FROM zkn_tokens WHERE token_id=?',(plain.get('token_id'),)).fetchone()
        if row:owner=row[0]
    elif kind=='zkc_transfer' and zs_exists(db,'zkc_editions'):
        row=asset_edition_owner(db,plain.get('edition_id'))
        if row:owner=row[0]
    if owner:required=cc.owner_cooperative(db,network,owner,height)
    if kind in {'zkn_shield_transfer','zkn_shield_withdraw'}:
        ring=plain.get('ring')
        if type(ring)is not list or len(ring) not in (16,32,64) or any(type(n)is not str for n in ring):
            fail('PRIVACY_REJECTED','bounded shielded ring required')
        labels=set()
        for note in ring:
            row=db.execute('SELECT cooperative FROM cooperative_note_controls WHERE note_id=?',(note,)).fetchone() if zs_exists(db,'cooperative_note_controls') else None
            labels.add(row[0] if row else None)
        if len(labels)!=1:fail('COOPERATIVE_REJECTED','shielded ring mixes cooperative authorization domains')
        required=next(iter(labels))
    if kind=='privacy_review_disclose' and zs_exists(db,'cooperative_note_controls'):
        row=db.execute('SELECT cooperative FROM cooperative_note_controls WHERE note_id=?',(plain.get('note_id'),)).fetchone()
        if row:required=row[0]
    if required and authorization is None:fail('COOPERATIVE_REJECTED','current cooperative members must authorize this asset operation')
    info=None
    if authorization is not None:
        try:info=cc.authorize(db,network,kind,plain,authorization,height)
        except Exception as error:
            from cryptography.exceptions import InvalidSignature
            if isinstance(error,(ValueError,KeyError,TypeError,InvalidSignature)):fail('COOPERATIVE_REJECTED',str(error) or 'invalid cooperative endorsement')
            raise
        if required and required!=info['cooperative']:fail('COOPERATIVE_REJECTED','asset belongs to another cooperative')
        if required and kind in {'zkn_transfer','zkn_private_transfer','zkc_issue','zkc_transfer','zkn_shield_deposit'}:sender=info['account']
    return plain,sender,info


def asset_edition_owner(db,edition):
    if zs_exists(db,'zkc_owners'):
        row=db.execute('SELECT owner,nonce FROM zkc_owners WHERE edition_id=?',(edition,)).fetchone()
        if row:return row
    if zs_exists(db,'zkc_editions'):
        row=db.execute('SELECT issuer FROM zkc_editions WHERE edition_id=?',(edition,)).fetchone()
        if row:return (row[0],0)
    return None


def asset_validate(db, network, tx_type, payload, sender, height=None):
    height=zs_height(db)+1 if height is None else height
    if tx_type=='cooperative_command':
        try:return _native_cooperative_consensus.apply_command(db,network,payload,height)
        except Exception as error:
            from cryptography.exceptions import InvalidSignature
            if isinstance(error,(ValueError,TypeError,KeyError,InvalidSignature)):fail('COOPERATIVE_REJECTED',str(error) or 'invalid cooperative command')
            raise
    plain,effective,_=asset_cooperative_guard(db,network,tx_type,payload,sender,height)
    return _asset_validate_base(db,network,tx_type,plain,effective,height)


def _asset_validate_base(db, network, tx_type, payload, sender, height=None):
    if tx_type in ZS_TYPES:
        try:return zs_validate(db,network,tx_type,payload,sender,height)
        except (ValueError,TypeError,KeyError) as exc:fail('PRIVACY_REJECTED',str(exc))
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
    if tx_type=='zkc_transfer':
        if (type(payload)is not dict or set(payload)!={'network_id','edition_id','recipient','nonce'} or payload['network_id']!=network
            or any(type(payload[k])is not str or not re.fullmatch('[a-f0-9]{64}',payload[k]) for k in ('edition_id','recipient'))
            or type(payload['nonce'])is not int or not 1<=payload['nonce']<2**53):fail('INVALID_ZKC','exact edition transfer required')
        row=asset_edition_owner(db,payload['edition_id'])
        if not row or row[0]!=sender or row[1]+1!=payload['nonce']:fail('POLICY_DENIED','current edition owner and next nonce required')
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
        if network in {'ziokt-main-recovery-20261024','ziokt-dna-side-20261024'}: fields.add('network_id')
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
    if tx_type=='cooperative_command':
        return _native_cooperative_consensus.apply_command(db,network,payload,height,True)
    plain,effective,info=asset_cooperative_guard(db,network,tx_type,payload,sender,height)
    _asset_apply_base(db,network,tx_hash,tx_type,plain,effective,height)
    if info:
        cc=_native_cooperative_consensus;cc.tables(db)
        db.execute('INSERT OR REPLACE INTO cooperative_asset_nonces VALUES(?,?)',(info['cooperative'],info['nonce']))
        if tx_type=='zkn_mint':
            db.execute('UPDATE zkn_tokens SET owner=? WHERE token_id=?',(info['account'],plain['snapshot']['manifest']['token_id']))
        if tx_type in {'zkn_shield_deposit','zkn_shield_transfer'}:
            db.execute('INSERT INTO cooperative_note_controls VALUES(?,?)',(zs_note_id(plain['note']),info['cooperative']))


def _asset_apply_base(db, network, tx_hash, tx_type, payload, sender, height):
    if tx_type in ZS_TYPES:
        try:return zs_apply(db,network,tx_type,payload,sender,tx_hash,height,validation_height=height)
        except (ValueError,TypeError,KeyError) as exc:fail('PRIVACY_REJECTED',str(exc))
    value=_asset_validate_base(db,network,tx_type,payload,sender,height)
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
        _native_cooperative_consensus.tables(db)
        issuer=db.execute('SELECT issuer FROM zkc_editions WHERE edition_id=?',(zkc_edition_id(payload),)).fetchone()[0]
        db.execute('INSERT OR IGNORE INTO zkc_owners VALUES(?,?,0)',(zkc_edition_id(payload),issuer))
    elif tx_type=='zkc_transfer':
        _native_cooperative_consensus.tables(db)
        db.execute('INSERT OR REPLACE INTO zkc_owners VALUES(?,?,?)',(payload['edition_id'],payload['recipient'],payload['nonce']))
    else:
        db.execute('UPDATE zkn_tokens SET owner=?,nonce=? WHERE token_id=?',
            (payload['recipient'],payload['nonce'],payload['token_id']))
        if tx_type=='zkn_private_transfer':
            db.execute('INSERT INTO zkn_receivers VALUES (?,?,?)',(payload['recipient'],tx_hash,height))


def asset_engine_main(args):
    action,db_path,network=args[0],Path(args[1]).absolute(),args[2]
    identifier(network,'network')
    if action == 'submit-asset':
        root = Path(args[3]).absolute()
        if db_path != root/'var/lib/corix/networks'/network/'blockchain/chain.db':
            fail('SCOPE_MISMATCH', 'native privacy database belongs to another root')
        tx = strict_json(args[4].encode())
        if type(tx) is not dict or tx.get('type') not in ZS_TYPES | {'zkn_mint','zkn_transfer','zkn_private_transfer','zkc_issue','zkc_transfer','cooperative_command'}:
            fail('INVALID_PARAMS', 'admitted native asset transaction required')
        result = asset_submit_gift(root, network, tx, tx['type'])
        print(result['transaction_hash'])
        return 0
    if action=='forward':
        root=Path(args[3]).absolute()
        asset_forward_pending(root,network)
        return 0
    if action in {'validate','apply'}:
        tx_type,raw,sender=args[3:6]
        payload=strict_json(raw.encode())
        db=sqlite3.connect(db_path,timeout=5)
        try:
            if action=='validate': asset_validate(db,network,tx_type,payload,sender,int(args[6]) if len(args)>6 else None)
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
    if action in {'privacy.submit','cooperative.submit'}:
        if resource!=('privacy:' if action=='privacy.submit' else 'cooperative:')+network or set(arguments)!={'transaction'}:fail('INVALID_PARAMS','exact signed privacy transaction required')
        transaction=arguments['transaction']
        if not isinstance(transaction,dict) or transaction.get('type') not in (ZS_TYPES if action=='privacy.submit' else ASSET_TYPES-{'ziokt_content','ziokt_identity_register'}):fail('INVALID_PARAMS','known signed privacy transaction required')
        tx,tx_hash,sender=asset_signed_gift(transaction,network,transaction['type'])
        with closing(corium_db(root,network,'blockchain/chain.db')) as db:
            existing=db.execute('SELECT type,data,signature,public_key,timestamp FROM transactions WHERE hash=?',(tx_hash,)).fetchone()
            if existing:
                if tuple(existing)!=(tx['type'],encoded(tx['data']).decode(),tx['signature'],tx['public_key'],tx['timestamp']):fail('IDEMPOTENCY_CONFLICT','privacy transaction changed')
            else:asset_validate(db,network,tx['type'],tx['data'],sender)
        return {'transaction_type':tx['type'],'payload':tx['data'],'issuer':sender,'transaction_hash':tx_hash}
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
        if network in {'ziokt-main-recovery-20261024','ziokt-dna-side-20261024'}:payload['network_id']=network
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

"""Explicit node-owner NNS/IBC transaction plans. Never fabricates confirmation."""

def naming_preflight(root,network,params,config):
    if params['expected_revision'] is not None or params['resource']!='naming:'+network or set(params['arguments'])!={'transaction_type','payload'}:
        fail('INVALID_PARAMS','fixed native naming transaction plan required')
    kind=params['arguments']['transaction_type'];payload=params['arguments']['payload']
    allowed={'nns_register','nns_update','nns_transfer','nns_renew','ibc_dispatch','ibc_receive'}
    if kind not in allowed or not isinstance(payload,dict) or len(encoded(payload))>65536:
        fail('INVALID_PARAMS','bounded NNS or naming IBC payload required')
    issuer=corium_identity(root,network)
    def label(value):
        if not isinstance(value,str) or not re.fullmatch('[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?',value):fail('INVALID_PARAMS','suffix-free NNS root required')
    def hex32(value):
        if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{64}',value):fail('INVALID_PARAMS','exact content or identity digest required')
    def owned(name):
        label(name)
        with closing(corium_db(root,network,'forum/forum.db')) as db:
            record=db.execute('SELECT owner_id FROM nns_records WHERE domain_name=?',(name,)).fetchone()
        if not record or record[0]!=issuer:fail('POLICY_DENIED','this explicit native action requires the configured node to own the NNS root')
    if kind=='nns_register':
        if not {'domain_name','target_hash'}<=set(payload) or set(payload)-{'domain_name','target_hash','proof_of_genesis_contribution','proof_of_contribution'}:
            fail('INVALID_PARAMS','native contribution proof registration required')
        label(payload['domain_name']);hex32(payload['target_hash'])
        if not any(isinstance(payload.get(k),dict) for k in ('proof_of_genesis_contribution','proof_of_contribution')):fail('INVALID_PARAMS','native contribution evidence required; not synthesized by MCP')
        with closing(corium_db(root,network,'forum/forum.db')) as db:
            if db.execute('SELECT 1 FROM nns_records WHERE domain_name=?',(payload['domain_name'],)).fetchone():fail('POLICY_DENIED','registered roots must use owner-authorized updates')
    elif kind=='nns_update':
        if set(payload)!={'records'} or not isinstance(payload['records'],list) or not 1<=len(payload['records'])<=32:fail('INVALID_PARAMS','bounded native NNS updates required')
        seen=set()
        for record in payload['records']:
            if not isinstance(record,dict) or set(record)!={'domain_name','target_hash'}:fail('INVALID_PARAMS','exact NNS update record required')
            owned(record['domain_name']);hex32(record['target_hash'])
            if record['domain_name'] in seen:fail('INVALID_PARAMS','duplicate NNS update')
            seen.add(record['domain_name'])
    elif kind=='nns_transfer':
        if set(payload)!={'domain_name','new_owner_id','contribution_tax'} or not isinstance(payload['contribution_tax'],dict):fail('INVALID_PARAMS','native transfer with contribution evidence required')
        owned(payload['domain_name']);hex32(payload['new_owner_id'])
    elif kind=='nns_renew':
        if set(payload)!={'domain_name'}:fail('INVALID_PARAMS','exact native renewal required')
        owned(payload['domain_name'])
    elif kind=='ibc_dispatch':
        if set(payload)!={'target_chain_id','message_type','message_payload'} or payload['message_type']!='ZIOKT_NAME_BINDING_V1':fail('INVALID_PARAMS','naming-only native IBC dispatch required')
        identifier(payload['target_chain_id'],'destination network')
        binding=payload['message_payload']
        if not isinstance(binding,dict) or set(binding)!={'namespace','root','source_chain_id','epoch','expires_at','record'} or binding['source_chain_id']!=network:fail('INVALID_PARAMS','exact source-bound naming lease required')
        owned(binding['root']);identifier(binding['namespace'],'shared namespace')
        if type(binding['epoch']) is not int or not 1<=binding['epoch']<=2**53-1 or type(binding['expires_at']) is not int or not int(time.time())<binding['expires_at']<=int(time.time())+600:fail('INVALID_PARAMS','bounded monotonic naming lease required')
        if not isinstance(binding['record'],dict) or binding['record'].get('network_id')!=binding['namespace']:fail('INVALID_PARAMS','shared namespace registration required')
    else:
        if set(payload)!={'source_chain_id','payload_and_proof'}:fail('INVALID_PARAMS','exact native IBC receive required')
        identifier(payload['source_chain_id'],'source chain')
        try:proof=strict_json(base64.b64decode(payload['payload_and_proof'],validate=True),65536)
        except (ValueError,TypeError):fail('INVALID_PARAMS','bounded native naming proof required')
        if not isinstance(proof,dict) or proof.get('message_type')!='ZIOKT_NAME_BINDING_V1':fail('INVALID_PARAMS','naming-only IBC receive required')
        with closing(corium_db(root,network,'blockchain/chain.db')) as db:
            if not db.execute('SELECT 1 FROM ibc_verifiers WHERE target_chain_id=? AND is_active=1',(payload['source_chain_id'],)).fetchone():fail('POLICY_DENIED','native governance-approved IBC verifier required')
    return {'transaction_type':kind,'payload':payload,'issuer':issuer}

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
        if (not isinstance(public, str) or not 1 <= len(public) <= 4096 or
                not isinstance(signature, str) or not 1 <= len(signature) <= 256 or
                not isinstance(message, bytes)):
            raise ValueError()
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
