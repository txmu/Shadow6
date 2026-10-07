"""Bounded private state used by the local service manager."""
import json
import math
import os
import stat
import tempfile
import unicodedata
from pathlib import Path

LIMIT = 1048576


def private_read(path, limit=LIMIT):
    path = Path(path)
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if (not stat.S_ISREG(opened.st_mode) or identity(before) != identity(opened)
                or identity(path.lstat()) != identity(opened)
                or opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_nlink != 1 or opened.st_size > limit):
            raise ValueError('private file requires stable owner-controlled regular file, mode 0600 and bounded size')
        data = bytearray()
        while len(data) <= limit:
            part = os.read(fd, min(65536, limit + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        if (len(data) > limit or len(data)!=opened.st_size or identity(opened) != identity(os.fstat(fd)) or
                identity(opened)!=identity(path.lstat())):
            raise ValueError('private file changed or exceeded limit')
        return bytes(data)
    finally:
        os.close(fd)


def strict_json(data, *, limit=LIMIT, string_limit=65536, allow_measurement_floats=False, uint64_measurements_as_strings=False):
    if not isinstance(data, (str, bytes, bytearray)):
        raise ValueError('JSON input must be text or bytes')
    if type(limit) is not int or limit < 1:
        raise ValueError('invalid JSON input limit')
    if type(string_limit) is not int or not 1<=string_limit<=16*1024*1024:
        raise ValueError('invalid JSON string limit')
    if type(allow_measurement_floats) is not bool:
        raise ValueError('invalid JSON numeric policy')
    if type(uint64_measurements_as_strings) is not bool or (uint64_measurements_as_strings and not allow_measurement_floats):
        raise ValueError('uint64 string conversion requires explicit measurement policy')
    try:
        size = len(data.encode('utf-8')) if isinstance(data, str) else len(data)
    except UnicodeError as exc:
        raise ValueError('invalid bounded JSON') from exc
    if size > limit:
        raise ValueError('JSON input size limit')
    try:
        text = data if isinstance(data, str) else bytes(data).decode('utf-8', 'strict')
    except UnicodeError as exc:
        raise ValueError('JSON must be UTF-8') from exc
    # Bound container depth before json.loads allocates nested containers.
    depth, quoted, escaped = 0, False, False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == '\\':
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in '[{':
            depth += 1
            if depth > 17:
                raise ValueError('JSON nesting limit')
        elif character in ']}':
            depth -= 1
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = value
        return result
    def reject(_):
        raise ValueError('noninteger JSON number')
    def measurement(raw):
        value = float(raw)
        if not math.isfinite(value):
            raise ValueError('nonfinite JSON measurement')
        return value
    def measurement_integer(raw):
        value = int(raw)
        if 2**53 <= value <= 2**64-1:
            return str(value)
        return value
    try:
        value = json.loads(text, object_pairs_hook=pairs,
            parse_float=measurement if allow_measurement_floats else reject, parse_constant=reject,
            parse_int=measurement_integer if uint64_measurements_as_strings else int)
        def bounded(v, depth=0):
            if depth > 16:
                raise ValueError('JSON nesting limit')
            if type(v) is int and not -(2**53-1) <= v <= 2**53-1:
                raise ValueError('JSON integer limit')
            if isinstance(v, str) and (len(v.encode('utf-8')) > string_limit or '\0' in v or unicodedata.normalize('NFC', v) != v):
                raise ValueError('JSON string limit')
            if isinstance(v, dict):
                for k, child in v.items():
                    bounded(k, depth+1); bounded(child, depth+1)
            elif isinstance(v, list):
                for child in v:
                    bounded(child, depth+1)
        bounded(value)
        return value
    except (RecursionError, UnicodeError) as exc:
        raise ValueError('invalid bounded JSON') from exc


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('state directory must be owner-controlled and not a symlink')


def atomic_write(path, data, *, limit=LIMIT):
    path = Path(path)
    if type(limit) is not int or limit < 1 or len(data) > limit:
        raise ValueError('state size limit')
    private_directory(path.parent)
    if path.exists() or path.is_symlink():
        private_read(path, limit=limit)
    with tempfile.TemporaryDirectory(prefix='.shadow6-', dir=path.parent) as directory:
        temp = Path(directory) / 'state'
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
