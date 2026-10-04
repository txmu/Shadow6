"""Bounded private state used by the local service manager."""
import json
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
        if len(data) > limit or identity(opened) != identity(os.fstat(fd)):
            raise ValueError('private file changed or exceeded limit')
        return bytes(data)
    finally:
        os.close(fd)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = value
        return result
    def reject(_):
        raise ValueError('noninteger JSON number')
    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
        def bounded(v, depth=0):
            if depth > 24:
                raise ValueError('JSON nesting limit')
            if type(v) is int and not -(2**53-1) <= v <= 2**53-1:
                raise ValueError('JSON integer limit')
            if isinstance(v, str) and (len(v.encode('utf-8')) > 8192 or '\0' in v or unicodedata.normalize('NFC', v) != v):
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
