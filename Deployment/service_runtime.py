"""Linux local service supervision: fixed Core argv, bounded lifetime, PID identity."""
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

try:
    from .service_storage import private_read, strict_json
except ImportError:
    from service_storage import private_read, strict_json


_CHILDREN = {}
try:
    _BOOT_ID = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
except OSError:
    _BOOT_ID = None

def identity(pid):
    try:
        data = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        if data[0] == 'Z':
            return None
        return f'{_BOOT_ID}:{data[19]}' if _BOOT_ID else None
    except (OSError, IndexError):
        return None


def alive(runtime):
    pid = runtime.get('pid')
    return type(pid) is int and pid > 1 and identity(pid) == runtime.get('processIdentity') and runtime.get('processIdentity') is not None


def stop(runtime):
    if not alive(runtime):
        child = _CHILDREN.pop(runtime.get('pid'), None)
        if child is not None:
            child.poll()
        return
    try:
        fd = os.pidfd_open(runtime['pid'])
    except ProcessLookupError:
        return
    try:
        if not alive(runtime):
            return
        try:
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 8
        while alive(runtime) and time.monotonic() < deadline:
            time.sleep(.05)
        if alive(runtime):
            raise ValueError('service shutdown timed out; state retained')
    finally:
        os.close(fd)
        child = _CHILDREN.pop(runtime.get('pid'), None)
        if child is not None:
            child.wait(timeout=1)


def executable(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_uid not in (0, os.geteuid()) or not os.access(path, os.X_OK):
        raise ValueError('executable must be an owner-controlled regular file')
    return str(path.absolute())


def start(plan):
    if sys.platform != 'linux' or not hasattr(os, 'pidfd_open'):
        raise ValueError('named service supervision requires Linux pidfd; use native CLI on this platform')
    for pid, child in list(_CHILDREN.items()):
        if child.poll() is not None:
            del _CHILDREN[pid]
    read_fd, write_fd = os.pipe()
    try:
        child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), str(plan), str(write_fd)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 pass_fds=(write_fd,), start_new_session=True)
    finally:
        os.close(write_fd)
    import select
    try:
        if not select.select([read_fd], [], [], 8)[0] or os.read(read_fd, 16) != b'OK':
            child.terminate(); child.wait(timeout=8)
            raise ValueError('service failed to start; check native configuration and executable')
        token = identity(child.pid)
        if token is None:
            raise ValueError('service exited during startup')
        _CHILDREN[child.pid] = child
        return {'pid': child.pid, 'processIdentity': token, 'readiness': 'process-alive'}
    finally:
        os.close(read_fd)


def supervise(plan_path, ack):
    plan = strict_json(private_read(plan_path))
    root = Path(plan['root'])
    sys.path.insert(0, str(root / 'CLI'))
    from native_config import load, prepare
    import tempfile
    children = []
    stopping = False
    def request_stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        with tempfile.TemporaryDirectory(prefix='shadow6-native-') as directory:
            core = plan['core']
            binary = executable(plan['binary'])
            config = plan['config']
            if core in ('carp', 'idris'):
                value = load(config)
                if value['core'] != core:
                    raise ValueError('native Core identity mismatch')
                argv = prepare(value, binary, directory)
            else:
                private_read(config)
                argv = [binary, '--config', config]
            commands = [argv]
            if plan.get('envelopeConfig'):
                private_read(plan['envelopeConfig'])
                commands.append([executable(plan['envelopeBinary']), '--config', plan['envelopeConfig']])
            for argv in commands:
                children.append(subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            deadline = time.monotonic() + plan['ttl']
            time.sleep(.3)
            if stopping or any(p.poll() is not None for p in children):
                raise ValueError('early process exit')
            os.write(ack, b'OK'); os.close(ack); ack = -1
            while not stopping and time.monotonic() < deadline and all(p.poll() is None for p in children):
                time.sleep(.1)
    finally:
        if ack >= 0:
            os.close(ack)
        for p in children:
            if p.poll() is None:
                p.terminate()
        for p in children:
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                p.kill(); p.wait(timeout=2)


if __name__ == '__main__':
    supervise(Path(sys.argv[1]), int(sys.argv[2]))
