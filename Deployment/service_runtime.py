"""Linux local service supervision: fixed Core argv, bounded lifetime, PID identity."""
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

try:
    from .service_storage import private_read, strict_json, atomic_write
    from .runtime_observation import sockets, private_socket, ready
except ImportError:
    from service_storage import private_read, strict_json, atomic_write
    from runtime_observation import sockets, private_socket, ready


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
    if not stat.S_ISREG(info.st_mode) or info.st_size > 536870912 or info.st_mode & 0o022 or info.st_uid not in (0, os.geteuid()) or not os.access(path, os.X_OK):
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
            if plan.get('launchAdapter') == 'native-files':
                value = load(config)
                if value['core'] != core:
                    raise ValueError('native Core identity mismatch')
                argv = prepare(value, binary, directory)
            elif plan.get('launchAdapter', 'native-config') == 'native-config':
                private_read(config)
                argv = [binary, '--config', config]
            else:
                raise ValueError('capability unavailable: Core launch adapter')
            if plan.get('envelopeConfig'):
                validate_native_private(config)
            commands = [argv]
            envelope_fields = None
            if plan.get('envelopeConfig'):
                content=private_read(plan['envelopeConfig']).decode()
                envelope_fields={line.split('=',1)[0].strip():line.split('=',1)[1].strip() for line in content.splitlines() if line.strip() and not line.strip().startswith('#')}
                validate_envelope(envelope_fields)
                commands.append([executable(plan['envelopeBinary']), '--config', plan['envelopeConfig']])
            gate_value = strict_json(private_read(plan['gateConfig'])) if plan.get('gateConfig') else None
            for component in ('gate','guard'):
                if plan.get(component + 'Config'):
                    private_read(plan[component + 'Config'])
                    commands.append([executable(plan[component + 'Binary']), '--config', plan[component + 'Config']])
            for argv in commands:
                children.append(subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL))
                os.set_blocking(children[-1].stdout.fileno(), False)
            buffers = {p.pid:b'' for p in children}
            ready_state = {}
            observed_path = Path(str(plan_path) + '.observed')
            def observe_children():
                for child in children:
                    try: data = os.read(child.stdout.fileno(), 65536)
                    except BlockingIOError: data = b''
                    buf = buffers[child.pid] + data
                    for line in buf.split(b'\n')[:-1]:
                        if child is children[0] and len(line) <= 65536:
                            try: ready_state.update(ready(line, core))
                            except (ValueError, UnicodeError): pass
                    buffers[child.pid] = buf.rsplit(b'\n',1)[-1][-65536:]
                native = sockets(children[0].pid)
                if plan.get('envelopeConfig') and any(not private_socket(e) for e in native):
                    raise ValueError('envelope invariant: native Core public exposure rejected')
                public = sockets(children[1].pid) if plan.get('envelopeConfig') else native
                if envelope_fields:
                    try:
                        from .broker_set import endpoint
                    except ImportError:
                        from broker_set import endpoint
                    upstream = endpoint(envelope_fields['upstream'])
                    gate_index = 2 if plan.get('gateConfig') else None
                    upstream_sockets = sockets(children[gate_index].pid) if gate_index else native
                    if gate_index:
                        if any(not private_socket(e) for e in upstream_sockets):
                            raise ValueError('envelope invariant: Gate public exposure rejected')
                        for target in (gate_value.get('upstreams') or [gate_value.get('upstream','')]):
                            parsed = endpoint(target)
                            if not any(e['host']==parsed.hostname and e['port']==parsed.port for e in native):
                                raise ValueError('Gate upstream is not an observed deployment listener')
                    if not any(e['host'] == upstream.hostname and e['port'] == upstream.port for e in upstream_sockets):
                        raise ValueError('envelope upstream is not an observed deployment listener')
                result = {'observedAt':int(time.time()), 'pid':os.getpid(), 'processIdentity':identity(os.getpid()),
                          'processes':[{'pid':p.pid,'processIdentity':identity(p.pid)} for p in children],
                          'nativeEndpoints':native, 'endpoints':public,
                          'endpoint':public[0] if len(public) == 1 else None,
                          'readiness':'listener-ready' if public else 'process-alive',
                          'transportReadiness':'unknown','applicationReadiness':'unknown'}
                candidate = ready_state.get('endpoint',{})
                if ready_state and any(e['host'] == candidate.get('host') and e['port'] == candidate.get('port') and (candidate.get('boundary') != 'stream' or e['transport'] == 'tcp') for e in native):
                    result.update(ready_state)
                    result['endpoint']['owner']={'pid':children[0].pid,'processIdentity':identity(children[0].pid)}
                    result['applicationReadiness'] = 'ready'
                if plan.get('envelopeConfig'):
                    # The public connection endpoint always denotes EPE, even
                    # when native client stdout reports an application endpoint.
                    result['endpoint'] = public[0] if len(public) == 1 else None
                    result['readiness'] = 'listener-ready' if public else 'process-alive'
                atomic_write(observed_path, __import__('json').dumps(result).encode())
            deadline = time.monotonic() + plan['ttl']
            time.sleep(.3)
            if stopping or any(p.poll() is not None for p in children):
                raise ValueError('early process exit')
            startup_deadline=time.monotonic()+5
            while True:
                try:
                    observe_children();break
                except ValueError as error:
                    if 'not an observed deployment listener' not in str(error) or time.monotonic() >= startup_deadline or any(p.poll() is not None for p in children): raise
                    time.sleep(.1)
            os.write(ack, b'OK'); os.close(ack); ack = -1
            while not stopping and time.monotonic() < deadline and all(p.poll() is None for p in children):
                observe_children()
                time.sleep(.2)
    finally:
        if ack >= 0:
            os.close(ack)
        for p in children:
            if p.poll() is None:
                p.terminate()
        for p in children:
            if p.stdout: p.stdout.close()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                p.kill(); p.wait(timeout=2)



def validate_native_private(config):
    # Uniform listener contract keys; no Core identity branching or route guesses.
    value = strict_json(private_read(config))
    found = []
    def scan(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if key in {'listen_addr','listen_address','listen'} and isinstance(child,str):
                    found.append(child)
                if key == 'listen_host':
                    import ipaddress
                    try: valid = ipaddress.ip_address(child).is_loopback
                    except (ValueError, TypeError): valid = False
                    if not valid: raise ValueError('envelope invariant: public native listen_host rejected')
                    found.append(('['+str(child)+']' if ':' in str(child) else str(child)) + ':1')
                if key == 'listen_port' and 'listen_host' not in item:
                    raise ValueError('capability unavailable: native listen_port has no verifiable private host')
                scan(child)
        elif isinstance(item, list):
            for child in item: scan(child)
    scan(value)
    if not found: raise ValueError('capability unavailable: native private listener contract unavailable')
    try:
        from .broker_set import private_endpoint
    except ImportError:
        from broker_set import private_endpoint
    if any(not private_endpoint(target) for target in found):
        raise ValueError('envelope invariant: public native endpoint rejected')
    return value


def validate_envelope(fields):
    try:
        from .broker_set import private_endpoint, endpoint
    except ImportError:
        from broker_set import private_endpoint, endpoint
    known={'listen','upstream','mode','role','auth_key','max_frame','handshake_timeout','max_preauth','max_sessions','idle_timeout','session_timeout','metrics_path'}
    if set(fields)-known: raise ValueError('unknown envelope configuration field')
    if fields.get('role','server') != 'server': raise ValueError('privacy=envelope requires a server admission boundary')
    if fields.get('mode','stream') not in {'stream','datagram'}: raise ValueError('invalid envelope mode')
    if not {'listen','upstream','auth_key'} <= set(fields):
        raise ValueError('envelope requires listen/upstream/auth_key')
    endpoint(fields['listen'])
    if not private_endpoint(fields['upstream']):
        raise ValueError('envelope invariant: native upstream must be literal loopback')
    return fields


def observe(item, plan_path):
    process = item.get('runtime')
    if not process or not alive(process): return
    try: value = strict_json(private_read(str(plan_path) + '.observed'))
    except FileNotFoundError: return
    if value.get('pid') != process['pid'] or value.get('processIdentity') != process['processIdentity']:
        raise ValueError('runtime observation identity mismatch')
    if type(value.get('observedAt')) is not int or not 0 <= int(time.time())-value['observedAt'] <= 2 or not all(alive(p) for p in value.get('processes',[])):
        process['endpoint']=None;process['readiness']='unavailable';return
    process['endpoint'] = value['endpoint']
    process['readiness'] = value['readiness']
    item['runtimeObservation'] = value

if __name__ == '__main__':
    supervise(Path(sys.argv[1]), int(sys.argv[2]))
