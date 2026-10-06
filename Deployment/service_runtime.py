"""Linux local service supervision: fixed Core argv, bounded lifetime, PID identity."""
import os
import hashlib
import json
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

try:
    from .service_storage import private_read, strict_json, atomic_write
    from .runtime_observation import sockets, private_socket, ready, validate_observation, endpoint_matches, control_connections
except ImportError:
    from service_storage import private_read, strict_json, atomic_write
    from runtime_observation import sockets, private_socket, ready, validate_observation, endpoint_matches, control_connections


def native_observed_endpoints(pid, native):
    result = sockets(pid)
    # Datagram native-file contracts can connect their transport socket before
    # admission. Require the exact configured local and peer tuple and actual
    # FD ownership; an unrelated UDP socket cannot establish startup readiness.
    if not result and 'peer_port' in native and 'listen_port' in native:
        result = [item for item in control_connections(pid, transport='udp')
                  if item['port'] == native['listen_port']
                  and item['remotePort'] == native['peer_port']
                  and item['remoteHost'] == native.get('peer_host', '127.0.0.1')]
    # Some stream agents allocate their data listener only when a client is
    # admitted. Their existing owned control connection is the startup boundary;
    # it is explicitly distinct from application readiness and authentication.
    if native.get('role') == 'agent' and not result:
        from urllib.parse import urlsplit
        config = native.get('agent', {})
        peers = config.get('broker_addrs') or [config.get('broker_addr', '')]
        targets = []
        for peer in peers:
            parsed = urlsplit(peer if '://' in peer else 'tcp://' + peer)
            if parsed.hostname and parsed.port: targets.append((parsed.hostname, parsed.port))
        result = [item for item in control_connections(pid)
                  if (item['remoteHost'], item['remotePort']) in targets]
    return result


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


def executable_digest(path):
    """Hash a stable, bounded executable through a rechecked file descriptor."""
    path = Path(executable(path))
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    def token(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_nlink,
                info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_size > 536870912
                or opened.st_mode & 0o022 or opened.st_uid not in (0,os.geteuid())
                or not opened.st_mode & 0o111):
            raise ValueError('executable descriptor must remain owner-controlled and bounded')
        if token(before) != token(opened) or token(path.lstat()) != token(opened):
            raise ValueError('executable changed while opening')
        digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            data = os.read(fd,min(65536,remaining))
            if not data: raise ValueError('executable changed while reading')
            digest.update(data);remaining -= len(data)
        if os.read(fd,1) or token(opened) != token(os.fstat(fd)) or token(path.lstat()) != token(opened):
            raise ValueError('executable changed while reading')
        return 'sha256:' + digest.hexdigest()
    finally:
        os.close(fd)




def source_material_digest(path):
    """Hash bounded owner-controlled implementation files without execute flags."""
    path = Path(path)
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    def token(value):
        return (value.st_dev,value.st_ino,value.st_size,value.st_mode,value.st_uid,value.st_nlink,value.st_mtime_ns,value.st_ctime_ns)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or
                opened.st_uid not in (0,os.geteuid()) or opened.st_mode & 0o022 or
                opened.st_size > 1048576 or token(before) != token(opened)):
            raise ValueError('invalid owner-controlled runtime implementation material')
        data = bytearray()
        while len(data) <= 1048576:
            block = os.read(fd,65536)
            if not block: break
            data.extend(block)
        if len(data) != opened.st_size or token(opened) != token(os.fstat(fd)) or token(opened) != token(path.lstat()):
            raise ValueError('runtime implementation material changed while reading')
        return 'sha256:' + hashlib.sha256(data).hexdigest()
    finally: os.close(fd)


def runtime_material_paths(root):
    """Fixed supervisor/config/record adapter inputs used by this invocation."""
    import native_profiles, feature_contract, limits
    here = Path(__file__).absolute().parent
    files = {name: str(here / (name + '.py')) for name in (
        'service_runtime','service_registry','runtime_observation','application_attachment',
        'credited_attachment','service_storage','profile_registry','protocol_context',
        'service_composition','broker_set')}
    # Lock the one existing adapter in a checkout or the installed companion
    # tree. The installed deployment module is a sibling of tree/, not CLI/.
    config_adapter = here.parent / 'CLI/native_config.py'
    if not config_adapter.is_file():
        config_adapter = Path(root) / 'CLI/native_config.py'
    if not config_adapter.is_file():
        config_adapter = here / 'native_config.py'
    files.update(native_config=str(config_adapter),
                 limits=str(Path(limits.__file__).absolute()),
                 native_profiles=str(Path(native_profiles.__file__).absolute()),
                 feature_contract=str(Path(feature_contract.__file__).absolute()))
    s6na_adapter = Path(root) / 'Network-Adapter/shadow6_network.py'
    if not s6na_adapter.is_file():
        s6na_adapter = here.parent / 'Network-Adapter/shadow6_network.py'
    if not s6na_adapter.is_file():
        s6na_adapter = here.parent / 'modules/shadow6_network.py'
    if s6na_adapter.is_file():
        files['s6na_adapter'] = str(s6na_adapter)
    provider = Path(root) / 'OCaml/privacy_envelope/lib/libdatachannel.so.0.23'
    if provider.exists() or provider.is_symlink():
        files['envelope_webrtc_provider'] = str(provider)
    return files


def runtime_material_digest(key, path):
    # The optional provider is compiled native code, not a small Python source
    # file. Apply the same bounded, owner-controlled executable check used for
    # Core and peripheral binaries.
    return executable_digest(path) if key == 'envelope_webrtc_provider' else source_material_digest(path)

def feature_report(binary: str, *, require_core=True) -> dict:
    import selectors
    binary_path = Path(executable(binary))
    before = executable_digest(binary_path)
    # Generated Idris/Chez launchers and Core-Nim load libraries from their
    # adjacent, artifact-owned directories. Reconstruct that narrow runtime
    # environment from the executable's install tree, while stripping ambient
    # loader overrides for every Core.
    root = binary_path.parent.parent
    try:
        relative = binary_path.relative_to(root)
    except ValueError:
        relative = binary_path.name
    try:
        from feature_contract import runtime_environment
    except ImportError:
        from Crosed.feature_contract import runtime_environment
    environment = runtime_environment(root, relative)
    process = subprocess.Popen([executable(binary), "--feature-report"], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, close_fds=True, env=environment)
    data = bytearray()
    deadline = time.monotonic() + 3
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("feature-report timeout")
                events = selector.select(remaining)
                if not events:
                    raise ValueError("feature-report timeout")
                block = os.read(process.stdout.fileno(), min(16385, 65537 - len(data)))
                data.extend(block)
                if len(data) > 65536:
                    raise ValueError("feature-report exceeds 64 KiB")
                if not block:
                    break
        if process.wait(timeout=max(0.1, deadline-time.monotonic())) != 0:
            raise ValueError("feature-report failed")
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()
    value = strict_json(bytes(data))
    if not isinstance(value, dict) or (require_core and not isinstance(value.get("core"), str)):
        raise ValueError("invalid Core feature-report")
    if executable_digest(binary_path) != before:
        raise ValueError("feature-report binary changed during probe")
    return value


def verify_launch_material(plan):
    required = {'root','core','profileBinding','binary','config','ttl','launchDigests','runtimeMaterials'}
    allowed = {'envelopeTlsCert','envelopeTlsKey','envelopeTlsCa'} | required | {'launchAdapter','protocolContext','contextDigest','lockDigest','nativeMaterials','componentMaterials','limitResolution','componentLimits','creditedAttachment','creditedConfig','creditedKey'} | {c + k for c in ('envelope','gate','guard') for k in ('Config','Binary')}
    if not isinstance(plan,dict) or not required <= set(plan) or set(plan) - allowed:
        raise ValueError('invalid launch plan fields')
    if not isinstance(plan['core'],str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,63}',plan['core']) is None:
        raise ValueError('invalid launch Core identity')
    try:
        from .profile_registry import native_material_paths, validate_profile_binding, validate_profile_realization
    except ImportError:
        from profile_registry import native_material_paths, validate_profile_binding, validate_profile_realization
    profile = validate_profile_binding(plan['profileBinding'], core=plan['core'])
    if 'limitResolution' in plan:
        from limits import LimitResolver, HostBudget
        LimitResolver().validate(plan['limitResolution'], profile)
    elif 'lockDigest' in plan:
        raise ValueError('LegacyLimitsLock: explicitly relock')
    if ('componentLimits' in plan) != ('componentLimits' in plan.get('launchDigests', {})):
        raise ValueError('component limits require exact launch digest')
    if type(plan['ttl']) is not int or not 30 <= plan['ttl'] <= 86400:
        raise ValueError('invalid launch lifetime')
    if plan.get('launchAdapter','native-config') not in ('native-config','native-files'):
        raise ValueError('capability unavailable: Core launch adapter')
    for component in ('envelope','gate','guard'):
        if (component + 'Config' in plan) != (component + 'Binary' in plan):
            raise ValueError('incomplete launch component realization')
    credited_keys = {'creditedAttachment','creditedConfig','creditedKey'} & set(plan)
    if credited_keys and len(credited_keys) != 3:
        raise ValueError('incomplete S6NA credited attachment realization')
    for key in ('root','binary','config') + tuple(k for k in plan if k.endswith(('Config','Binary','Key')) or k.startswith('envelopeTls')):
        if not isinstance(plan[key],str) or not Path(plan[key]).is_absolute():
            raise ValueError('absolute launch paths required')
    expected = plan.get('launchDigests')
    files = {'binary':'executable','config':'private'}
    for component in ('envelope','gate','guard'):
        if component + 'Config' in plan:
            files[component + 'Config'] = 'private'
            files[component + 'Binary'] = 'executable'
    if credited_keys:
        files['creditedConfig'] = 'private'
        files['creditedKey'] = 'credited-key'
    tls_keys = {'envelopeTlsCert','envelopeTlsKey','envelopeTlsCa'} & set(plan)
    if tls_keys and (len(tls_keys) != 3 or 'envelopeConfig' not in plan):
        raise ValueError('incomplete TLS launch material')
    files.update({key:'tls-private' for key in tls_keys})
    # Check every direct launch input against its lock before parsing it. A
    # mutated, malformed file is still reported as locked-material drift.
    if not isinstance(expected, dict) or not set(files) <= set(expected):
        raise ValueError('launch plan requires exact locked file digests')
    for key, kind in files.items():
        locked = expected[key]
        if not isinstance(locked, str) or re.fullmatch(r'sha256:[0-9a-f]{64}', locked) is None:
            raise ValueError('invalid locked launch digest')
        read_limit = 32 if kind == 'credited-key' else 16384 if kind == 'tls-private' else 1048576
        actual = executable_digest(plan[key]) if kind == 'executable' else 'sha256:' + hashlib.sha256(private_read(plan[key], limit=read_limit)).hexdigest()
        if actual != locked:
            raise ValueError(f'deployment drift before launch: {key}; explicitly reconfigure')

    native = strict_json(private_read(plan['config']))
    validate_profile_realization(plan['profileBinding'], native, plan.get('protocolContext'))
    native_materials = native_material_paths(plan['profileBinding'], native)
    if plan.get('nativeMaterials', {}) != native_materials:
        raise ValueError('native launch material differs from locked configuration')
    if credited_keys:
        try:
            from .credited_attachment import validate_attachment, credited_core
        except ImportError:
            from credited_attachment import validate_attachment, credited_core
        expected_credited_core = credited_core(plan['core'], profile)
        locked_attachment = validate_attachment(plan['creditedConfig'], root=plan['root'], expected_core=expected_credited_core)
        if (locked_attachment != plan['creditedAttachment'] or
                plan['creditedKey'] != locked_attachment['keyPath']):
            raise ValueError('S6NA attachment material differs from deployment lock')
    if 'componentLimits' in plan:
        inputs = {}
        if 'gateConfig' in plan:
            inputs['gate'] = strict_json(private_read(plan['gateConfig']))
        if 'guardConfig' in plan:
            inputs['guard'] = strict_json(private_read(plan['guardConfig']))
        if 'creditedConfig' in plan:
            inputs['credited'] = strict_json(private_read(plan['creditedConfig'], limit=16384))
        if 'envelopeConfig' in plan:
            inputs['envelope'] = parse_envelope(private_read(plan['envelopeConfig']))
        from limits import LimitResolver, HostBudget
        limit_resolution = plan.get('limitResolution')
        if not isinstance(limit_resolution, dict):
            raise ValueError('component limits require host limit resolution')
        base = LimitResolver().validate(limit_resolution, profile)
        LimitResolver().validate_components(plan['componentLimits'], inputs,
            host=HostBudget.from_dict(base['host_budget']),
            process_fds=base['effective_limits']['process_fds'])
    if 'envelopeConfig' in plan:
        envelope_fields=parse_envelope(private_read(plan['envelopeConfig']))
        if envelope_fields.get('carrier')=='webrtc' and (
                profile['core']!='nim' or profile.get('transport')!='webrtc'):
            raise ValueError('WebRTC S6EPE requires the locked Nim/WebRTC Profile')
    try:
        from .service_composition import component_material_paths
    except ImportError:
        from service_composition import component_material_paths
    component_materials = {key:path for component in ('gate','guard') if component + 'Config' in plan
                           for key,path in component_material_paths(component, strict_json(private_read(plan[component + 'Config']))).items()}
    if plan.get('componentMaterials', {}) != component_materials:
        raise ValueError('component launch material differs from locked configuration')
    runtime_materials = runtime_material_paths(plan['root'])
    if plan['runtimeMaterials'] != runtime_materials:
        raise ValueError('runtime implementation material differs from approved launch plan')
    material_keys = {'nativeMaterial:' + key for key in native_materials} | {'componentMaterial:' + key for key in component_materials} | {'runtimeMaterial:' + key for key in runtime_materials}
    exact = set(files) | material_keys | ({'componentLimits'} if 'componentLimits' in plan else set())
    if not isinstance(expected,dict) or set(expected) != exact:
        raise ValueError('launch plan requires exact locked file digests')
    if 'componentLimits' in plan:
        actual = 'sha256:' + hashlib.sha256(json.dumps(plan['componentLimits'], sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        if expected['componentLimits'] != actual:
            raise ValueError('deployment drift before launch: componentLimits')
    for key,kind in files.items():
        digest = expected[key]
        if not isinstance(digest,str) or re.fullmatch(r'sha256:[0-9a-f]{64}',digest) is None:
            raise ValueError('invalid locked launch digest')
        read_limit = 32 if kind == 'credited-key' else 16384 if kind == 'tls-private' else 1048576
        actual = executable_digest(plan[key]) if kind == 'executable' else 'sha256:' + hashlib.sha256(private_read(plan[key],limit=read_limit)).hexdigest()
        if actual != digest:
            raise ValueError(f'deployment drift before launch: {key}; explicitly reconfigure')
    for key,path in native_materials.items():
        actual = 'sha256:' + hashlib.sha256(private_read(path,limit=16384)).hexdigest()
        if expected['nativeMaterial:' + key] != actual:
            raise ValueError('deployment drift before launch: nativeMaterial:' + key)
    for key,path in runtime_materials.items():
        if expected['runtimeMaterial:' + key] != runtime_material_digest(key, path):
            raise ValueError('deployment drift before launch: runtimeMaterial:' + key)
    for key,path in component_materials.items():
        actual = 'sha256:' + hashlib.sha256(private_read(path,limit=16384)).hexdigest()
        if expected['componentMaterial:' + key] != actual:
            raise ValueError('deployment drift before launch: componentMaterial:' + key)
    if 'envelopeConfig' in plan:
        actual_tls = envelope_tls_material(parse_envelope(private_read(plan['envelopeConfig'])))
        if actual_tls != {key:plan[key] for key in tls_keys}:
            raise ValueError('TLS launch material differs from envelope configuration')
    verify_launch_admission(plan)


def verify_launch_admission(plan):
    """Recheck original S6P1 admission; expiration is not a startup-only rule."""
    keys = {'protocolContext','contextDigest','lockDigest'}
    if not keys & set(plan): return  # Legacy direct supervisor plans.
    if not keys <= set(plan): raise ValueError('incomplete approved launch context')
    try:
        from .protocol_context import context_digest, admit_realization
        from .topology_contract import check_node_binding
    except ImportError:
        from protocol_context import context_digest, admit_realization
        from topology_contract import check_node_binding
    context = plan['protocolContext']
    if context_digest(context) != plan['contextDigest']:
        raise ValueError('launch intent digest mismatch')
    if not isinstance(plan['lockDigest'],str) or re.fullmatch(r'sha256:[0-9a-f]{64}',plan['lockDigest']) is None:
        raise ValueError('invalid approved lock digest')
    for route in context['routes']:
        if route.get('kind') == 'broker_set' and 'engine' in route:
            check_node_binding(route['engine'],plan['core'],role=context['role'] if context['role'] != 'all' else 'client')
    native = strict_json(private_read(plan['config']))
    role = native.get('role') if isinstance(native,dict) else None
    if role is not None and context['role'] not in ('all',role):
        raise ValueError('launch native role conflicts with S6P1')
    components = [('s6epe' if c == 'envelope' else c) for c in ('envelope','gate','guard') if c + 'Config' in plan]
    admit_realization(context,native_role=role,components=components)


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
        acknowledgement = os.read(read_fd, 4096) if select.select([read_fd], [], [], 32)[0] else b''
        if acknowledgement != b'OK':
            child.terminate(); child.wait(timeout=8)
            detail = acknowledgement.removeprefix(b'ERROR:').decode('utf-8', errors='replace') if acknowledgement.startswith(b'ERROR:') else 'StartupAcknowledgementUnavailable'
            raise ValueError('service failed to start: ' + detail)
        token = identity(child.pid)
        if token is None:
            raise ValueError('service exited during startup')
        _CHILDREN[child.pid] = child
        return {'pid': child.pid, 'processIdentity': token, 'readiness': 'unavailable'}
    finally:
        os.close(read_fd)


def supervise(plan_path, ack):
    os.umask(0o077)
    plan = strict_json(private_read(plan_path))
    verify_launch_material(plan)
    root = Path(plan['root'])
    # The locked adapter path is the implementation selected during apply.
    # Installed trees keep Python modules outside the Core artifact tree.
    sys.path.insert(0, str(Path(plan['runtimeMaterials']['native_config']).parent))
    from native_config import load, prepare
    import tempfile
    children = []
    attachment = None
    signalling_broker = None
    application_completed = False
    stopping = False
    def request_stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        with tempfile.TemporaryDirectory(prefix='shadow6-native-') as directory:
            core = plan['core']
            try:
                from .profile_registry import validate_profile_binding
            except ImportError:
                from profile_registry import validate_profile_binding
            profile = validate_profile_binding(plan['profileBinding'], core=core)
            from limits import LimitResolver
            resolution = LimitResolver().validate(plan['limitResolution'], profile, check_host=True)
            import resource
            fd_limit = resolution['effective_limits']['process_fds']
            resource.setrlimit(resource.RLIMIT_NOFILE, (fd_limit, fd_limit))
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
            native_config = strict_json(private_read(config))
            if profile['attachment']['mode'] == 'seqpacket-fd' and native_config.get('role') == 'client':
                try:
                    from .application_attachment import NativeRecordAttachment
                except ImportError:
                    from application_attachment import NativeRecordAttachment
                attachment = NativeRecordAttachment(Path(directory) / 'application.sock', plan['profileBinding'],
                    resolution['effective_limits']['max_record'], plan['lockDigest'])
            commands = [argv]
            envelope_fields = None
            if plan.get('envelopeConfig'):
                envelope_fields=parse_envelope(private_read(plan['envelopeConfig']))
                validate_envelope(envelope_fields)
                if envelope_fields.get('carrier') == 'webrtc':
                    try:
                        from .webrtc_broker import SignallingBroker
                    except ImportError:
                        from webrtc_broker import SignallingBroker
                    signalling_broker = SignallingBroker(envelope_fields['signal_path'], envelope_fields['signal_id'], max_sessions=int(envelope_fields.get('max_sessions','32'))).start()
                commands.append([executable(plan['envelopeBinary']), '--config', plan['envelopeConfig']])
            gate_value = strict_json(private_read(plan['gateConfig'])) if plan.get('gateConfig') else None
            for component in ('gate','guard'):
                if plan.get(component + 'Config'):
                    private_read(plan[component + 'Config'])
                    commands.append([executable(plan[component + 'Binary']), '--config', plan[component + 'Config']])
            # Spawn dependencies first, while keeping the observation's stable
            # native/EPE/Gate/Guard indexing for every backend and consumer.
            labels = ['core'] + [name for name in ('envelope','gate','guard') if plan.get(name + 'Config')]
            launch_order = ['gate','core','envelope','guard'] if gate_value and gate_value.get('role') == 'client' else ['core','gate','envelope','guard']
            children = [None] * len(commands)
            startup_deadline = time.monotonic() + 30
            for label in launch_order:
                if label not in labels: continue
                index = labels.index(label); argv = commands[index]
                verify_launch_material(plan)
                from feature_contract import runtime_environment
                environment = runtime_environment(root, profile['artifact'] if index == 0 else str(argv[0]))
                environment.pop('SHADOW6_APP_FLOW_FD', None)
                descriptors = ()
                if index == 0 and attachment is not None:
                    environment['SHADOW6_APP_FLOW_FD'] = str(attachment.child_fd)
                    descriptors = (attachment.child_fd,)
                children[index] = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                                 env=environment, pass_fds=descriptors)
                if index == 0 and attachment is not None: attachment.release_child()
                os.set_blocking(children[index].stdout.fileno(), False)
                if label != 'core':
                    component_deadline = min(startup_deadline, time.monotonic() + 5)
                    while not sockets(children[index].pid):
                        if stopping or children[index].poll() is not None or time.monotonic() >= component_deadline:
                            raise ValueError(label + ' did not expose an owned readiness listener')
                        time.sleep(.05)
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
                native_owner = {'pid':children[0].pid,'processIdentity':identity(children[0].pid)}
                if attachment is not None:
                    if ready_state and not attachment.ready: attachment.acknowledge(ready_state, native_owner)
                    attachment.pump()
                native = native_observed_endpoints(children[0].pid, native_config)
                webtransport='unknown'
                if envelope_fields and envelope_fields.get('carrier')=='webrtc':
                    try:
                        status=strict_json(private_read(envelope_fields['metrics_path'],limit=16384))
                        fresh=(type(status.get('observed_at')) is int and 0<=int(time.time())-status['observed_at']<=5)
                        webtransport='ready' if (fresh and status.get('schema')=='shadow6.privacy-envelope-status.v6'
                            and status.get('carrier')=='webrtc' and type(status.get('active_sessions')) is int
                            and status['active_sessions']>0) else 'pending'
                    except (OSError,ValueError,KeyError,TypeError): webtransport='pending'
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
                            if not any(endpoint_matches(e,parsed) for e in native):
                                raise ValueError('Gate upstream is not an observed deployment listener')
                    carrier=envelope_fields.get('carrier','raw')
                    transport={'stream':'tcp','datagram':'udp','message':('udp' if carrier=='webrtc' else 'sctp')}[envelope_fields.get('mode','stream')]
                    if carrier!='webrtc' and not any(endpoint_matches(e,upstream,transport=transport) for e in upstream_sockets):
                        raise ValueError('envelope upstream is not an observed deployment listener')
                if envelope_fields and envelope_fields.get('carrier')=='webrtc' and webtransport=='ready':
                    if not any(e.get('transport')=='udp' for e in public):
                        webtransport='pending'
                result = {'limitResolutionDigest': __import__('limits').LimitResolution(resolution).digest,
                          'effectiveLimits':resolution['effective_limits'],
                          'limitsEnforcement':{'process_fds':{'actual':resource.getrlimit(resource.RLIMIT_NOFILE)[0], 'enforced':True}},
                          'observedAt':int(time.time()), 'pid':os.getpid(), 'processIdentity':identity(os.getpid()),
                          'processes':[{'pid':p.pid,'processIdentity':identity(p.pid)} for p in children],
                          'nativeEndpoints':native, 'endpoints':public,
                          'endpoint':public[0] if len(public) == 1 else None,
                          'readiness':('control-ready' if any(e.get('observation') == 'process-owned-control-connection' for e in public)
                                       else 'listener-ready') if public else 'process-alive',
                          'transportReadiness':webtransport,'applicationReadiness':'unknown'}
                candidate = ready_state.get('endpoint',{})
                if (ready_state and candidate.get('boundary') == profile['attachment']['kind']
                        and candidate.get('mode') == profile['attachment']['mode']
                        and any(e.get('host') == candidate.get('host') and e.get('port') == candidate.get('port')
                                and e['transport'] == profile['attachment']['transport'] for e in native)):
                    result.update(ready_state)
                    result['endpoint']['owner']={'pid':children[0].pid,'processIdentity':identity(children[0].pid)}
                    result['applicationReadiness'] = 'ready'
                if attachment is not None and attachment.ready:
                    result.update(endpoint=attachment.endpoint({'pid':os.getpid(),'processIdentity':identity(os.getpid())},native_owner),
                                  readiness='application-ready', applicationReadiness='ready')
                if plan.get('envelopeConfig') and attachment is None:
                    # The public connection endpoint always denotes EPE, even
                    # when native client stdout reports an application endpoint.
                    result['endpoint'] = public[0] if len(public) == 1 else None
                    result['readiness'] = 'listener-ready' if public else 'process-alive'
                atomic_write(observed_path, __import__('json').dumps(result).encode())
                return result
            deadline = time.monotonic() + plan['ttl']
            time.sleep(.3)
            exited = [(index, child.poll()) for index, child in enumerate(children) if child.poll() is not None]
            if stopping or exited:
                raise ValueError('early process exit: ' + repr(exited[:4]))
            while True:
                try:
                    observation = observe_children()
                    native_ready = (observation['readiness'] == 'application-ready' if native_config.get('role') == 'client'
                                    else bool(observation['nativeEndpoints']))
                    components_ready = all(sockets(child.pid) for child in children[1:])
                    if envelope_fields and envelope_fields.get('carrier')=='webrtc':
                        envelope_endpoints=sockets(children[1].pid)
                        components_ready=(components_ready and
                                          any(e.get('transport')=='udp' for e in envelope_endpoints))
                    transport_ready=(observation['transportReadiness']!='pending')
                    if envelope_fields and envelope_fields.get('carrier')=='webrtc':
                        transport_ready=observation['transportReadiness']=='ready'
                    if not native_ready or not components_ready or not transport_ready:
                        if time.monotonic() >= startup_deadline:
                            issue='AuthenticatedWebRTCSessionTimeout' if not transport_ready else 'OwnedEndpointReadinessTimeout'
                            raise ValueError(issue + ': ' + core + '/' + str(native_config.get('role'))
                                + '; observed=' + observation['readiness'] + '; transport=' + observation['transportReadiness']
                                + '; readyEvent=' + str(bool(ready_state)))
                        for index, process in enumerate(children):
                            code = process.poll()
                            if code is not None:
                                raise ValueError(labels[index] + ' process exited before readiness (exit ' + str(code) + ')')
                        time.sleep(.05); continue
                    break
                except ValueError as error:
                    if 'not an observed deployment listener' not in str(error) or time.monotonic() >= startup_deadline or any(p.poll() is not None for p in children): raise
                    time.sleep(.1)
            verify_launch_material(plan)
            if stopping or any(p.poll() is not None for p in children):
                raise ValueError('critical process exited during startup')
            if ack >= 0:
                os.write(ack, b'OK'); os.close(ack); ack = -1
            checked = observed_at = time.monotonic()
            while not stopping and time.monotonic() < deadline and all(p.poll() is None for p in children):
                if attachment is not None: attachment.pump()
                if time.monotonic() - observed_at >= .2:
                    verify_launch_admission(plan); observe_children(); observed_at = time.monotonic()
                if time.monotonic() - checked >= 5:
                    verify_launch_material(plan)
                    checked = time.monotonic()
                time.sleep(.01 if attachment is not None else .2)
            if (not stopping and attachment is not None and attachment.input_eof and
                    children[0].poll() == 0 and all(p.poll() is None for p in children[1:])):
                drain_deadline = time.monotonic() + 8
                while (not attachment.output_eof or attachment.pending_peer is not None) and time.monotonic() < drain_deadline:
                    attachment.pump(); time.sleep(.01)
                application_completed = attachment.output_eof and attachment.pending_peer is None
            if application_completed:
                atomic_write(str(plan_path) + '.result', __import__('json').dumps({
                    'schema':'shadow6.runtime-result.v1', 'pid':os.getpid(), 'processIdentity':identity(os.getpid()),
                    'lockDigest':plan['lockDigest'], 'profileBinding':plan['profileBinding'],
                    'state':'exited', 'reason':'application-record-drained'}).encode())
    except (ValueError, OSError) as error:
        if ack >= 0:
            # Only supervisor diagnostics cross this private pipe. Native logs
            # and configuration contents may contain secrets and stay private.
            os.write(ack, b'ERROR:' + str(error).encode('utf-8')[:2048])
        raise
    finally:
        if signalling_broker is not None:
            signalling_broker.close()
        if ack >= 0:
            os.close(ack)
        for p in children:
            if p is None: continue
            if p.poll() is None:
                p.terminate()
        if attachment is not None: attachment.close()
        for p in children:
            if p is None: continue
            if p.stdout: p.stdout.close()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                p.kill(); p.wait(timeout=2)




def validate_native_file_config(root, native):
    """Use the one existing normalized native configuration authority."""
    sys.path.insert(0, str(Path(root) / 'CLI'))
    from native_config import validate
    return validate(native)

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


def parse_envelope(content):
    fields = {}
    for line in content.decode('utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        key, separator, value = line.partition('=')
        key = key.strip()
        if not separator or not key or key in fields:
            raise ValueError('invalid envelope configuration fields')
        fields[key] = value.strip()
    return fields


def envelope_tls_material(fields):
    carrier = fields.get('carrier','raw')
    keys = {'tls_cert','tls_key','tls_ca','tls_peer_name'}
    if carrier in {'raw','sctp','webrtc'}:
        if carrier == 'sctp' and fields.get('mode') != 'message':raise ValueError('SCTP requires message mode')
        if carrier == 'webrtc' and fields.get('mode') != 'message':raise ValueError('WebRTC requires message mode')
        if keys & set(fields): raise ValueError('raw carrier rejects TLS material')
        return {}
    if carrier != 'tls' or fields.get('mode','stream') != 'stream' or not keys <= set(fields):
        raise ValueError('TLS carrier requires stream mode and complete material')
    if re.fullmatch(r'[A-Za-z0-9.:-]{1,253}',fields['tls_peer_name']) is None:
        raise ValueError('invalid TLS peer name')
    material = {name:fields[key] for name,key in (
        ('envelopeTlsCert','tls_cert'),('envelopeTlsKey','tls_key'),('envelopeTlsCa','tls_ca'))}
    if len(set(material.values())) != 3 or any(not Path(path).is_absolute() for path in material.values()):
        raise ValueError('TLS material requires distinct absolute paths')
    if fields.get('metrics_path') in material.values():
        raise ValueError('TLS material conflicts with metrics path')
    for path in material.values(): private_read(path,limit=16384)
    return material


def validate_envelope(fields):
    try:
        from .broker_set import private_endpoint, endpoint
    except ImportError:
        from broker_set import private_endpoint, endpoint
    known={'listen','upstream','mode','role','auth_key','max_frame','handshake_timeout','max_preauth','max_sessions','idle_timeout','session_timeout','metrics_path','key_epoch','replay_path','padding_block','jitter_ms','cover_interval','cover_limit','shaping_budget','carrier','tls_cert','tls_key','tls_ca','tls_peer_name','message_channels','sctp_streams','signal_path','signal_id'}
    if set(fields)-known: raise ValueError('unknown envelope configuration field')
    if fields.get('role','server') != 'server': raise ValueError('privacy=envelope requires a server admission boundary')
    mode=fields.get('mode','stream')
    if mode not in {'stream','datagram','message'}: raise ValueError('invalid envelope mode')
    if mode == 'message':
        carrier=fields.get('carrier')
        if carrier not in {'sctp','webrtc'}:raise ValueError('message mode requires SCTP or WebRTC carrier')
        if carrier=='webrtc':
            if not {'signal_path','signal_id'} <= set(fields):raise ValueError('WebRTC requires Named Service signalling handoff')
            try: max_sessions=int(fields.get('max_sessions','32'))
            except (ValueError,TypeError) as error: raise ValueError('invalid WebRTC session limit') from error
            if not 1<=max_sessions<=128:raise ValueError('invalid WebRTC session limit')
            signal_path=fields['signal_path'];signal_id=fields['signal_id']
            if not Path(signal_path).is_absolute() or len(signal_path.encode())>103 or signal_path in {fields.get('metrics_path'),fields.get('listen'),fields.get('upstream')}:
                raise ValueError('invalid WebRTC signalling socket path')
            parent=Path(signal_path).parent
            try: info=parent.lstat()
            except OSError as error: raise ValueError('WebRTC signalling directory must exist') from error
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:
                raise ValueError('WebRTC signalling directory must be private and owner-controlled')
            if not isinstance(signal_id,str) or re.fullmatch(r'[A-Za-z0-9._-]{1,31}',signal_id) is None:
                raise ValueError('invalid WebRTC signalling service prefix')
            if not fields.get('metrics_path'):
                raise ValueError('WebRTC requires a session metrics path for readiness')
            metrics_path=fields['metrics_path']
            if not Path(metrics_path).is_absolute() or metrics_path in {signal_path,fields.get('listen'),fields.get('upstream')}:
                raise ValueError('invalid WebRTC session metrics path')
            metrics_parent=Path(metrics_path).parent
            try: metrics_parent_info=metrics_parent.lstat()
            except OSError as error: raise ValueError('WebRTC metrics directory must exist') from error
            if not stat.S_ISDIR(metrics_parent_info.st_mode) or metrics_parent_info.st_uid!=os.geteuid() or metrics_parent_info.st_mode&0o077:
                raise ValueError('WebRTC metrics directory must be private and owner-controlled')
        elif {'signal_path','signal_id'} & set(fields):raise ValueError('signal fields require WebRTC carrier')
        streams=int(fields.get('sctp_streams','4'))
        if not 1<=streams<=64:raise ValueError('invalid SCTP stream budget')
        seen=set();control=False
        for value in fields.get('message_channels','0:ordered:reliable').split(','):
            match=re.fullmatch(r'([0-9]+):(ordered|unordered):(reliable|retransmits:[0-9]+|lifetime:[0-9]+)',value)
            if not match:raise ValueError('invalid message channel schema')
            channel=int(match[1]);policy=match[3]
            if channel>=streams or channel in seen:raise ValueError('duplicate/unavailable message stream')
            seen.add(channel)
            if ':' in policy:
                kind,budget=policy.split(':');budget=int(budget)
                if not (0<=budget<=65535 if kind=='retransmits' else 1<=budget<=60000):raise ValueError('invalid message reliability budget')
            control=control or (channel==0 and match[2]=='ordered' and policy=='reliable')
        if not control:raise ValueError('ordered reliable message control channel required')
        if any(fields.get(key,'').startswith('unix:') for key in ('listen','upstream')):raise ValueError('message carriers require IP endpoints')
    elif {'message_channels','sctp_streams'} & set(fields):raise ValueError('message fields require message mode')
    replay_path=fields.get('replay_path')
    if mode == 'datagram':
        if not replay_path or not Path(replay_path).is_absolute() or replay_path in {fields.get('metrics_path'),fields.get('listen'),fields.get('upstream')}:
            raise ValueError('datagram mode requires a distinct absolute persistent replay_path')
        parent=Path(replay_path).parent
        try: info=parent.lstat()
        except OSError as error: raise ValueError('persistent replay directory must already exist') from error
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('persistent replay directory must be private and owner-controlled')
        try: private_read(replay_path,limit=400000)
        except FileNotFoundError: pass
        except OSError as error: raise ValueError('invalid private persistent replay state') from error
    elif replay_path is not None:
        raise ValueError('persistent replay_path is datagram-only')
    if not {'listen','upstream','auth_key'} <= set(fields):
        raise ValueError('envelope requires listen/upstream/auth_key')
    envelope_tls_material(fields)
    endpoint(fields['listen'])
    if not private_endpoint(fields['upstream']):
        raise ValueError('envelope invariant: native upstream must be literal loopback')
    return fields


def observe(item, plan_path):
    process = item.get('runtime')
    if not process:return
    if not alive(process):
        process['endpoint']=None;process['readiness']='unavailable';return
    try:
        value = strict_json(private_read(str(plan_path) + '.observed'))
        plan = strict_json(private_read(plan_path))
    except FileNotFoundError:
        process['endpoint']=None;process['readiness']='unavailable';return
    if not isinstance(plan,dict):raise ValueError('invalid runtime launch plan')
    value = validate_observation(value)
    try:
        from .profile_registry import validate_profile_binding
    except ImportError:
        from profile_registry import validate_profile_binding
    profile = validate_profile_binding(plan.get('profileBinding'), core=plan.get('core'))
    if plan.get('profileBinding') != item.get('profileBinding') or process.get('profileBinding') != item.get('profileBinding'):
        raise ValueError('runtime ProfileBinding differs from approved service')
    from limits import LimitResolver, LimitResolution
    resolution = LimitResolver().validate(plan.get('limitResolution'), profile)
    if (value.get('limitResolutionDigest') != LimitResolution(resolution).digest or
            value.get('effectiveLimits') != resolution['effective_limits']):
        raise ValueError('RuntimeLimitsDrift')
    if value.get('pid') != process['pid'] or value.get('processIdentity') != process['processIdentity']:
        raise ValueError('runtime observation identity mismatch')
    if type(value.get('observedAt')) is not int or not 0 <= int(time.time())-value['observedAt'] <= 2 or not all(alive(p) for p in value.get('processes',[])):
        process['endpoint']=None;process['readiness']='unavailable';return
    def direct_child(pid):
        try:
            stat_fields=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
            return int(stat_fields[1]) == process['pid']
        except (OSError,ValueError,IndexError):return False
    if not all(direct_child(p['pid']) for p in value['processes']):
        process['endpoint']=None;process['readiness']='unavailable';return
    children=value['processes']
    if len(children) != 1 + sum(component + 'Config' in plan for component in ('envelope','gate','guard')):
        raise ValueError('observed critical processes differ from deployment realization')
    if sys.platform == 'linux':
        for owned in [process] + value['processes']:
            with open('/proc/' + str(owned['pid']) + '/limits') as handle:
                actual = next((line.split()[-3:-1] for line in handle if line.startswith('Max open files')), None)
            if actual != [str(resolution['effective_limits']['process_fds'])] * 2:
                raise ValueError('RuntimeLimitsEnforcementDrift')
    native=native_observed_endpoints(children[0]['pid'], strict_json(private_read(plan['config'])))
    record_attachment = isinstance(value.get('endpoint'),dict) and value['endpoint'].get('observation') == 'supervisor-owned-record-adapter'
    if process['privacy'] == 'envelope' and value['readiness'] == 'application-ready' and not record_attachment:
        raise ValueError('envelope public endpoint must denote the admission listener')
    if process['privacy'] == 'envelope' and len(children) < 2:
        raise ValueError('envelope observation requires its critical admission process')
    public=sockets(children[1]['pid']) if process['privacy'] == 'envelope' else native
    target=value['endpoint']
    if process['privacy'] == 'envelope' and any(not private_socket(e) for e in native):
        process['endpoint']=None;process['readiness']='unavailable';return
    actual = (all(e in native for e in value['nativeEndpoints'])
              and all(e in public for e in value['endpoints']))
    if record_attachment:
        try:
            from .application_attachment import owned_seqpacket
        except ImportError:
            from application_attachment import owned_seqpacket
        actual = (actual and profile['attachment']['mode'] == 'seqpacket-fd' and
                  target['maxRecord'] == profile['limits']['max_record'] and
                  any(e.get('transport') == 'unix-seqpacket' and e.get('path') == target['path'] for e in sockets(process['pid'])) and
                  owned_seqpacket(children[0]['pid'], target['nativeFd'], target['nativeInode']))
    elif target is not None and value['readiness'] == 'application-ready':
        actual = actual and target.get('boundary') == profile['attachment']['kind'] and target.get('mode') == profile['attachment']['mode']
        actual = actual and any(e.get('host')==target['host'] and e.get('port')==target['port']
                                and e['transport'] == profile['attachment']['transport'] for e in native)
    if not actual:
        process['endpoint']=None;process['readiness']='unavailable';return
    process['endpoint'] = value['endpoint']
    process['readiness'] = value['readiness']
    item['runtimeObservation'] = value

if __name__ == '__main__':
    supervise(Path(sys.argv[1]), int(sys.argv[2]))
