"""Private, transactional named services with explicit Core bindings."""
from __future__ import annotations
import functools
import hashlib
import json
import os
import platform
import re
import sys
import time
import threading
from pathlib import Path
try:
    from .profile_registry import CORE_IDS, bind_profile, native_material_paths, validate_profile_binding, validate_profile_realization, LimitResolver, HostBudget, validate_policy
    from .core_catalog import CoreCatalog
    from .service_storage import private_read, strict_json, private_directory, atomic_write
    from . import service_runtime as runtime
    from .protocol_context import validate_context, minimal_context, check_binding, context_digest, admit, admit_realization
    from .connection_plan import resolve_connection
except ImportError:
    from profile_registry import CORE_IDS, bind_profile, native_material_paths, validate_profile_binding, validate_profile_realization, LimitResolver, HostBudget, validate_policy
    from core_catalog import CoreCatalog
    from service_storage import private_read, strict_json, private_directory, atomic_write
    import service_runtime as runtime
    from protocol_context import validate_context, minimal_context, check_binding, context_digest, admit, admit_realization
    from connection_plan import resolve_connection

NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
SCHEMA = 'shadow6.service-registry.v2'
MAX_REGISTRY_BYTES = 64 * 1024 * 1024
REGISTRY_BYTES_PER_SERVICE = 512
SERVICE_MEMORY_RESERVE = 64 * 1024
SERVICE_FD_RESERVE = 8


def _service_host_budget():
    try:
        return HostBudget.capture()
    except ValueError:
        # Python's resource/sysconf backend is not available on Windows. Query
        # physical memory through Win32 and retain a finite handle budget;
        # an unavailable platform probe must never make the registry unbounded.
        if sys.platform != 'win32':
            raise
        import ctypes
        from ctypes import wintypes

        class MemoryStatus(ctypes.Structure):
            _fields_ = [('dwLength', wintypes.DWORD), ('dwMemoryLoad', wintypes.DWORD),
                        ('ullTotalPhys', ctypes.c_ulonglong), ('ullAvailPhys', ctypes.c_ulonglong),
                        ('ullTotalPageFile', ctypes.c_ulonglong), ('ullAvailPageFile', ctypes.c_ulonglong),
                        ('ullTotalVirtual', ctypes.c_ulonglong), ('ullAvailVirtual', ctypes.c_ulonglong),
                        ('ullAvailExtendedVirtual', ctypes.c_ulonglong)]

        memory = MemoryStatus()
        memory.dwLength = ctypes.sizeof(MemoryStatus)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)) or memory.ullTotalPhys < 1:
            raise ValueError('HostBudgetUnavailable: Windows memory ceiling unavailable')
        return type('WindowsServiceBudget', (), {
            'memory_bytes': int(memory.ullTotalPhys), 'fd_ceiling': 65_536,
        })()


def service_capacity(host=None):
    """Return a finite service ceiling derived from host and registry budgets."""
    host = host or _service_host_budget()
    memory_capacity = max(1, host.memory_bytes // SERVICE_MEMORY_RESERVE)
    descriptor_capacity = max(1, host.fd_ceiling // SERVICE_FD_RESERVE)
    registry_capacity = MAX_REGISTRY_BYTES // REGISTRY_BYTES_PER_SERVICE
    return min(memory_capacity, descriptor_capacity, registry_capacity)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(value):
    return 'sha256:' + hashlib.sha256(value).hexdigest()


def transaction(method):
    @functools.wraps(method)
    def call(self, *args, **kwargs):
        if not self._thread_lock.acquire(timeout=12):
            raise ValueError('service registry busy')
        try:
            return invoke(self, *args, **kwargs)
        finally:
            self._thread_lock.release()
    def invoke(self, *args, **kwargs):
        if self._depth:
            return method(self, *args, **kwargs)
        import fcntl
        private_directory(self.path.parent)
        lock = self.path.with_suffix('.lock')
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            private_read(lock)
            deadline = time.monotonic() + 12
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); break
                except BlockingIOError:
                    if time.monotonic() > deadline:
                        raise ValueError('service registry busy')
                    time.sleep(.05)
            self._load(); self._depth = 1
            if getattr(self, '_migration_pending', False):
                self._save(); self._migration_pending = False
            return method(self, *args, **kwargs)
        finally:
            self._depth = 0
            os.close(fd)
    return call


class ServiceRegistry:
    def __init__(self, path=None, catalog=None):
        self.path = Path(path or os.environ.get('SHADOW6_SERVICE_REGISTRY', Path.home() / '.config/shadow6/services.json')).absolute()
        self.catalog = catalog or CoreCatalog()
        self.services = {}
        self._depth = 0
        self._thread_lock = threading.RLock()
        self._load()

    def _load(self):
        try:
            data = strict_json(private_read(self.path, limit=MAX_REGISTRY_BYTES))
        except FileNotFoundError:
            self.services = {}; return
        if (not isinstance(data, dict) or set(data) != {'schema', 'services'} or
                data['schema'] not in (SCHEMA, 'shadow6.service-registry.v1') or
                not isinstance(data['services'], dict) or
                len(data['services']) > MAX_REGISTRY_BYTES // REGISTRY_BYTES_PER_SERVICE):
            raise ValueError('invalid service registry')
        allowed = {'name', 'protocolContext', 'spec', 'privacy', 'privacyTelemetry', 'coreBinding', 'profileBinding', 'state', 'deploymentLock', 'runtime'}
        for name, item in data['services'].items():
            if not NAME.fullmatch(name) or not isinstance(item, dict) or set(item) - allowed or item.get('name') != name:
                raise ValueError('invalid named service record')
            if item.get('state') not in {'unresolved','ready','locked','applied','running','stopped','exited','stale','degraded','failed'}:
                raise ValueError('invalid service state')
            binding = item.get('coreBinding')
            if binding is not None:
                fields = {'core','version','binaryDigest','featureReportDigest','configSchemaVersion','config','configDigest'}
                if not isinstance(binding, dict) or set(binding) not in (fields,fields | {'descriptorDigest'}) or binding['core'] not in self.catalog._items:
                    raise ValueError('invalid Core binding')
                self.catalog.binding(binding['core'], binding['config'])
            profile = item.get('profileBinding')
            if profile is not None:
                if binding is None: raise ValueError('ProfileBinding requires CoreBinding')
                validate_profile_binding(profile, core=binding['core'], current=False)
            lock = item.get('deploymentLock')
            if lock is not None and (not isinstance(lock, dict) or set(lock) not in ({'schema','digest','coreBinding'}, {'schema','digest','coreBinding','contextDigest'}, {'schema','digest','coreBinding','contextDigest','limitResolution'}, {'schema','digest','coreBinding','contextDigest','limitResolution','componentLimits'}, {'schema','digest','coreBinding','profileBinding','contextDigest'}, {'schema','digest','coreBinding','profileBinding','contextDigest','limitResolution'}, {'schema','digest','coreBinding','profileBinding','contextDigest','limitResolution','componentLimits'}) or lock['schema'] != 'shadow6.deployment-lock.v2'):
                raise ValueError('invalid deployment lock')
            if lock is not None and 'profileBinding' in lock:
                validate_profile_binding(lock['profileBinding'], core=lock['coreBinding']['core'], current=False)
            process = item.get('runtime')
            if process is not None:
                fields = {'pid','processIdentity','readiness','state','core','lockDigest','endpoint','privacy','startedAt','expiresAt'}
                if not isinstance(process, dict) or set(process) not in (fields, fields | {'profileBinding'}) or type(process['pid']) is not int or process['pid'] <= 1 or not isinstance(process['processIdentity'], str) or not re.fullmatch(r'[0-9a-f-]{36}:[0-9]+', process['processIdentity']):
                    raise ValueError('invalid runtime identity; legacy simulated state needs explicit recreation')
                if 'profileBinding' in process:
                    validate_profile_binding(process['profileBinding'], core=process['core'], current=False)
                if any(type(process[k]) is not int for k in ('startedAt','expiresAt')):
                    raise ValueError('invalid runtime timestamps')
            if 'protocolContext' not in item:
                if process is not None:
                    raise ValueError(f'{name}: legacy runtime cannot establish S6P1 intent; stop/recreate explicitly')
                legacy = item.get('spec', {})
                if legacy.get('endpoint', {'mode':'private'}) != {'mode':'private'}:
                    raise ValueError(f'{name}: ambiguous legacy endpoint; supply an explicit S6P1 context')
                if binding is not None:
                    # Native config schemas are not interchangeable; only intent-free
                    # records can migrate without inventing role/routes/credentials.
                    try: native = strict_json(private_read(binding['config']['config_path']))
                    except (ValueError, OSError): native = None
                    if native != {}:
                        raise ValueError(f'{name}: legacy native intent requires explicit S6P1 recreation; no semantics guessed')
                item['protocolContext'] = minimal_context(binding['core'] if binding else None)
                item['spec'] = {k:v for k,v in legacy.items() if k != 'endpoint'}
                item.pop('deploymentLock', None)
                item['state'] = 'ready' if binding else 'unresolved'
            item['protocolContext'] = validate_context(item['protocolContext'])
            if binding: check_binding(item['protocolContext'], binding['core'], self.catalog)
            self._spec(item.get('spec', {}))
            if item.get('privacy') not in ('native', 'envelope'):
                raise ValueError('invalid privacy mode')
        self.services = data['services']
        if data['schema'] != SCHEMA:
            self._migration_pending = True

    def _save(self):
        atomic_write(self.path, encoded({'schema': SCHEMA, 'services': self.services}) + b'\n',
            limit=MAX_REGISTRY_BYTES)

    @staticmethod
    def _spec(spec):
        if not isinstance(spec, dict) or set(spec) - {'ttl', 'envelope_config', 'metrics_path', 'gate_config', 'guard_config', 'credited_config', 'limits'}:
            raise ValueError('unknown service specification field')
        if type(spec.get('ttl', 3600)) is not int or not 30 <= spec.get('ttl', 3600) <= 86400:
            raise ValueError('service ttl must be 30..86400 seconds')
        validate_policy(spec.get('limits'))
        for key in ('envelope_config', 'metrics_path', 'gate_config', 'guard_config', 'credited_config'):
            if key in spec and (not isinstance(spec[key], str) or not Path(spec[key]).is_absolute()):
                raise ValueError('service file references must be absolute paths')

    @transaction
    def init(self):
        self._save()
        return {'schema': 'shadow6.lifecycle.v1', 'stage': 'init', 'platform': platform.system(), 'statePath': str(self.path)}

    @transaction
    def create(self, name, *, core, config, spec=None, privacy='native', context=None, profile=None):
        if not NAME.fullmatch(name) or name in self.services:
            raise ValueError('service name must be unique namespace/name')
        if len(self.services) >= service_capacity():
            raise ValueError('host service capacity reached; remove unused services or increase available host resources')
        spec = spec or {}; self._spec(spec)
        if privacy not in ('native', 'envelope'):
            raise ValueError('privacy must be native or envelope')
        context = admit(validate_context(context)) if context is not None else minimal_context(core)
        binding = None if core is None else self.catalog.binding(core, config or {})
        if binding: check_binding(context, core, self.catalog)
        if profile is not None and core is None: raise ValueError('ProfileBinding requires explicit Core')
        profile_binding = bind_profile(core, profile) if core in CORE_IDS else None
        if profile is not None and profile_binding is None: raise ValueError('UnknownNativeProfile')
        item = {'name': name, 'protocolContext': context, 'spec': spec, 'privacy': privacy, 'coreBinding': binding, 'profileBinding': profile_binding,
                'state': 'unresolved' if binding is None else 'ready'}
        self.services[name] = item; self._save(); return item

    @transaction
    def configure(self, name, *, core, config, privacy=None, spec=None, context=None, profile=None):
        item = self.inspect(name)
        if runtime.alive(item.get('runtime', {})):
            raise ValueError('stop the service before reconfiguring')
        binding = self.catalog.binding(core, config)
        context = admit(validate_context(context)) if context is not None else admit(item['protocolContext'])
        check_binding(context, core, self.catalog)
        profile_binding = bind_profile(core, profile) if core in CORE_IDS else None
        if profile is not None and profile_binding is None: raise ValueError('UnknownNativeProfile')
        if spec is not None: self._spec(spec)
        if privacy is not None and privacy not in ('native', 'envelope'):
            raise ValueError('invalid privacy mode')
        replacement = json.loads(json.dumps(item))
        if spec is not None: replacement['spec'] = spec
        replacement['protocolContext'] = context
        replacement['coreBinding'] = binding
        replacement['profileBinding'] = profile_binding
        if privacy is not None: replacement['privacy'] = privacy
        replacement.pop('deploymentLock', None); replacement.pop('runtime', None)
        replacement['state'] = 'ready'
        self.services[name] = replacement
        try:
            # A previously locked deployment gets full replacement admission
            # before losing its original approved state. Unresolved drafts can
            # still be edited before their first explicit lock/apply.
            if item.get('deploymentLock'): self._material(name)
            self._save()
        except BaseException:
            self.services[name] = item
            raise
        return replacement

    @transaction
    def upgrade(self, name, *, core, config, privacy=None, spec=None, context=None, profile=None):
        """Atomically stage, lock and apply a stopped service replacement.

        This commits registry intent only; it never builds, installs, activates,
        or starts a Core. A failed admission or apply restores the previous
        record and its lock byte-for-byte.
        """
        item = self.inspect(name)
        if runtime.alive(item.get('runtime', {})):
            raise ValueError('stop the service before upgrading')
        original_services = json.loads(json.dumps(self.services))
        original_registry = private_read(self.path)
        try:
            self.configure(name, core=core, config=config, privacy=privacy,
                           spec=spec, context=context, profile=profile)
            self.lock(name)
            return self.apply(name)
        except BaseException:
            self.services = original_services
            try:
                atomic_write(self.path, original_registry)
            except BaseException as restore_error:
                raise ValueError('UpgradeRollbackFailed') from restore_error
            raise

    def _material(self, name):
        item = self.inspect(name); binding = self.require_binding(name)
        check_binding(item['protocolContext'], binding['core'], self.catalog)
        current = self.catalog.binding(binding['core'], binding['config'])
        if current != binding:
            raise ValueError('Core binding drift; explicitly reconfigure')
        if runtime.executable_digest(self.catalog.inspect(binding['core'])['executable']) != binding['binaryDigest']:
            raise ValueError('Core binary drift; explicitly reconfigure')
        content = private_read(binding['config']['config_path'])
        config_hash = digest(content)
        try: native = strict_json(content)
        except ValueError: native = None
        context = item['protocolContext']
        profile_binding = self.require_profile_binding(name)
        selected_profile = validate_profile_realization(profile_binding, native, context)
        if selected_profile['realization']['launcher'] == 'native-files':
            runtime.validate_native_file_config(self.catalog.root, native)

        if isinstance(native,dict) and 'role' in native and context['role'] not in ('all',native['role']):
            raise ValueError('native role realization differs from S6P1')
        if isinstance(native,dict) and context['identity'].get('id') is not None:
            role = native.get('role')
            native_id = native.get(role,{}).get('id') if isinstance(native.get(role),dict) else native.get('id')
            if native_id != context['identity']['id']: raise ValueError('native identity realization differs from S6P1')
        native_materials = native_material_paths(profile_binding, native)
        extra = {'nativeMaterials': native_materials, 'nativeMaterialDigests': {key:digest(private_read(path,limit=16384)) for key,path in native_materials.items()}}
        credited_path = item['spec'].get('credited_config')
        if credited_path:
            try:
                from .credited_attachment import validate_attachment, credited_core
            except ImportError:
                from credited_attachment import validate_attachment, credited_core
            if context['role'] not in ('client', 'all') or not isinstance(native, dict) or native.get('role') != 'client':
                raise ValueError('S6NA credited attachment requires a realized client service')
            extra['creditedAttachment'] = validate_attachment(
                credited_path, root=self.catalog.root,
                expected_core=credited_core(binding['core'], profile_binding))
        extra['runtimeMaterials'] = runtime.runtime_material_paths(self.catalog.root)
        extra['runtimeMaterialDigests'] = {key:runtime.runtime_material_digest(key,path) for key,path in extra['runtimeMaterials'].items()}
        fields = None
        components = {}
        if item['privacy'] == 'envelope':
            path = item['spec'].get('envelope_config')
            if not path:
                raise ValueError('envelope privacy requires --envelope-config')
            content = private_read(path)
            fields = runtime.parse_envelope(content)
            if item['spec'].get('metrics_path') and fields.get('metrics_path') != item['spec']['metrics_path']:
                raise ValueError('service metrics path must match envelope metrics_path')
            runtime.validate_envelope(fields)
            if fields.get('carrier') == 'webrtc' and (
                    profile_binding['core'] != 'nim' or selected_profile.get('transport') != 'webrtc'):
                raise ValueError('WebRTC S6EPE bridge requires the explicitly bound Nim/WebRTC Profile')
            runtime.validate_native_private(binding['config']['config_path'])
            extra['envelopeTlsMaterial'] = runtime.envelope_tls_material(fields)
            extra['envelopeTlsDigests'] = {key:digest(private_read(path,limit=16384)) for key,path in extra['envelopeTlsMaterial'].items()}
            extra['envelopeConfigDigest'] = digest(content)
            extra['envelopeBinaryDigest'] = digest(Path(runtime.executable(self.catalog.envelope_binary())).read_bytes())
        for component in ('gate', 'guard'):
            path = item['spec'].get(component + '_config')
            if path:
                value = strict_json(private_read(path))
                components[component] = value
                if item['privacy'] == 'envelope' and component == 'gate':
                    import ipaddress
                    if not ipaddress.ip_address(value.get('listen_host','0.0.0.0')).is_loopback:
                        raise ValueError('envelope invariant: Gate listener must be private behind EPE')
                if component == 'gate' and value.get('enabled') is not True:
                    raise ValueError('explicit Gate composition requires enabled: true')
                extra[component + 'ConfigDigest'] = digest(private_read(path))
                extra[component + 'BinaryDigest'] = digest(Path(runtime.executable(self.catalog.component_binary(component))).read_bytes())
        try:
            from .service_composition import validate_composition, broker_realization, component_material_paths
        except ImportError:
            from service_composition import validate_composition, broker_realization, component_material_paths
        component_materials = {key:path for component,value in components.items() for key,path in component_material_paths(component,value).items()}
        extra['componentMaterials'] = component_materials
        extra['componentMaterialDigests'] = {key:digest(private_read(path,limit=16384)) for key,path in component_materials.items()}
        realized = set(components)
        if item['privacy'] == 'envelope': realized.add('s6epe')
        admit_realization(context, native_role=native.get('role') if isinstance(native,dict) else None, components=realized)
        extra['brokerRealization'] = broker_realization(context,native=native,gate=components.get('gate'))
        extra['composition'] = validate_composition(privacy=item['privacy'], envelope=fields, gate=components.get('gate'), guard=components.get('guard'))
        return {'contextDigest':context_digest(item['protocolContext']), 'name': name, 'spec': item['spec'], 'privacy': item['privacy'], 'binding': binding, 'profileBinding': profile_binding, 'nativeConfigDigest': config_hash, **extra}

    def _component_limit_inputs(self, name):
        item = self.inspect(name)
        inputs = {}
        gate_path = item['spec'].get('gate_config')
        if gate_path:
            inputs['gate'] = strict_json(private_read(gate_path))
        guard_path = item['spec'].get('guard_config')
        if guard_path:
            inputs['guard'] = strict_json(private_read(guard_path))
        credited = item['spec'].get('credited_config')
        if credited:
            inputs['credited'] = strict_json(private_read(credited, limit=16384))
        if item['privacy'] == 'envelope':
            inputs['envelope'] = runtime.parse_envelope(private_read(item['spec']['envelope_config']))
        return inputs

    @transaction
    def lock(self, name):
        item = self.inspect(name)
        if runtime.alive(item.get('runtime', {})):
            raise ValueError('stop service before locking')
        material = self._material(name)
        resolution = LimitResolver().resolve(validate_profile_binding(self.require_profile_binding(name)), item['spec'].get('limits')).to_dict()
        components = LimitResolver().resolve_components(self._component_limit_inputs(name),
            host=HostBudget.from_dict(resolution['host_budget']),
            process_fds=resolution['effective_limits']['process_fds'])
        item['deploymentLock'] = {'schema': 'shadow6.deployment-lock.v2', 'limitResolution': resolution, 'componentLimits': components, 'digest': digest(encoded(material)), 'coreBinding': self.require_binding(name), 'profileBinding': self.require_profile_binding(name), 'contextDigest':context_digest(item['protocolContext'])}
        item['state'] = 'locked'; self._save(); return item['deploymentLock']

    @transaction
    def apply(self, name):
        item = self.inspect(name)
        if not item.get('deploymentLock'):
            self.lock(name)
        resolution = item['deploymentLock'].get('limitResolution')
        if resolution is None: raise ValueError('LegacyLimitsLock: explicitly stop and relock')
        LimitResolver().validate(resolution, validate_profile_binding(self.require_profile_binding(name)), item['spec'].get('limits'), check_host=True)
        component_resolution = item['deploymentLock'].get('componentLimits')
        if component_resolution is None:
            if self._component_limit_inputs(name):
                raise ValueError('LegacyComponentLimitsLock: explicitly stop and relock')
        else:
            try:
                LimitResolver().validate_components(component_resolution, self._component_limit_inputs(name),
                    host=HostBudget.from_dict(resolution['host_budget']),
                    process_fds=resolution['effective_limits']['process_fds'])
            except ValueError as error:
                # A post-lock config edit can make its limits malformed before
                # the material digest comparison below. Report that as locked
                # deployment drift while preserving the admission detail.
                raise ValueError('deployment drift; locked component limits no longer validate: ' + str(error)) from error
        if item['deploymentLock']['digest'] != digest(encoded(self._material(name))):
            raise ValueError('deployment drift; explicitly reconfigure and apply')
        if not runtime.alive(item.get('runtime', {})):
            item['state'] = 'applied'
        self._save(); return item

    @transaction
    def launch_plan(self, name):
        """Export the same approved component graph used by strong/native runners."""
        item = self.apply(name)
        binding = self.require_binding(name)
        material = self._material(name)
        if digest(encoded(material)) != item['deploymentLock']['digest']:
            raise ValueError('deployment drift while preparing launch plan')
        binary = runtime.executable(self.catalog.inspect(binding['core'])['executable'])
        plan = {'limitResolution': item['deploymentLock']['limitResolution'], 'componentLimits': item['deploymentLock']['componentLimits'], 'root': str(self.catalog.root), 'core': binding['core'], 'profileBinding': self.require_profile_binding(name), 'binary': binary,
                'config': binding['config']['config_path'], 'launchAdapter':self.catalog.inspect(binding['core']).get('launchAdapter','native-config'), 'ttl': item['spec'].get('ttl', 3600),
                'protocolContext':item['protocolContext'], 'contextDigest':material['contextDigest'], 'lockDigest':item['deploymentLock']['digest']}
        if material.get('creditedAttachment'):
            plan['creditedAttachment'] = material['creditedAttachment']
            plan['creditedConfig'] = material['creditedAttachment']['configPath']
            plan['creditedKey'] = material['creditedAttachment']['keyPath']
        if item['privacy'] == 'envelope':
            plan.update(envelopeConfig=item['spec']['envelope_config'], envelopeBinary=str(self.catalog.envelope_binary()))
        if item['privacy'] == 'envelope': plan.update(material['envelopeTlsMaterial'])
        for component in ('gate', 'guard'):
            if item['spec'].get(component + '_config'):
                plan[component + 'Config'] = item['spec'][component + '_config']
                plan[component + 'Binary'] = str(self.catalog.component_binary(component))
        plan['runtimeMaterials'] = material['runtimeMaterials']
        plan['componentMaterials'] = material['componentMaterials']
        plan['nativeMaterials'] = material['nativeMaterials']
        plan['launchDigests'] = {'binary':binding['binaryDigest'], 'config':material['nativeConfigDigest']}
        plan['launchDigests']['componentLimits'] = digest(encoded(item['deploymentLock']['componentLimits']))
        for component in ('envelope','gate','guard'):
            if component + 'Config' in plan:
                plan['launchDigests'][component + 'Config'] = material[component + 'ConfigDigest']
                plan['launchDigests'][component + 'Binary'] = material[component + 'BinaryDigest']
        if material.get('creditedAttachment'):
            plan['launchDigests']['creditedConfig'] = material['creditedAttachment']['configDigest']
            plan['launchDigests']['creditedKey'] = material['creditedAttachment']['keyDigest']
        plan['launchDigests'].update(material.get('envelopeTlsDigests',{}))
        plan['launchDigests'].update({'nativeMaterial:' + key:value for key,value in material['nativeMaterialDigests'].items()})
        plan['launchDigests'].update({'runtimeMaterial:' + key:value for key,value in material['runtimeMaterialDigests'].items()})
        plan['launchDigests'].update({'componentMaterial:' + key:value for key,value in material['componentMaterialDigests'].items()})
        path = self.path.parent / (hashlib.sha256(name.encode()).hexdigest() + '.runtime.json')
        atomic_write(path, encoded(plan))
        return path, plan

    @transaction
    def run(self, name):
        if not self.inspect(name).get('deploymentLock'):
            raise ValueError('DeploymentLock required; explicitly lock/apply before run')
        item = self.apply(name); binding = self.require_binding(name)
        admit(item['protocolContext'], role=None if item['protocolContext']['role'] == 'all' else item['protocolContext']['role'])
        if runtime.alive(item.get('runtime', {})):
            existing = self.status(name)
            if existing['runtime']['readiness'] == 'unavailable':
                raise ValueError('runtime health unavailable; explicitly restart')
            return existing
        material = self._material(name)
        if digest(encoded(material)) != item['deploymentLock']['digest']:
            raise ValueError('deployment drift; explicitly reconfigure and apply')
        binary = runtime.executable(self.catalog.inspect(binding['core'])['executable'])
        path, plan = self.launch_plan(name)
        process = runtime.start(path)
        item['runtime'] = {**process, 'state': 'running', 'core': binding['core'], 'profileBinding': self.require_profile_binding(name), 'lockDigest': item['deploymentLock']['digest'],
                           'endpoint': None, 'privacy': item['privacy'],
                           'startedAt': int(time.time()), 'expiresAt': int(time.time()) + plan['ttl']}
        item['state'] = 'running'
        try:
            self._save()
        except Exception:
            runtime.stop(item['runtime']); raise
        return self.status(name)

    @transaction
    def status(self, name):
        item = self.inspect(name)
        if item.get('runtime', {}).get('state') == 'running' and not runtime.alive(item['runtime']):
            terminal = 'exited' if int(time.time()) >= item['runtime'].get('expiresAt', 0) else 'failed'
            result_path = self.path.parent / (hashlib.sha256(name.encode()).hexdigest() + '.runtime.json.result')
            try:
                outcome = strict_json(private_read(result_path))
                expected = {'schema':'shadow6.runtime-result.v1', 'pid':item['runtime']['pid'],
                            'processIdentity':item['runtime']['processIdentity'], 'lockDigest':item['runtime']['lockDigest'],
                            'profileBinding':item.get('profileBinding'), 'state':'exited', 'reason':'application-record-drained'}
                if outcome == expected: terminal = 'exited'
            except (ValueError, OSError): pass
            item['runtime']['state'] = terminal; item['state'] = terminal; self._save()
        result = json.loads(json.dumps(item))
        try:
            runtime.observe(result, self.path.parent / (hashlib.sha256(name.encode()).hexdigest() + '.runtime.json'))
        except (ValueError, OSError, KeyError, TypeError):
            result.pop('runtimeObservation', None)
            if result.get('runtime'):
                result['runtime'].update(endpoint=None, readiness='unavailable')
            result['runtimeDiagnostic'] = 'RuntimeObservationInvalid'
        process = result.get('runtime')
        if process and process.get('state') == 'running':
            try:
                lock = result.get('deploymentLock')
                binding = result.get('coreBinding')
                valid = (lock is not None and lock.get('schema') == 'shadow6.deployment-lock.v2'
                         and process.get('lockDigest') == lock.get('digest')
                         and process.get('core') == binding.get('core')
                         and lock.get('coreBinding') == binding
                         and process.get('profileBinding') == result.get('profileBinding')
                         and lock.get('profileBinding') == result.get('profileBinding')
                         and lock.get('contextDigest') == context_digest(result['protocolContext'])
                         and digest(encoded(self._material(name))) == lock.get('digest'))
            except (ValueError, OSError, KeyError, TypeError):
                valid = False
            if not valid:
                process.update(endpoint=None, readiness='unavailable')
                result.pop('runtimeObservation', None)
                result['state'] = 'stale'
                item['state'] = 'stale'; self._save()
            elif process.get('readiness') not in ('listener-ready', 'control-ready', 'application-ready') or not result.get('runtimeObservation'):
                result['state'] = 'degraded'
                result['runtimeDiagnostic'] = result.get('runtimeDiagnostic', 'RuntimeReadinessUnavailable')
                item['state'] = 'degraded'; self._save()
            elif item['state'] in ('degraded', 'stale'):
                result['state'] = 'running'; item['state'] = 'running'; self._save()
        try:
            from privacy_envelope import read_metrics
        except ImportError:
            import sys
            sys.path.insert(0, str(self.catalog.root / 'Control-Center'))
            from privacy_envelope import read_metrics
        result['privacyTelemetry'] = read_metrics(item['spec'].get('metrics_path'))
        return result

    @transaction
    def compliance_snapshot(self, name):
        """Capture lock material and observed status under one registry transaction."""
        item = self.inspect(name)
        try:
            before = self._material(name)
        except (ValueError, OSError, KeyError):
            before = None
        status = self.status(name)
        try:
            after = self._material(name)
        except (ValueError, OSError, KeyError):
            after = None
        if before is None or after is None or encoded(before) != encoded(after):
            before = None
        return json.loads(json.dumps(item)), status, before

    @transaction
    def connection_inputs(self, name):
        item = self.inspect(name)
        if item['state'] == 'stale':
            raise ValueError('deployment drift; explicitly stop and reconfigure/relock')
        if item['state'] not in ('running', 'degraded') or not runtime.alive(item.get('runtime', {})):
            raise ValueError('service is not running')
        self.apply(name)
        item = self.status(name)
        if item['state'] == 'stale':
            raise ValueError('deployment drift; explicitly stop and reconfigure/relock')
        if item['state'] not in ('running', 'degraded') or not runtime.alive(item.get('runtime', {})):
            raise ValueError('service is not running')
        material = self._material(name)
        if digest(encoded(material)) != item['deploymentLock']['digest']:
            raise ValueError('deployment drift; explicitly reconfigure and apply')
        return item, material

    @transaction
    def credited_attachment(self, name):
        """Return lock-checked S6NA companion material for a ready client."""
        self.connect(name, role='client')
        item = self.inspect(name)
        material = self._material(name)
        attachment = material.get('creditedAttachment')
        if attachment is None:
            raise ValueError('Named Service has no S6NA credited attachment')
        if digest(encoded(material)) != item['deploymentLock']['digest']:
            raise ValueError('deployment drift; explicitly reconfigure and apply')
        return item, attachment

    @transaction
    def webrtc_signal_endpoint(self, name):
        """Expose only the lock-bound local S6EPE Name Service handoff fields."""
        item = self.inspect(name)
        if item.get('state') == 'stale' or not item.get('deploymentLock'):
            raise ValueError('locked Named Service required for WebRTC signalling')
        material = self._material(name)
        if digest(encoded(material)) != item['deploymentLock']['digest']:
            raise ValueError('deployment drift; explicitly reconfigure and apply')
        profile = self.require_profile_binding(name)
        if (profile.get('core') != 'nim' or profile.get('profile') != 'nim-webrtc'):
            raise ValueError('capability unavailable: S6EPE signalling requires Nim/WebRTC Profile')
        config_path = item.get('spec', {}).get('envelope_config')
        if not config_path:
            raise ValueError('Named Service has no S6EPE configuration')
        fields = runtime.parse_envelope(private_read(config_path))
        if fields.get('carrier') != 'webrtc' or not {'signal_path', 'signal_id'} <= set(fields):
            raise ValueError('Named Service has no WebRTC Name Service bridge')
        return {'schema':'shadow6.webrtc-signal-endpoint.v1',
            'path':fields['signal_path'], 'sessionPrefix':fields['signal_id'],
            'core':'nim', 'profile':profile['profile'],
            'lockDigest':item['deploymentLock']['digest'],
            'protocol':'S6SG1', 'transport':'owner-only-unix-stream'}

    @transaction
    def connect(self, name, *, core=None, role=None, adapter=None):
        item, _material = self.connection_inputs(name)
        if item.get('privacy') == 'envelope':
            fields = runtime.parse_envelope(private_read(item['spec']['envelope_config']))
            if fields.get('carrier') == 'webrtc' and (item.get('runtimeObservation') or {}).get('transportReadiness') != 'ready':
                raise ValueError('WebRTC transport has no active authenticated Named Service session')
        if item['runtime'].get('readiness') not in ('listener-ready', 'application-ready') or not item.get('runtimeObservation'):
            # Check a requested native role against the locked realization first;
            # readiness failure must not hide a binding conflict.
            if role is not None and item['protocolContext']['role'] == 'all':
                data = private_read(item['coreBinding']['config']['config_path'])
                try: native = strict_json(data)
                except ValueError as error: raise ValueError('capability unavailable: named deployment role cannot be verified') from error
                if not isinstance(native,dict) or native.get('role') != role:
                    raise ValueError('requested role differs from locked native realization')
            raise ValueError('service runtime readiness is unavailable; connect requires an observed listener or native ready event')
        return resolve_connection(service=name, registry=self, catalog=self.catalog,
                                  core=core, role=role, adapter=adapter)

    @transaction
    def stop(self, name):
        item = self.inspect(name); runtime.stop(item.get('runtime', {}))
        if item.get('runtime'):
            item['runtime'].update(state='stopped',endpoint=None,readiness='unavailable')
        item['state'] = 'stopped'; self._save(); return item

    @transaction
    def restart(self, name):
        # Verify the approved replacement before terminating a healthy group.
        self.apply(name)
        self.stop(name); return self.run(name)

    @transaction
    def remove(self, name):
        self.stop(name); self.services.pop(name); self._save()
        path = self.path.parent / (hashlib.sha256(name.encode()).hexdigest() + '.runtime.json')
        observed = Path(str(path) + '.observed')
        if observed.exists():
            private_read(observed); observed.unlink()
        result = Path(str(path) + '.result')
        if result.exists():
            private_read(result); result.unlink()
        if path.exists():
            private_read(path); path.unlink()
        return {'removed': name}

    @transaction
    def list(self):
        return [self.status(k) for k in sorted(self.services)]

    @transaction
    def inspect(self, name):
        if name not in self.services:
            raise ValueError('unknown named service')
        return self.services[name]

    @transaction
    def require_binding(self, name):
        binding = self.inspect(name).get('coreBinding')
        if not isinstance(binding, dict) or not binding.get('core'):
            raise ValueError('service has unresolved Core binding')
        return binding

    @transaction
    def require_profile_binding(self, name):
        item = self.inspect(name)
        binding = item.get('profileBinding')
        if binding is None:
            raise ValueError('ProfileBinding required; explicitly stop and service configure with --core/--profile, then relock/apply')
        validate_profile_binding(binding, core=self.require_binding(name)['core'])
        return binding

    @transaction
    def doctor(self, name):
        """Inspect the same binding, lock and observations used by run/connect."""
        item = self.inspect(name)
        findings = []
        material = None
        selected = None
        try:
            selected = validate_profile_binding(item.get('profileBinding'), core=self.require_binding(name)['core'])
        except ValueError:
            findings.append('ProfileBindingMissingOrDrifted')
        try:
            material = self._material(name)
        except (ValueError, OSError, KeyError, TypeError):
            findings.append('DeploymentMaterialUnavailableOrDrifted')
        lock = item.get('deploymentLock')
        valid_lock = bool(material and lock and lock.get('digest') == digest(encoded(material))
                          and lock.get('profileBinding') == item.get('profileBinding'))
        if not valid_lock: findings.append('DeploymentLockMissingOrDrifted')
        if lock and selected:
            try:
                LimitResolver().validate(lock.get('limitResolution'), selected, item['spec'].get('limits'), check_host=True)
            except (ValueError, TypeError, KeyError) as error:
                findings.append(str(error).split(':', 1)[0])
        feature_valid = False
        try:
            binding = self.require_binding(name)
            report = runtime.feature_report(self.catalog.inspect(binding['core'])['executable'])
            from feature_contract import validate_feature_report
            validate_feature_report(report, 'shadow6-' + binding['core'])
            if selected is None or selected['applicationBoundary'] not in report['application_boundaries']:
                raise ValueError('Profile feature boundary mismatch')
            feature_valid = True
        except (ValueError, OSError, KeyError, TypeError):
            findings.append('InstalledProfileFeatureReportUnavailableOrMismatch')
        current = self.status(name)
        if current.get('runtime') and current['state'] != 'running':
            findings.append('RuntimeNotReady:' + current['state'])
        return {'schema':'shadow6.named-service-doctor.v1', 'service':name,
                'limitResolution':(lock or {}).get('limitResolution'),
                'currentHostBudget':HostBudget.capture().to_dict(),
                'core':(item.get('coreBinding') or {}).get('core'),
                'profileBinding':item.get('profileBinding'), 'state':current['state'],
                'materialValid':material is not None, 'lockValid':valid_lock,
                'featureReportValid':feature_valid, 'findings':sorted(set(findings)),
                'healthy':not findings, 'runtime':current.get('runtime'),
                'runtimeObservation':current.get('runtimeObservation'),
                'hint':'Use explicit stop, upgrade/reconfigure, lock/apply and run; run never builds or changes Profile.'}
