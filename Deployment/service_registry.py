"""Private, transactional named services with explicit Core bindings."""
from __future__ import annotations
import functools
import hashlib
import json
import os
import platform
import re
import time
import threading
from pathlib import Path
try:
    from .core_catalog import CoreCatalog
    from .service_storage import private_read, strict_json, private_directory, atomic_write
    from . import service_runtime as runtime
    from .protocol_context import validate_context, minimal_context, check_binding, context_digest, admit, admit_realization
    from .connection_plan import resolve_connection
except ImportError:
    from core_catalog import CoreCatalog
    from service_storage import private_read, strict_json, private_directory, atomic_write
    import service_runtime as runtime
    from protocol_context import validate_context, minimal_context, check_binding, context_digest, admit, admit_realization
    from connection_plan import resolve_connection

NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
SCHEMA = 'shadow6.service-registry.v2'


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
            data = strict_json(private_read(self.path))
        except FileNotFoundError:
            self.services = {}; return
        if not isinstance(data, dict) or set(data) != {'schema', 'services'} or data['schema'] not in (SCHEMA, 'shadow6.service-registry.v1') or not isinstance(data['services'], dict) or len(data['services']) > 128:
            raise ValueError('invalid service registry')
        allowed = {'name', 'protocolContext', 'spec', 'privacy', 'privacyTelemetry', 'coreBinding', 'state', 'deploymentLock', 'runtime'}
        for name, item in data['services'].items():
            if not NAME.fullmatch(name) or not isinstance(item, dict) or set(item) - allowed or item.get('name') != name:
                raise ValueError('invalid named service record')
            if item.get('state') not in {'unresolved','ready','locked','applied','running','stopped','exited'}:
                raise ValueError('invalid service state')
            binding = item.get('coreBinding')
            if binding is not None:
                fields = {'core','version','binaryDigest','featureReportDigest','configSchemaVersion','config','configDigest'}
                if not isinstance(binding, dict) or set(binding) not in (fields,fields | {'descriptorDigest'}) or binding['core'] not in self.catalog._items:
                    raise ValueError('invalid Core binding')
                self.catalog.binding(binding['core'], binding['config'])
            lock = item.get('deploymentLock')
            if lock is not None and (not isinstance(lock, dict) or set(lock) not in ({'schema','digest','coreBinding'}, {'schema','digest','coreBinding','contextDigest'}) or lock['schema'] != 'shadow6.deployment-lock.v2'):
                raise ValueError('invalid deployment lock')
            process = item.get('runtime')
            if process is not None:
                fields = {'pid','processIdentity','readiness','state','core','lockDigest','endpoint','privacy','startedAt','expiresAt'}
                if not isinstance(process, dict) or set(process) != fields or type(process['pid']) is not int or process['pid'] <= 1 or not isinstance(process['processIdentity'], str) or not re.fullmatch(r'[0-9a-f-]{36}:[0-9]+', process['processIdentity']):
                    raise ValueError('invalid runtime identity; legacy simulated state needs explicit recreation')
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
        atomic_write(self.path, encoded({'schema': SCHEMA, 'services': self.services}) + b'\n')

    @staticmethod
    def _spec(spec):
        if not isinstance(spec, dict) or set(spec) - {'ttl', 'envelope_config', 'metrics_path', 'gate_config', 'guard_config'}:
            raise ValueError('unknown service specification field')
        if type(spec.get('ttl', 3600)) is not int or not 30 <= spec.get('ttl', 3600) <= 86400:
            raise ValueError('service ttl must be 30..86400 seconds')
        for key in ('envelope_config', 'metrics_path', 'gate_config', 'guard_config'):
            if key in spec and (not isinstance(spec[key], str) or not Path(spec[key]).is_absolute()):
                raise ValueError('service file references must be absolute paths')

    @transaction
    def init(self):
        self._save()
        return {'schema': 'shadow6.lifecycle.v1', 'stage': 'init', 'platform': platform.system(), 'statePath': str(self.path)}

    @transaction
    def create(self, name, *, core, config, spec=None, privacy='native', context=None):
        if not NAME.fullmatch(name) or name in self.services or len(self.services) >= 128:
            raise ValueError('service name must be unique namespace/name; maximum 128 services')
        spec = spec or {}; self._spec(spec)
        if privacy not in ('native', 'envelope'):
            raise ValueError('privacy must be native or envelope')
        context = admit(validate_context(context)) if context is not None else minimal_context(core)
        binding = None if core is None else self.catalog.binding(core, config or {})
        if binding: check_binding(context, core, self.catalog)
        item = {'name': name, 'protocolContext': context, 'spec': spec, 'privacy': privacy, 'coreBinding': binding,
                'state': 'unresolved' if binding is None else 'ready'}
        self.services[name] = item; self._save(); return item

    @transaction
    def configure(self, name, *, core, config, privacy=None, spec=None, context=None):
        item = self.inspect(name)
        if runtime.alive(item.get('runtime', {})):
            raise ValueError('stop the service before reconfiguring')
        binding = self.catalog.binding(core, config)
        context = admit(validate_context(context)) if context is not None else admit(item['protocolContext'])
        check_binding(context, core, self.catalog)
        item['protocolContext'] = context
        if privacy is not None and privacy not in ('native', 'envelope'):
            raise ValueError('invalid privacy mode')
        if spec is not None:
            self._spec(spec); item['spec'] = spec
        item['coreBinding'] = binding
        if privacy is not None:
            item['privacy'] = privacy
        item.pop('deploymentLock', None); item.pop('runtime', None)
        item['state'] = 'ready'; self._save(); return item

    def _material(self, name):
        item = self.inspect(name); binding = self.require_binding(name)
        check_binding(item['protocolContext'], binding['core'], self.catalog)
        current = self.catalog.binding(binding['core'], binding['config'])
        if current != binding:
            raise ValueError('Core binding drift; explicitly reconfigure')
        content = private_read(binding['config']['config_path'])
        config_hash = digest(content)
        try: native = strict_json(content)
        except ValueError: native = None
        context = item['protocolContext']
        if isinstance(native,dict) and 'role' in native and context['role'] not in ('all',native['role']):
            raise ValueError('native role realization differs from S6P1')
        if isinstance(native,dict) and context['identity'].get('id') is not None:
            role = native.get('role')
            native_id = native.get(role,{}).get('id') if isinstance(native.get(role),dict) else native.get('id')
            if native_id != context['identity']['id']: raise ValueError('native identity realization differs from S6P1')
        extra = {}
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
            from .service_composition import validate_composition, broker_realization
        except ImportError:
            from service_composition import validate_composition, broker_realization
        realized = set(components)
        if item['privacy'] == 'envelope': realized.add('s6epe')
        admit_realization(context, native_role=native.get('role') if isinstance(native,dict) else None, components=realized)
        extra['brokerRealization'] = broker_realization(context,native=native,gate=components.get('gate'))
        extra['composition'] = validate_composition(privacy=item['privacy'], envelope=fields, gate=components.get('gate'), guard=components.get('guard'))
        return {'contextDigest':context_digest(item['protocolContext']), 'name': name, 'spec': item['spec'], 'privacy': item['privacy'], 'binding': binding, 'nativeConfigDigest': config_hash, **extra}

    @transaction
    def lock(self, name):
        item = self.inspect(name)
        if runtime.alive(item.get('runtime', {})):
            raise ValueError('stop service before locking')
        material = self._material(name)
        item['deploymentLock'] = {'schema': 'shadow6.deployment-lock.v2', 'digest': digest(encoded(material)), 'coreBinding': self.require_binding(name), 'contextDigest':context_digest(item['protocolContext'])}
        item['state'] = 'locked'; self._save(); return item['deploymentLock']

    @transaction
    def apply(self, name):
        item = self.inspect(name)
        if not item.get('deploymentLock'):
            self.lock(name)
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
        plan = {'root': str(self.catalog.root), 'core': binding['core'], 'binary': binary,
                'config': binding['config']['config_path'], 'launchAdapter':self.catalog.inspect(binding['core']).get('launchAdapter','native-config'), 'ttl': item['spec'].get('ttl', 3600),
                'protocolContext':item['protocolContext'], 'contextDigest':material['contextDigest'], 'lockDigest':item['deploymentLock']['digest']}
        if item['privacy'] == 'envelope':
            plan.update(envelopeConfig=item['spec']['envelope_config'], envelopeBinary=str(self.catalog.envelope_binary()))
        if item['privacy'] == 'envelope': plan.update(material['envelopeTlsMaterial'])
        for component in ('gate', 'guard'):
            if item['spec'].get(component + '_config'):
                plan[component + 'Config'] = item['spec'][component + '_config']
                plan[component + 'Binary'] = str(self.catalog.component_binary(component))
        plan['launchDigests'] = {'binary':binding['binaryDigest'], 'config':material['nativeConfigDigest']}
        for component in ('envelope','gate','guard'):
            if component + 'Config' in plan:
                plan['launchDigests'][component + 'Config'] = material[component + 'ConfigDigest']
                plan['launchDigests'][component + 'Binary'] = material[component + 'BinaryDigest']
        plan['launchDigests'].update(material.get('envelopeTlsDigests',{}))
        path = self.path.parent / (hashlib.sha256(name.encode()).hexdigest() + '.runtime.json')
        atomic_write(path, encoded(plan))
        return path, plan

    @transaction
    def run(self, name):
        item = self.apply(name); binding = self.require_binding(name)
        admit(item['protocolContext'], role=None if item['protocolContext']['role'] == 'all' else item['protocolContext']['role'])
        if runtime.alive(item.get('runtime', {})):
            existing = self.status(name)
            if not existing.get('runtimeObservation') or existing['runtime']['readiness'] == 'unavailable':
                raise ValueError('runtime health unavailable; explicitly restart')
            return existing
        material = self._material(name)
        if digest(encoded(material)) != item['deploymentLock']['digest']:
            raise ValueError('deployment drift; explicitly reconfigure and apply')
        binary = runtime.executable(self.catalog.inspect(binding['core'])['executable'])
        path, plan = self.launch_plan(name)
        process = runtime.start(path)
        item['runtime'] = {**process, 'state': 'running', 'core': binding['core'], 'lockDigest': item['deploymentLock']['digest'],
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
            item['runtime']['state'] = 'exited'; item['state'] = 'exited'; self._save()
        result = json.loads(json.dumps(item))
        runtime.observe(result, self.path.parent / (hashlib.sha256(name.encode()).hexdigest() + '.runtime.json'))
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
        if item['state'] != 'running' or not runtime.alive(item.get('runtime', {})):
            raise ValueError('service is not running')
        self.apply(name)
        item = self.status(name)
        if item['state'] != 'running' or not runtime.alive(item.get('runtime', {})):
            raise ValueError('service is not running')
        material = self._material(name)
        if digest(encoded(material)) != item['deploymentLock']['digest']:
            raise ValueError('deployment drift; explicitly reconfigure and apply')
        return item, material

    @transaction
    def connect(self, name, *, core=None, role=None, adapter=None):
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
