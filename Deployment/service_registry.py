"""Private, transactional named services with explicit Core bindings."""
from __future__ import annotations
import functools
import hashlib
import json
import os
import platform
import re
import time
from pathlib import Path
try:
    from .core_catalog import CoreCatalog
    from .service_storage import private_read, strict_json, private_directory, atomic_write
    from . import service_runtime as runtime
except ImportError:
    from core_catalog import CoreCatalog
    from service_storage import private_read, strict_json, private_directory, atomic_write
    import service_runtime as runtime

NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
SCHEMA = 'shadow6.service-registry.v1'


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(value):
    return 'sha256:' + hashlib.sha256(value).hexdigest()


def transaction(method):
    @functools.wraps(method)
    def call(self, *args, **kwargs):
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
        self._load()

    def _load(self):
        try:
            data = strict_json(private_read(self.path))
        except FileNotFoundError:
            self.services = {}; return
        if not isinstance(data, dict) or set(data) != {'schema', 'services'} or data['schema'] != SCHEMA or not isinstance(data['services'], dict) or len(data['services']) > 128:
            raise ValueError('invalid service registry')
        allowed = {'name', 'spec', 'privacy', 'privacyTelemetry', 'coreBinding', 'state', 'deploymentLock', 'runtime'}
        for name, item in data['services'].items():
            if not NAME.fullmatch(name) or not isinstance(item, dict) or set(item) - allowed or item.get('name') != name:
                raise ValueError('invalid named service record')
            if item.get('state') not in {'unresolved','ready','locked','applied','running','stopped','exited'}:
                raise ValueError('invalid service state')
            binding = item.get('coreBinding')
            if binding is not None:
                fields = {'core','version','binaryDigest','featureReportDigest','configSchemaVersion','config','configDigest'}
                if not isinstance(binding, dict) or set(binding) != fields or binding['core'] not in self.catalog._items:
                    raise ValueError('invalid Core binding')
                self.catalog.binding(binding['core'], binding['config'])
            lock = item.get('deploymentLock')
            if lock is not None and (not isinstance(lock, dict) or set(lock) != {'schema','digest','coreBinding'} or lock['schema'] != 'shadow6.deployment-lock.v2'):
                raise ValueError('invalid deployment lock')
            process = item.get('runtime')
            if process is not None:
                fields = {'pid','processIdentity','readiness','state','core','lockDigest','endpoint','privacy','startedAt','expiresAt'}
                if not isinstance(process, dict) or set(process) != fields or type(process['pid']) is not int or process['pid'] <= 1 or not isinstance(process['processIdentity'], str) or not re.fullmatch(r'[0-9a-f-]{36}:[0-9]+', process['processIdentity']):
                    raise ValueError('invalid runtime identity; legacy simulated state needs explicit recreation')
                if any(type(process[k]) is not int for k in ('startedAt','expiresAt')):
                    raise ValueError('invalid runtime timestamps')
            self._spec(item.get('spec', {}))
            if item.get('privacy') not in ('native', 'envelope'):
                raise ValueError('invalid privacy mode')
        self.services = data['services']

    def _save(self):
        atomic_write(self.path, encoded({'schema': SCHEMA, 'services': self.services}) + b'\n')

    @staticmethod
    def _spec(spec):
        if not isinstance(spec, dict) or set(spec) - {'endpoint', 'ttl', 'envelope_config', 'metrics_path'}:
            raise ValueError('unknown service specification field')
        if type(spec.get('ttl', 3600)) is not int or not 30 <= spec.get('ttl', 3600) <= 86400:
            raise ValueError('service ttl must be 30..86400 seconds')
        endpoint = spec.get('endpoint', {'mode': 'private'})
        if not isinstance(endpoint, dict) or set(endpoint) - {'mode', 'address'} or endpoint.get('mode') != 'private':
            raise ValueError('service endpoint requires private mode')
        if 'address' in endpoint and (not isinstance(endpoint['address'], str) or len(endpoint['address']) > 256):
            raise ValueError('invalid endpoint address')
        for key in ('envelope_config', 'metrics_path'):
            if key in spec and (not isinstance(spec[key], str) or not Path(spec[key]).is_absolute()):
                raise ValueError('service file references must be absolute paths')

    @transaction
    def init(self):
        self._save()
        return {'schema': 'shadow6.lifecycle.v1', 'stage': 'init', 'platform': platform.system(), 'statePath': str(self.path)}

    @transaction
    def create(self, name, *, core, config, spec=None, privacy='native'):
        if not NAME.fullmatch(name) or name in self.services or len(self.services) >= 128:
            raise ValueError('service name must be unique namespace/name; maximum 128 services')
        spec = spec or {}; self._spec(spec)
        if privacy not in ('native', 'envelope'):
            raise ValueError('privacy must be native or envelope')
        binding = None if core is None else self.catalog.binding(core, config or {})
        item = {'name': name, 'spec': spec, 'privacy': privacy, 'coreBinding': binding,
                'state': 'unresolved' if binding is None else 'ready'}
        self.services[name] = item; self._save(); return item

    @transaction
    def configure(self, name, *, core, config, privacy=None, spec=None):
        item = self.inspect(name)
        if runtime.alive(item.get('runtime', {})):
            raise ValueError('stop the service before reconfiguring')
        binding = self.catalog.binding(core, config)
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
        current = self.catalog.binding(binding['core'], binding['config'])
        if current != binding:
            raise ValueError('Core binding drift; explicitly reconfigure')
        config_hash = digest(private_read(binding['config']['config_path']))
        extra = {}
        if item['privacy'] == 'envelope':
            path = item['spec'].get('envelope_config')
            if not path:
                raise ValueError('envelope privacy requires --envelope-config')
            content = private_read(path)
            fields = {}
            for line in content.decode('utf-8').splitlines():
                line = line.strip()
                if not line or line.startswith('#'): continue
                key, separator, value = line.partition('=')
                if not separator or key.strip() in fields:
                    raise ValueError('invalid envelope configuration fields')
                fields[key.strip()] = value.strip()
            if item['spec'].get('metrics_path') and fields.get('metrics_path') != item['spec']['metrics_path']:
                raise ValueError('service metrics path must match envelope metrics_path')
            extra['envelopeConfigDigest'] = digest(content)
            extra['envelopeBinaryDigest'] = digest(Path(runtime.executable(self.catalog.envelope_binary())).read_bytes())
        return {'name': name, 'spec': item['spec'], 'privacy': item['privacy'], 'binding': binding, 'nativeConfigDigest': config_hash, **extra}

    @transaction
    def lock(self, name):
        item = self.inspect(name)
        if runtime.alive(item.get('runtime', {})):
            raise ValueError('stop service before locking')
        material = self._material(name)
        item['deploymentLock'] = {'schema': 'shadow6.deployment-lock.v2', 'digest': digest(encoded(material)), 'coreBinding': self.require_binding(name)}
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
    def run(self, name):
        item = self.apply(name); binding = self.require_binding(name)
        if runtime.alive(item.get('runtime', {})):
            return self.status(name)
        binary = runtime.executable(self.catalog.inspect(binding['core'])['executable'])
        plan = {'root': str(self.catalog.root), 'core': binding['core'], 'binary': binary,
                'config': binding['config']['config_path'], 'ttl': item['spec'].get('ttl', 3600)}
        if item['privacy'] == 'envelope':
            plan.update(envelopeConfig=item['spec']['envelope_config'], envelopeBinary=str(self.catalog.envelope_binary()))
        path = self.path.parent / (hashlib.sha256(name.encode()).hexdigest() + '.runtime.json')
        atomic_write(path, encoded(plan))
        process = runtime.start(path)
        item['runtime'] = {**process, 'state': 'running', 'core': binding['core'], 'lockDigest': item['deploymentLock']['digest'],
                           'endpoint': item['spec'].get('endpoint', {'mode': 'private'}), 'privacy': item['privacy'],
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
        from privacy_envelope import read_metrics
        result = json.loads(json.dumps(item))
        result['privacyTelemetry'] = read_metrics(item['spec'].get('metrics_path'))
        return result

    @transaction
    def connect(self, name):
        item = self.status(name)
        if item['state'] != 'running' or not runtime.alive(item.get('runtime', {})):
            raise ValueError('service is not running')
        return {'service': name, 'core': self.require_binding(name)['core'], 'endpoint': item['runtime']['endpoint'], 'readiness': item['runtime']['readiness']}

    @transaction
    def stop(self, name):
        item = self.inspect(name); runtime.stop(item.get('runtime', {}))
        if item.get('runtime'):
            item['runtime']['state'] = 'stopped'
        item['state'] = 'stopped'; self._save(); return item

    @transaction
    def restart(self, name):
        self.stop(name); return self.run(name)

    @transaction
    def remove(self, name):
        self.stop(name); self.services.pop(name); self._save()
        path = self.path.parent / (hashlib.sha256(name.encode()).hexdigest() + '.runtime.json')
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
