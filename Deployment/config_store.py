"""Owner-only Named Service drafts. Browser callers never select host paths."""
import hashlib
import itertools
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
try:
    from .service_storage import private_read, strict_json, atomic_write
    from .profile_registry import bind_profile, validate_profile_realization
except ImportError:
    from service_storage import private_read, strict_json, atomic_write
    from profile_registry import bind_profile, validate_profile_realization

MAX_CONFIG = 65536
SECRET_KEYS = frozenset({'private_key','secret','shared_secret','auth_key','psk','password',
                        'key','key_material','tls_key','tls_key_pem','token','bearer_token','secret_key','encryption_key'})
FORBIDDEN_KEYS = frozenset({'on_success','command','shell','post_command','pre_command'})


def digest(raw): return 'sha256:'+hashlib.sha256(raw).hexdigest()


def secret_key(key):
    value = key.lower()
    return value in SECRET_KEYS or value.endswith(('_secret','_password','_private_key','_token'))


def view(document, old=None, path=''):
    """Redact secrets and return only semantic field-level changes."""
    redacted, changes = {}, []
    for key, value in document.items():
        field = path+'/'+key
        before = old.get(key) if isinstance(old,dict) else None
        if secret_key(key):
            redacted[key] = {'secret':True,'present':value is not None}
            if old is not None and before != value:
                changes.append({'field':field,'secret':True,'before':'redacted','after':'redacted'})
        elif isinstance(value,dict):
            nested, delta = view(value,before,field)
            redacted[key] = nested; changes.extend(delta)
        elif isinstance(value,list):
            # Arrays can contain credentials. Redact recursively rather than
            # reflecting native config collections as raw JSON.
            redacted[key] = [view(item)[0] if isinstance(item,dict) else item for item in value]
            if old is not None and before != value:
                changes.append({'field':field,'collectionChanged':True})
        else:
            redacted[key] = value
            if old is not None and before != value:
                changes.append({'field':field,'before':before,'after':value})
    if isinstance(old,dict):
        for key in old.keys()-document.keys():
            changes.append({'field':path+'/'+key,'removed':True,'secret':secret_key(key)})
    return redacted,changes


def merge_secrets(document, old):
    if not isinstance(document,dict): raise ValueError('InvalidManagedConfiguration')
    output = {}
    for key,value in document.items():
        before = old.get(key) if isinstance(old,dict) else None
        if key in FORBIDDEN_KEYS and value not in ('',None):
            raise ValueError('HostCommandConfigurationRejected')
        if secret_key(key) and value == {'unchanged':True}:
            if before is None: raise ValueError('SecretReplacementRequired')
            output[key] = before
        elif isinstance(value,dict): output[key] = merge_secrets(value,before)
        elif isinstance(value,list):
            output[key] = [merge_secrets(item, before[index] if isinstance(before,list) and index<len(before) else None)
                           if isinstance(item,dict) else item for index,item in enumerate(value)]
        else: output[key] = value
    return output


class ConfigStore:
    def __init__(self, registry):
        self.registry = registry
        self.root = registry.path.parent/'config'

    @staticmethod
    def directory(path):
        path.mkdir(mode=0o700, exist_ok=True)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('UnsafeManagedConfigurationDirectory')

    def path(self,name):
        try: from .service_registry import NAME, service_capacity
        except ImportError: from service_registry import NAME, service_capacity
        if not isinstance(name,str) or not NAME.fullmatch(name): raise ValueError('InvalidServiceName')
        self.directory(self.registry.path.parent)
        self.directory(self.root)
        parent = self.root/hashlib.sha256(name.encode()).hexdigest()
        if not parent.exists() and not parent.is_symlink():
            capacity = min(128,service_capacity())
            with os.scandir(self.root) as entries:
                if len(list(itertools.islice(entries,capacity))) >= capacity:
                    raise ValueError('ManagedConfigurationCapacity')
        self.directory(parent)
        return parent/'draft.json'

    def inspect(self,name):
        path = self.path(name)
        if not path.exists() and not path.is_symlink():
            return {'schema':'shadow6.managed-config.v1','name':name,'exists':False,'digest':None,'document':None}
        raw = private_read(path,limit=MAX_CONFIG)
        document = strict_json(raw,limit=MAX_CONFIG)
        redacted,_ = view(document)
        return {'schema':'shadow6.managed-config.v1','name':name,'exists':True,
                'digest':digest(raw),'document':redacted}

    def prepare(self,name,*,core,profile,document,expected_digest,role=None):
        path = self.path(name)
        old_raw = private_read(path,limit=MAX_CONFIG) if path.exists() or path.is_symlink() else None
        actual = digest(old_raw) if old_raw is not None else None
        if actual != expected_digest: raise ValueError('ReviewedConfigurationChanged')
        incoming = strict_json(document,limit=MAX_CONFIG)
        old = strict_json(old_raw,limit=MAX_CONFIG) if old_raw is not None else None
        merged = merge_secrets(incoming,old)
        if role is not None and merged.get('role') != role:
            raise ValueError('ConfigurationRoleMismatch')
        selected = validate_profile_realization(bind_profile(core,profile),merged)
        raw = json.dumps(merged,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
        if len(raw)>MAX_CONFIG: raise ValueError('ManagedConfigurationTooLarge')
        validation = 'authority-not-provided'
        if hasattr(self.registry,'catalog'):
            if selected['realization']['launcher'] == 'native-files':
                try: from .service_runtime import validate_native_file_config
                except ImportError: from service_runtime import validate_native_file_config
                validate_native_file_config(self.registry.catalog.root,merged)
                validation = 'normalized-native-authority'
            else:
                binary = self.registry.catalog.inspect(core)['executable']
                with tempfile.TemporaryDirectory(prefix='.shadow6-config-check-',dir=path.parent) as directory:
                    temporary = Path(directory)/'native.json'
                    atomic_write(temporary,raw,limit=MAX_CONFIG)
                    result = subprocess.run([binary,'--config',str(temporary),'--check-config'],
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
                    if result.returncode: raise ValueError('NativeConfigurationRejected')
                validation = 'native-check-config'
        redacted,delta = view(merged,old)
        return path,raw,{'schema':'shadow6.managed-config-review.v1','name':name,
            'core':core,'profile':profile,'previousDigest':actual,'digest':digest(raw),
            'document':redacted,'changes':delta,'saved':False,'applied':False,
            'nativeValidation':validation,
            'evidence':'strict portable JSON, Profile and existing native configuration authority; material planning follows save'}

    def review(self,name,**params): return self.prepare(name,**params)[2]

    def save(self,name,*,confirmed,expected_review_digest,**params):
        if confirmed is not True: raise ValueError('ExplicitHumanConfirmationRequired')
        path,raw,review = self.prepare(name,**params)
        if digest(json.dumps(review,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()) != expected_review_digest:
            raise ValueError('ReviewedConfigurationChanged')
        material = path.parent/('material-'+hashlib.sha256(raw).hexdigest()+'.json')
        if not material.exists() and not material.is_symlink():
            if len(list(path.parent.glob('material-*.json'))) >= 16:
                raise ValueError('ManagedConfigurationCapacity')
            atomic_write(material,raw,limit=MAX_CONFIG)
        elif private_read(material,limit=MAX_CONFIG) != raw:
            raise ValueError('ManagedConfigurationMaterialChanged')
        atomic_write(path,raw)
        return {**review,'saved':True,'native_config':str(material)}

    def reclaim(self,name,*,confirmed,expected_digest):
        if confirmed is not True: raise ValueError('ExplicitHumanConfirmationRequired')
        current = self.inspect(name)
        if current['digest'] != expected_digest: raise ValueError('ReviewedConfigurationChanged')
        path = self.path(name)
        protected = {str(path.parent/('material-'+current['digest'].removeprefix('sha256:')+'.json'))} if current['digest'] else set()
        for item in getattr(self.registry,'services',{}).values():
            config = (item.get('coreBinding') or {}).get('config') or {}
            if config.get('config_path'): protected.add(str(Path(config['config_path']).absolute()))
            for key,value in (item.get('spec') or {}).items():
                if key.endswith('_config') and isinstance(value,str): protected.add(str(Path(value).absolute()))
        removed = 0
        with os.scandir(path.parent) as entries:
            candidates = [Path(entry.path) for entry in itertools.islice(entries,64)]
        for candidate in candidates:
            match = re.fullmatch(r'material-([0-9a-f]{64})\.json',candidate.name)
            if not match or str(candidate.absolute()) in protected: continue
            raw = private_read(candidate,limit=MAX_CONFIG)
            if hashlib.sha256(raw).hexdigest()!=match[1]: raise ValueError('ManagedConfigurationMaterialChanged')
            candidate.unlink();removed += 1
        return {'schema':'shadow6.managed-config-reclaim.v1','name':name,
                'removedSnapshots':removed,'activeMaterialsPreserved':True}
