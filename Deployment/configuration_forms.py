"""Operator forms derived from existing native realization authorities."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
try:
    from .profile_registry import select_profile, bind_profile, profile_digest
    from .config_store import secret_key
    from .service_storage import private_read, strict_json
except ImportError:
    from profile_registry import select_profile, bind_profile, profile_digest
    from config_store import secret_key
    from service_storage import private_read, strict_json

# This is configuration provider metadata, not a native data-plane switch.
PROVIDERS = {'cpp-sctp-tls13':'native-init-demo'}


def form(catalog, *, core, profile, role):
    selected = select_profile(core,profile)
    if role not in selected['roles']: raise ValueError('InvalidConfigurationRole')
    provider = PROVIDERS.get(profile, selected['realization']['launcher'])
    if provider == 'native-files':
        root = Path(catalog.root)
        candidates = [root/'CLI',Path(__file__).parent,Path(__file__).parent.parent/'CLI']
        for path in candidates:
            if (path/'native_config.py').is_file(): sys.path.insert(0,str(path)); break
        from native_config import configuration_fields
        fields = configuration_fields(core,role)
        template = {key:(4433 if key.endswith('_port') else 1000 if key=='iterations' else
                         '127.0.0.1' if key.endswith('_host') else '') for key in fields}
        template.update(core=core,role=role)
    elif provider == 'native-init-demo':
        descriptor = catalog.inspect(core)
        with tempfile.TemporaryDirectory(prefix='shadow6-config-form-') as directory:
            destination = Path(directory)/'native'
            # Fixed native configuration generation, never caller commands.
            result = subprocess.run([descriptor['executable'],'--init-demo',str(destination)],
                                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            if result.returncode: raise ValueError('ProfileUnavailable')
            template = strict_json(private_read(destination/(role+'.json'),limit=65536))
    else:
        try: from .native_realization import realize_native_node
        except ImportError: from native_realization import realize_native_node
        nodes = [{'name':name,'type':name,'engines':['shadow6-'+core]} for name in ('broker','agent','client')]
        node = next(item for item in nodes if item['type']==role)
        node.update(listen_host='127.0.0.1',listen_port=4433,target_agent='agent',target_port=22)
        template = realize_native_node(topo={'global':{'native_profile':profile,'stealth_mode':False},'nodes':nodes},
            node=node,core_engine='shadow6-'+core,broker_pub='',broker_priv='',
            agents_data=[{'id':'agent','pubkey':''}],
            clients_data=[{'id':'client','pubkey':'','allowed_agents':['agent']}],
            agent_keys={'agent':('','')},client_keys={'client':('','')},
            broker_url='ws://127.0.0.1:4433/ws',native_configs=None,sni='shadow6.local')
    def clean(value,key=''):
        if secret_key(key) or key.endswith(('pubkey','public_key')): return ''
        if isinstance(value,dict): return {name:clean(item,name) for name,item in value.items()}
        if isinstance(value,list): return [clean(item,key) for item in value]
        return value
    template = clean(template)
    def field_schema(value, key=''):
        if secret_key(key): return {'type':'string','writeOnly':True}
        if isinstance(value,dict):
            return {'type':'object','additionalProperties':False,
                    'required':list(value),'properties':{k:field_schema(v,k) for k,v in value.items()}}
        if isinstance(value,list):
            return {'type':'array','maxItems':256,**({'items':field_schema(value[0])} if value else {})}
        if type(value) is bool: return {'type':'boolean'}
        if type(value) is int:
            return {'type':'integer','minimum':1 if key.endswith('_port') else 0,
                    'maximum':65535 if key.endswith('_port') else 2**53-1}
        if value is None: return {'type':['string','null']}
        return {'type':'string','maxLength':65536}
    return {'schema':'shadow6.configuration-form.v1','profileBinding':bind_profile(core,profile),
            'role':role,'template':template,'inputSchema':field_schema(template),'contractDigest':profile_digest(selected),
            'provider':provider,'secretFieldsWriteOnly':True,
            'evidence':'existing normalized/native configuration realization; values require operator review'}
