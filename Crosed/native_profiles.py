"""Single source of truth for the built-in Core/Profile contracts."""
from __future__ import annotations
import hashlib, json

CORE_IDS = ('go','rust','gleam','ada','nim','pony','zig','d','cpp','idris','hare','carp')
_STREAM = {'kind':'stream','mode':'localhost-tcp-proxy','roles':['client'],'full_duplex':True,'ordered':True,'reliable':True,'backpressure':'tcp-flow-control','half_close':True,'listener_ownership':'core','endpoint_discovery':'stdout-ready-jsonl-v1','listener_ready':'bound-and-listening','local_connection_limit':64,'shutdown':'close-active-flows','eof':'propagate-half-close','connection_mapping':'one-local-connection-per-native-flow'}
_MESSAGE = {'kind':'message','mode':'seqpacket-fd','roles':['client'],'max_record':1048576,'message_preserving':True,'backpressure':'native-window','producer_send_success':'kernel-queue-only','endpoint_discovery':'stdout-ready-jsonl-v1','oversize':'discard-record-continue','transient_error':'retry-eagain-eintr','hard_error':'fail-closed','eof':'empty-record-drain','close':'drain-accepted-then-stop'}
_MUX = {'kind':'message','mode':'localhost-udp-datagram-proxy','roles':['client'],'message_preserving':True,'ordered':False,'reliable':False,'delivery':'best-effort','backpressure':'udp-datagram-loss','max_record':65465,'listener_ownership':'core','endpoint_discovery':'stdout-ready-jsonl-v1','listener_ready':'bound-and-listening','local_peer_limit':1,'oversize':'discard-datagram'}

def _profile(core, ident, boundary, artifact=None, *, primary=False, launcher='native-config', transport='tcp'):
    return {'id':ident,'profile':ident,'core':core,'primary':primary,
            'artifact':artifact or 'Core-' + core.title() + '/shadow6-' + core,
            'applicationBoundary':dict(boundary),
            'attachment':{'mode':boundary['mode'],'kind':boundary['kind'],'transport':'tcp' if boundary['kind']=='stream' else 'unix-seqpacket'},
            'limits':{'max_record':1048576 if boundary['kind']=='message' else 16777216,'local_connection_limit':64,
                      'session_seconds':300,'session_bytes':16777216,'process_fds':256},
            'configTransport':transport,
            'realization':{'launcher':launcher,'roles':['broker','agent','client']},
            'nativeMaterials':{}}

_DATA = [
 ('go','go-kcp',_STREAM,True,'kcp'), ('rust','rust-quic',_STREAM,True,'quic'),
 ('gleam','gleam-secure-stream',_STREAM,True,'secure-stream'),
 ('gleam','gleam-micro-mux',_MUX,False,'micro-mux'),
 ('ada','ada-cell',_MESSAGE,True,'cell'), ('nim','nim-datachannel',_STREAM,True,'datachannel'),
 ('pony','pony-udp',_MESSAGE,True,'udp'), ('zig','zig-udp',_MESSAGE,True,'udp'),
 ('d','d-stream',_STREAM,True,'stream'), ('cpp','cpp-sctp',_STREAM,True,'sctp'),
 ('idris','idris-fixed-peer',_MESSAGE,True,'fixed-peer'),
 ('hare','hare-fixed-route',_MESSAGE,True,'fixed-route'), ('carp','carp-fixed-route',_MESSAGE,True,'fixed-route')]
_PROFILES = [_profile(c, p, b, primary=pri, transport=t) for c,p,b,pri,t in _DATA]

def profiles(core=None):
    return [dict(p) for p in _PROFILES if core is None or p['core'] == core]
def select_profile(core, profile=None):
    found = [p for p in _PROFILES if p['core']==core and (profile is None or p['id']==profile or p['profile']==profile)]
    if not found: raise ValueError('UnknownNativeProfile')
    return dict(found[0])
def profile_digest(profile):
    return 'sha256:' + hashlib.sha256(json.dumps(profile,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def bind_profile(core, profile=None):
    p=select_profile(core, profile)
    return {'schema':'shadow6.profile-binding.v1','core':core,'profile':p['id'],'digest':profile_digest(p)}
def validate_profile_binding(binding, core=None, current=True):
    if not isinstance(binding,dict) or set(binding) != {'schema','core','profile','digest'} or binding.get('schema') != 'shadow6.profile-binding.v1': raise ValueError('invalid ProfileBinding')
    if core is not None and binding['core'] != core: raise ValueError('ProfileBinding Core mismatch')
    p=select_profile(binding['core'],binding['profile'])
    if binding['digest'] != profile_digest(p): raise ValueError('ProfileBinding digest mismatch')
    return p
def application_boundaries(core):
    if core == 'gleam': return [dict(_STREAM), dict(_MUX)]
    selected=[{k:v for k,v in p['applicationBoundary'].items() if k != 'transport'} for p in _PROFILES if p['core']==core]
    return selected or [select_profile(core)['applicationBoundary']]
def topology_profile(core, _global=None): return select_profile(core)
def transport_map(configuration=False): return {'shadow6-'+p['core']:p['configTransport'] for p in _PROFILES}
def artifact_map(): return {('shadow6-'+p['core']):p['artifact'] for p in _PROFILES if p['primary']}
def native_material_paths(binding, native): return {}
def validate_profile_realization(binding, native, context=None):
    p=validate_profile_binding(binding)
    if not isinstance(native,dict): raise ValueError('invalid native realization')
    return p
def validate_policy(value):
    if value is None: return {'mode':'safe','operator_overrides':{}}
    if not isinstance(value,dict) or set(value)-{'mode','operator_overrides'}: raise ValueError('invalid limits policy')
    if value.get('mode','safe') not in {'safe','elastic','custom'}: raise ValueError('invalid limits mode')
    overrides=value.get('operator_overrides',{})
    if not isinstance(overrides,dict) or any(type(v) is not int or v <= 0 for v in overrides.values()): raise ValueError('invalid limit override')
    return {'mode':value.get('mode','safe'),'operator_overrides':dict(overrides)}
