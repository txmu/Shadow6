"""Bounded host-derived limit authority shared by deployment and runtime."""
from __future__ import annotations
import hashlib,json,os,resource
from dataclasses import dataclass
MAX=2**31-1
def integer(v,name='value'):
    if type(v) is not int or not 1 <= v <= MAX: raise ValueError('invalid '+name)
    return v
@dataclass(frozen=True)
class HostBudget:
    memory_bytes:int; fd_ceiling:int; cpu_units:int; platform:str='unknown'; memory_sources:tuple=(); fd_sources:tuple=(); cpu_sources:tuple=()
    @classmethod
    def capture(cls):
        memory=0
        try:
            with open('/proc/meminfo') as meminfo:
                for line in meminfo:
                    if line.startswith('MemTotal:'): memory=int(line.split()[1])*1024; break
        except OSError: pass
        memory=memory or 512*1024*1024
        try: fd=resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        except (OSError,ValueError): fd=256
        if fd==resource.RLIM_INFINITY: fd=1048576
        cpu=os.cpu_count() or 1
        return cls(max(1,memory),max(1,min(int(fd),MAX)),max(1,min(cpu,MAX)),os.name,('procfs',),('rlimit_nofile',),('cpu_count',))
    def to_dict(self): return {'memory_bytes':self.memory_bytes,'fd_ceiling':self.fd_ceiling,'cpu_units':self.cpu_units,'platform':self.platform,'memory_sources':list(self.memory_sources),'fd_sources':list(self.fd_sources),'cpu_sources':list(self.cpu_sources)}
    @classmethod
    def from_dict(cls,v): return cls(v['memory_bytes'],v['fd_ceiling'],v['cpu_units'],v.get('platform','unknown'),tuple(v.get('memory_sources',())),tuple(v.get('fd_sources',())),tuple(v.get('cpu_sources',())))
class LimitResolution(dict):
    def to_dict(self): return dict(self)
    @property
    def digest(self): return 'sha256:'+hashlib.sha256(json.dumps(self,sort_keys=True,separators=(',',':')).encode()).hexdigest()
class LimitResolver:
    def resolve(self,profile,policy=None):
        policy=validate_policy(policy); host=HostBudget.capture(); base=profile['limits']; hard={'max_record':16*1024*1024,'session_seconds':86400,'session_bytes':1024*1024*1024,'process_fds':min(65536,host.fd_ceiling)}
        safe={'max_record':min(base['max_record'],1048576),'session_seconds':300,'session_bytes':16*1024*1024,'process_fds':min(base['process_fds'],host.fd_ceiling)}
        rec={'max_record':min(hard['max_record'],max(safe['max_record'],host.memory_bytes//4096)),'session_seconds':3600,'session_bytes':min(hard['session_bytes'],host.memory_bytes//2),'process_fds':min(hard['process_fds'],host.fd_ceiling)}
        chosen=safe if policy['mode']=='safe' else rec
        if policy['mode']=='custom': chosen=dict(safe); chosen.update(policy['operator_overrides'])
        effective={k:min(integer(chosen.get(k,safe[k]),k),hard[k],host.fd_ceiling if k=='process_fds' else MAX) for k in hard}
        return LimitResolution({'schema':'shadow6.limit-resolution.v1','mode':policy['mode'],'host_budget':host.to_dict(),'safe_defaults':safe,'recommended_limits':rec,'operator_overrides':policy['operator_overrides'],'host_derived_ceiling':hard,'hard_protocol_limits':hard,'effective_limits':effective,'sources':{k:'safe_defaults' if policy['mode']=='safe' else 'recommended_limits' for k in effective},'enforced_by':{'process_fds':'supervisor','max_record':'application-boundary'}})
    def validate(self,resolution,profile,policy=None,check_host=False):
        if not isinstance(resolution,dict) or resolution.get('schema')!='shadow6.limit-resolution.v1': raise ValueError('invalid limit resolution')
        expected=self.resolve(profile,policy)
        for k,v in resolution.get('effective_limits',{}).items():
            if k not in expected['hard_protocol_limits'] or type(v) is not int or v<1 or v>expected['hard_protocol_limits'][k]: raise ValueError('LimitHardCapViolation:'+k)
        if check_host:
            current=HostBudget.capture(); locked=HostBudget.from_dict(resolution['host_budget'])
            if (current.memory_bytes < locked.memory_bytes or current.fd_ceiling < locked.fd_ceiling or current.cpu_units < locked.cpu_units):
                raise ValueError('HostBudgetDrift')
        return resolution
def validate_policy(value):
    if value is None:return {'mode':'safe','operator_overrides':{}}
    if not isinstance(value,dict) or value.get('mode','safe') not in {'safe','elastic','custom'}: raise ValueError('invalid limits policy')
    o=value.get('operator_overrides',{})
    if not isinstance(o,dict) or any(type(v) is not int or v<1 for v in o.values()): raise ValueError('invalid limit override')
    return {'mode':value.get('mode','safe'),'operator_overrides':o}
class _LR(LimitResolver): pass
