"""Bounded local Operator history and existing Test Lab report views."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time
import sys

for _candidate in (Path(__file__).parent.parent/'Deployment',
                   Path(__file__).parent.parent/'deployment',
                   Path(__file__).parent.parent/'share/shadow6/deployment'):
    if (_candidate/'service_storage.py').is_file(): sys.path.insert(0,str(_candidate)); break

_LOCK = threading.RLock()


def history_path():
    registry = Path(os.environ.get('SHADOW6_SERVICE_REGISTRY',Path.home()/'.config/shadow6/services.json'))
    return registry.parent/'operator-activity.json'


def activity_append(method,params,code):
    if os.environ.get('SHADOW6_ACTIVITY_ENABLED') != '1': return
    if not re.fullmatch(r'[a-z0-9._-]{1,128}',method): return
    name = params.get('name')
    if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}/[A-Za-z0-9][A-Za-z0-9._-]{0,63}',name): name = None
    from shadow6_security import secure_read, atomic_write, strict_json_loads
    path = history_path()
    with _LOCK:
        try:
            events = strict_json_loads(secure_read(path,131072,secret=True)) if path.exists() else []
            if not isinstance(events,list): raise ValueError('InvalidActivityHistory')
            events = events[-127:]+[{'timestamp':int(time.time()),'requestId':secrets.token_hex(16),
                                    'method':method,'service':name,'result':code}]
            atomic_write(path,json.dumps(events,separators=(',',':')).encode(),0o600)
        except (OSError,ValueError):
            # An observation failure must not turn a completed mutation into
            # an apparent failure that applications might repeat.
            return


def activity_read():
    from shadow6_security import secure_read, strict_json_loads
    path = history_path()
    if not path.exists(): return {'schema':'shadow6.operator-activity.v1','events':[]}
    events = strict_json_loads(secure_read(path,131072,secret=True))
    if not isinstance(events,list) or len(events)>128: raise ValueError('InvalidActivityHistory')
    fields = {'timestamp','requestId','method','service','result'}
    if any(not isinstance(event,dict) or set(event)!=fields for event in events):
        raise ValueError('InvalidActivityHistory')
    return {'schema':'shadow6.operator-activity.v1','events':events}


def lab_report():
    path = os.environ.get('SHADOW6_TESTLAB_REPORT')
    if not path:
        return {'schema':'shadow6.operator-lab-view.v1','available':False,'reason':'NoVerifiedReportAttached'}
    from shadow6_security import secure_read
    from service_storage import strict_json
    raw = secure_read(Path(path),16*1024*1024,secret=True)
    report = strict_json(raw,limit=16*1024*1024,allow_measurement_floats=True)
    fields = {'schema','runId','environment','inventory','profileAvailability','nativeCoreCoverage',
              'results','s6epeCompatibility','s6epeCoverage','limitations','preflight','notes'}
    if not isinstance(report,dict) or set(report)-fields or report.get('schema')!='shadow6.wan-pcap-test-report.v2':
        raise ValueError('InvalidTestLabReport')
    def rows(items):
        if not isinstance(items,list) or len(items)>1024: raise ValueError('InvalidTestLabRows')
        result=[]
        for item in items:
            if not isinstance(item,dict): raise ValueError('InvalidTestLabRow')
            result.append({key:item.get(key) for key in ('core','profile','scenario','status','networkKind','placement','carrier')}
                | {'correctness':(item.get('correctness') or {}).get('status'),
                   'capture':(item.get('capture') or {}).get('status'),
                   'metrics':item.get('metrics'),'applicationGame':item.get('applicationGame'),
                   'stages':{key:value.get('status') for key,value in (item.get('stages') or {}).items() if isinstance(value,dict)}})
        return result
    carriers=[]
    for item in report.get('s6epeCompatibility',[]):
        carriers.append({'core':item.get('core'),'profile':item.get('profile'),
                         'carrier':item.get('carrier'),'legal':item.get('legal'),
                         'status':item.get('status'),'results':rows(item.get('results',[]))})
    environment = report.get('environment') or {}
    inventory = report.get('inventory') or {}
    return {'schema':'shadow6.operator-lab-view.v1','available':True,
        'runId':report.get('runId'),'reportDigest':'sha256:'+hashlib.sha256(raw).hexdigest(),
        'sourceCommit':environment.get('sourceCommit'),'artifact':environment.get('artifact'),
        'inventoryStatus':inventory.get('status'),'networkMode':environment.get('networkMode'),
        'results':rows(report.get('results',[])),'s6epe':carriers,
        'limitations':report.get('limitations',[]),'authority':'existing-Test-Lab-report; no new execution or PASS inference'}
