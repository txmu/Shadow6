"""Exercise the actual install-prebuilt target from outside the source cwd."""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

class InstalledImports(unittest.TestCase):
    def test_staged_entrypoints_package_imports_and_repeat_install(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-installed-') as directory:
            stage=Path(directory)
            flags=set(re.findall(r'BUILD_[A-Z_]+',(ROOT/'Makefile').read_text()+(ROOT/'config.mk').read_text() if (ROOT/'config.mk').exists() else (ROOT/'Makefile').read_text()))
            command=['make','install-prebuilt','PREFIX=/usr/local','DESTDIR='+directory]+[f'{flag}=0' for flag in sorted(flags)]
            env={k:v for k,v in os.environ.items() if k not in {'PYTHONPATH','SHADOW6_ROOT'}}
            installed=stage/'usr/local'
            for _ in range(2):
                result=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stderr[-4000:])
            for args in (['abi','catalog'],['connect','--help'],['core','list'],['core','profiles'],['setup','--help'],['doctor','--help']):
                result=subprocess.run([sys.executable,str(installed/'bin/shadow6'),*args],cwd=stage,env=env,capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stderr)
            package=next(installed.glob('lib/python*/site-packages/Deployment')) if list(installed.glob('lib/python*/site-packages/Deployment')) else next(installed.glob('lib/python*/dist-packages/Deployment'))
            code='''import sys,json
sys.path.insert(0,sys.argv[1])
from libshadow6 import Shadow6
from libshadow6.webrtc_signal import WebrtcClientReflector
from Deployment import encode_control
from Deployment.credited_attachment import credited_core
from Deployment.service_registry import ServiceRegistry
from Deployment.core_catalog import CoreCatalog
from Deployment.profile_registry import profiles, select_profile, profile_digest
from Deployment.profile_availability import inspect_profile, installed_profiles
from Deployment.application_attachment import NativeRecordAttachment
from Deployment.supervisor_contract import capabilities
from Deployment.system_operations import operation_request
assert len(profiles()) == 13
assert callable(WebrtcClientReflector)
assert credited_core('go', {'profile':'go-kcp'}) == 'go'
assert capabilities('launchd')['systemOperationInterface'] == 'available'
assert operation_request(backend='systemd', operation='status', service='home/nas', plan_path='/private/launch.json', lock_digest='sha256:'+'a'*64, now=1000)['expiresAt'] == 1060
assert profile_digest(select_profile('gleam', 'gleam-micro-mux')).startswith('sha256:')
from Deployment.protocol_context import minimal_context
from Deployment.connection_plan import resolve_connection
catalog=CoreCatalog()
assert catalog.root == __import__('pathlib').Path(sys.argv[2])
assert resolve_connection(context=minimal_context('go'),catalog=catalog,core='go')['core']=='go'
print('installed imports passed')
'''
            result=subprocess.run([sys.executable,'-I','-c',code,str(package.parent),str(installed/'share/shadow6/tree')],cwd=stage,env=env,capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
