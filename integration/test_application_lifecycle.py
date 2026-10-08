"""Real Web gateway -> canonical config -> native trio -> Python/C FD handoff.

No mocked dispatcher, process or application traffic. Reuse an existing Go/KCP
artifact; the all-Profile WAN/capture gates remain in Test Lab and Named tests.
"""
import asyncio
import ctypes
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),*[str(ROOT/name) for name in ('Deployment','Security-Assistants','Infrastructure-Assistants','Auto-Orchestrator','Plugin-System','Crosed','Slot-System','Extension-System','Application-Layer','Public6','Package-Manager','Migration','Online-Repository','Gate','Service-Init','CLI','Control-Center','Virtual-Adapter','Detector','integration','Test-Lab')]]
from aiohttp.test_utils import TestClient, TestServer
from shadow6_control import http_app
from web_gateway import gateway_app
from fd_gateway import FDGateway
from Deployment.service_registry import ServiceRegistry
from Deployment.core_catalog import CoreCatalog
from Deployment.service_storage import atomic_write, strict_json
from libshadow6 import Shadow6, RegistryControl, ConnectionError
from local_configs import generate_configs
from stack_test import EchoTarget, free_port
from application_game import game_workload


class ApplicationLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='shadow6-app-e2e-')
        self.addCleanup(self.temp.cleanup)
        self.directory=Path(self.temp.name)
        self.previous={key:os.environ.get(key) for key in ('SHADOW6_SERVICE_REGISTRY','SHADOW6_CONTROL_SOCKET','SHADOW6_CONTROL_TOKEN_FILE')}
        os.environ['SHADOW6_SERVICE_REGISTRY']=str(self.directory/'services.json')
        self.addCleanup(self.restore)
        self.registry=ServiceRegistry()
        self.target=EchoTarget();self.addCleanup(self.target.close)
        target_port=self.target.start()
        configs=self.directory/'configs'
        generate_configs(configs,target_port,free_port(),'shadow6-go')
        self.documents={role:strict_json((configs/f'it-shadow6-go-{role}.json').read_bytes()) for role in ('broker','agent','client')}
        self.backend=TestServer(http_app('b'*32,allow_mutations=True));await self.backend.start_server()
        self.addAsyncCleanup(self.backend.close)
        self.web=TestClient(TestServer(gateway_app('b'*32,'p'*32,backend_port=self.backend.port)))
        await self.web.start_server();self.addAsyncCleanup(self.web.close)
        self.origin=str(self.web.make_url('/')).rstrip('/')
        pair=await self.web.post('/gateway/pair',json={'code':'p'*32},headers={'Origin':self.origin})
        self.assertEqual(pair.status,200)
        csrf=(await pair.json())['csrf']
        self.headers={'Origin':self.origin,'X-Shadow6-CSRF':csrf,
                      'Cookie':'shadow6_loopback_session='+pair.cookies['shadow6_loopback_session'].value}
        self.addAsyncCleanup(self.stop_services)

    def restore(self):
        for key,value in self.previous.items():
            if value is None:os.environ.pop(key,None)
            else:os.environ[key]=value

    async def stop_services(self):
        for role in ('client','agent','broker'):
            try:await asyncio.to_thread(self.registry.stop,'e2e/'+role)
            except (ValueError,OSError):pass

    async def rpc(self,method,params=None,*,ok=True):
        response=await self.web.post('/v1/rpc',json={'method':method,'params':params or {}},headers=self.headers)
        raw=await response.read();value=strict_json(raw)
        self.assertEqual(value.get('ok'),ok,raw.decode())
        return value['result'] if ok else value['error']

    async def save_apply(self,role,*,expected=None,document=None):
        name='e2e/'+role
        params={'name':name,'core':'go','profile':'go-kcp','role':role,
                'document':json.dumps(document or self.documents[role]),'expected_digest':expected}
        reviewed=await self.rpc('service.config_review',params)
        private=self.documents[role][role]['private_key']
        self.assertNotIn(private,json.dumps(reviewed))
        saved=await self.rpc('service.config_save',{**params,'confirmed':True,'expected_review_digest':reviewed['expected_review_digest']})
        plan_params={'name':name,'core':'go','profile':'go-kcp'}
        plan=await self.rpc('service.config_plan',plan_params)
        self.assertTrue(plan['valid'],plan)
        apply_params={**plan_params,'confirmed':True,'expected_plan_digest':plan['expected_plan_digest'],
                      'expected_material_digest':plan['materialDigest'],'expected_lock_digest':plan['expected_lock_digest']}
        applied=await self.rpc('service.config_apply',apply_params)
        # Identical browser-saved material keeps its lock, so applying it again
        # is idempotent. A request reviewed against a changed lock must fail.
        if applied['deploymentLock']['digest']==plan['expected_lock_digest']:
            repeated=await self.rpc('service.config_apply',apply_params)
            self.assertEqual(repeated['deploymentLock']['digest'],plan['expected_lock_digest'])
        else:
            error=await self.rpc('service.config_apply',apply_params,ok=False)
            self.assertEqual(error['code'],'ReviewedLockChanged')
        return saved

    async def test_already_applied_configuration_keeps_lock(self):
        first=await self.save_apply('client')
        initial=await self.rpc('service.status',{'name':'e2e/client'})
        second=await self.save_apply('client',expected=first['digest'])
        current=await self.rpc('service.status',{'name':'e2e/client'})
        self.assertEqual(first['digest'],second['digest'])
        self.assertEqual(initial['deploymentLock']['digest'],current['deploymentLock']['digest'])
        document=json.loads(json.dumps(self.documents['client']))
        document['client']['broker_addrs']=[f'ws://127.0.0.1:{free_port()}/ws']
        await self.save_apply('client',expected=second['digest'],document=document)
        changed=await self.rpc('service.status',{'name':'e2e/client'})
        self.assertNotEqual(current['deploymentLock']['digest'],changed['deploymentLock']['digest'])

    async def browser_config(self):
        # CI explicitly provides Chromium; local dependency-free runs still
        # exercise the real HTTP/native lifecycle below.
        if os.environ.get('SHADOW6_BROWSER_TEST')!='1':return
        from playwright.async_api import async_playwright
        runtime=await async_playwright().start();self.addAsyncCleanup(runtime.stop)
        browser=await runtime.chromium.launch();self.addAsyncCleanup(browser.close)
        context=await browser.new_context()
        cookie=self.headers['Cookie'].split('=',1)[1]
        await context.add_cookies([{'name':'shadow6_loopback_session','value':cookie,'url':self.origin,'httpOnly':True,'sameSite':'Strict'}])
        page=await context.new_page();errors=[]
        page.on('pageerror',lambda error:errors.append(str(error)))
        await page.goto(self.origin+'/#services')
        await page.locator('#config-core option[value="go"]').wait_for(state='attached')
        await page.locator('#operator-service').fill('e2e/client')
        await page.locator('#config-core').select_option('go')
        await page.locator('#config-profile').select_option('go-kcp')
        await page.locator('#config-role').select_option('client')
        await page.get_by_label('client / private_key',exact=True).wait_for()
        metadata=await self.rpc('core.config_form',{'core':'go','profile':'go-kcp','role':'client'})
        async def fill(template,provided,schema,prefix=''):
            for key,value in template.items():
                label=prefix+' / '+key if prefix else key
                actual=provided.get(key,value)
                field_schema=schema.get('properties',{}).get(key,{})
                if isinstance(value,dict):await fill(value,actual,field_schema,label)
                elif isinstance(value,list):
                    for index,_ in enumerate(value):
                        await page.get_by_label(label+' / '+str(index),exact=True).fill(str(actual[index]))
                elif type(value) is bool:await page.get_by_label(label,exact=True).set_checked(actual)
                else:
                    await page.get_by_label(label,exact=True).fill(str(actual))
                    if field_schema.get('writeOnly'):
                        await page.get_by_label('Confirm replacement: '+label,exact=True).fill(str(actual))
        await fill(metadata['template'],self.documents['client'],metadata['inputSchema'])
        await page.get_by_role('button',name='Validate & review draft',exact=True).click()
        dialog=page.get_by_role('dialog');await dialog.wait_for()
        await dialog.get_by_role('button',name='Confirm / 确认',exact=True).click()
        await page.get_by_role('button',name='Replace secret / 替换秘密').first.wait_for()
        private=self.documents['client']['client']['private_key']
        self.assertNotIn(private,await page.locator('body').inner_text())
        await page.get_by_role('button',name='Plan & apply saved material',exact=True).click()
        await dialog.wait_for();await dialog.get_by_role('button',name='Confirm / 确认',exact=True).click()
        await page.get_by_role('status').filter(has_text='Reviewed configuration applied.').wait_for()
        self.assertEqual(errors,[])

    async def test_real_config_lifecycle_peer_fd_python_and_c_abi(self):
        metadata=await self.rpc('core.config_form',{'core':'go','profile':'go-kcp','role':'client'})
        self.assertTrue(metadata['inputSchema']['properties']['client']['properties']['private_key']['writeOnly'])
        await self.browser_config()
        saved={}
        for role in ('broker','agent','client'):
            inspected=await self.rpc('service.config_inspect',{'name':'e2e/'+role})
            saved[role]=await self.save_apply(role,expected=inspected['digest'])
            current=await self.rpc('service.status',{'name':'e2e/'+role})
            await self.rpc('service.run',{'name':'e2e/'+role,'confirmed':True,'expected_lock_digest':current['deploymentLock']['digest']})
        deadline=time.monotonic()+30
        while True:
            current=await self.rpc('service.status',{'name':'e2e/client'})
            if current.get('runtime',{}).get('readiness')=='application-ready':break
            self.assertLess(time.monotonic(),deadline,current)
            await asyncio.sleep(.1)
        facade=Shadow6(control=RegistryControl(self.registry));self.addCleanup(facade.close)
        peer=facade.peer('e2e/client')
        def workload():
            try:
                handle=peer.reconnect(timeout=10)
                report=game_workload(handle,ticks=12)
                self.assertTrue(report['complete'],report)
                self.assertFalse(peer.status()['migrationSupported'])
                peer.disconnect();self.assertEqual(peer.status()['state'],'closed')
            finally:peer.close()
        await asyncio.to_thread(workload)
        async def restart_ready():
            for role in ('broker','agent','client'):
                current=await self.rpc('service.status',{'name':'e2e/'+role})
                await self.rpc('service.restart',{'name':'e2e/'+role,'confirmed':True,'expected_lock_digest':current['deploymentLock']['digest']})
            deadline=time.monotonic()+30
            while True:
                current=await self.rpc('service.status',{'name':'e2e/client'})
                if current.get('runtime',{}).get('readiness')=='application-ready':return
                self.assertLess(time.monotonic(),deadline,current)
                await asyncio.sleep(.1)
        await restart_ready()
        socket_dir=self.directory/'fd';socket_dir.mkdir(mode=0o700)
        self.gateway=await FDGateway(socket_dir/'control.sock','b'*32,allow_mutations=True).start()
        self.addAsyncCleanup(self.gateway.close)
        token=socket_dir/'token';atomic_write(token,b'b'*32)
        os.environ['SHADOW6_CONTROL_SOCKET']=str(self.gateway.path)
        os.environ['SHADOW6_CONTROL_TOKEN_FILE']=str(token)
        await asyncio.to_thread(workload)
        await restart_ready()
        library=ROOT/'libshadow6/native/libshadow6.so'
        self.assertTrue(library.is_file(),'CI must compile only the small application SDK before this gate')
        def native_abi():
            lib=ctypes.CDLL(str(library))
            class Error(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('code',ctypes.c_char*96)]
            lib.s6_connection_open.argtypes=[ctypes.c_uint32,ctypes.c_char_p,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(Error)]
            lib.s6_connection_fd.argtypes=[ctypes.c_void_p];lib.s6_connection_fd.restype=ctypes.c_int
            lib.s6_connection_dup_fd.argtypes=[ctypes.c_void_p];lib.s6_connection_dup_fd.restype=ctypes.c_int
            lib.s6_connection_destroy.argtypes=[ctypes.c_void_p]
            handle=ctypes.c_void_p();error=Error()
            self.assertEqual(lib.s6_connection_open(1,b'e2e/client',ctypes.byref(handle),ctypes.byref(error)),0,error.code)
            duplicate=-1
            try:
                fd=lib.s6_connection_fd(handle);self.assertFalse(os.get_inheritable(fd))
                duplicate=lib.s6_connection_dup_fd(handle);self.assertGreaterEqual(duplicate,0)
                os.write(fd,b'C-native-fd');self.assertEqual(os.read(fd,11),b'C-native-fd')
                lib.s6_connection_destroy(handle);handle=ctypes.c_void_p()
                os.write(duplicate,b'owned-duplicate');self.assertEqual(os.read(duplicate,15),b'owned-duplicate')
            finally:
                if handle:lib.s6_connection_destroy(handle)
                if duplicate>=0:os.close(duplicate)
        await asyncio.to_thread(native_abi)
        # TOCTOU: edits to a reviewed content-addressed material fail closed.
        path=Path(saved['client']['native_config']);original=path.read_bytes()
        atomic_write(path,original+b'\n')
        stale=await self.rpc('service.status',{'name':'e2e/client'})
        self.assertEqual(stale['state'],'stale')
        atomic_write(path,original)
        current=await self.rpc('service.status',{'name':'e2e/client'})
        await self.rpc('service.stop',{'name':'e2e/client','confirmed':True,'expected_lock_digest':current['deploymentLock']['digest']})
        doc=json.loads(json.dumps(self.documents['client']));doc['client']['on_success']=''
        doc['client']['broker_addrs']=[f'ws://127.0.0.1:{free_port()}/ws']
        updated=await self.save_apply('client',expected=saved['client']['digest'],document=doc)
        for role in ('client','agent','broker'):
            current=await self.rpc('service.status',{'name':'e2e/'+role})
            await self.rpc('service.remove',{'name':'e2e/'+role,'confirmed':True,'expected_lock_digest':current['deploymentLock']['digest']})
        reclaimed=await self.rpc('service.config_reclaim',{'name':'e2e/client','confirmed':True,'expected_digest':updated['digest'],'discard_draft':True})
        self.assertTrue(reclaimed['activeMaterialsPreserved']);self.assertTrue(reclaimed['draftDiscarded'])
        self.assertFalse((await self.rpc('service.config_inspect',{'name':'e2e/client'}))['exists'])
        self.assertEqual((await self.rpc('service.list'))['services'],[])


if __name__=='__main__':unittest.main()
