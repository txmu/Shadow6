"""State and binding adversarial tests; real native paths are integration gates."""
import copy
import threading
import time
import unittest
from libshadow6 import PeerConnection, ConnectionError


class Handle:
    def __init__(self,plan):self._plan=copy.deepcopy(plan);self.closed=False
    def close(self):self.closed=True
    def status(self):return {'state':'running'}


class Facade:
    def __init__(self):
        self.plan={'core':'go','profileBinding':{'profile':'go-kcp'},'securityPolicyDigest':'policy',
                   'contextDigest':'context','lockDigest':'lock'}
        self.calls=[];self.fail_primary=False
    def connection_plan(self,name):return copy.deepcopy(self.plan)
    def connect_handle(self,name,**options):
        self.calls.append(name)
        if name=='home/primary' and self.fail_primary:raise ConnectionError('ConnectionRefused',retryable=True)
        return Handle(self.plan)


class PeerTests(unittest.TestCase):
    def test_explicit_fallback_bindings_reconnect_and_close(self):
        facade=Facade();facade.fail_primary=True
        peer=PeerConnection(facade,'home/primary',fallback_services=['home/fallback'])
        first=peer.connect();self.assertEqual(peer.selected_path,'home/fallback')
        self.assertFalse(peer.status()['migrationSupported'])
        second=peer.reconnect();self.assertTrue(first.closed)
        facade.plan['securityPolicyDigest']='changed'
        peer.disconnect()
        with self.assertRaisesRegex(ConnectionError,'PeerBindingChanged'):peer.connect()
        self.assertTrue(second.closed)

    def test_every_security_binding_mismatch_rejects_fallback(self):
        for field in ('core','profileBinding','securityPolicyDigest','contextDigest'):
            facade=Facade();facade.fail_primary=True
            original=facade.connection_plan
            def plan(name):
                value=original(name)
                if name.endswith('fallback'):value[field]='different'
                return value
            facade.connection_plan=plan
            with self.subTest(field=field),self.assertRaisesRegex(ConnectionError,'FallbackPolicyMismatch'):
                PeerConnection(facade,'home/primary',fallback_services=['home/fallback']).connect()
            self.assertEqual(facade.calls,['home/primary'])

    def test_cancel_disconnect_late_completion_cannot_publish_or_overwrite_closed(self):
        facade=Facade();entered=threading.Event();release=threading.Event();handles=[];errors=[]
        def opening(name,**options):
            entered.set();release.wait(1);handle=Handle(facade.plan);handles.append(handle);return handle
        facade.connect_handle=opening
        peer=PeerConnection(facade,'home/primary')
        def run():
            try:peer.connect()
            except ConnectionError as error:errors.append(error.code)
        task=threading.Thread(target=run);task.start();self.assertTrue(entered.wait(1))
        peer.disconnect();release.set();task.join(2)
        self.assertFalse(task.is_alive());self.assertEqual(errors,['ConnectionCancelled'])
        self.assertTrue(handles[0].closed);self.assertEqual(peer.status()['state'],'closed')

    def test_timeout_and_nonretryable_error_never_fallback(self):
        facade=Facade()
        def delayed(name,**options):time.sleep(.02);return Handle(facade.plan)
        facade.connect_handle=delayed
        with self.assertRaisesRegex(ConnectionError,'PeerConnectionTimeout'):
            PeerConnection(facade,'home/primary').connect(timeout=.005)
        facade=Facade()
        def rejected(*args,**kwargs):raise ConnectionError('ReviewedLockChanged')
        facade.connect_handle=rejected
        with self.assertRaisesRegex(ConnectionError,'ReviewedLockChanged'):
            PeerConnection(facade,'home/primary',fallback_services=['home/fallback']).connect()
        cancellation=threading.Event();cancellation.set()
        with self.assertRaisesRegex(ConnectionError,'ConnectionCancelled'):
            PeerConnection(facade,'home/primary').connect(cancellation=cancellation)

    def test_network_failure_is_degraded_and_requires_explicit_reconnect(self):
        facade=Facade();peer=PeerConnection(facade,'home/primary');handle=peer.connect()
        handle.status=lambda:{'state':'exited'}
        self.assertEqual(peer.status()['state'],'degraded')
        self.assertEqual(len(facade.calls),1)
        peer.reconnect();self.assertTrue(handle.closed);peer.close()
