"""Application capability/ownership tests, not native transport evidence."""
import os
import socket
import threading
import unittest
from unittest.mock import patch
from libshadow6 import Shadow6, BoundaryDescriptor, ConnectionHandle, ConnectionError
from Deployment.profile_registry import profiles, bind_profile


class BoundaryTests(unittest.TestCase):
    def test_all_profiles_use_semantics_not_core_switches(self):
        for profile in profiles():
            plan = {'core':profile['core'], 'profileBinding':bind_profile(profile['core'],profile['id'])}
            boundary = BoundaryDescriptor.from_plan(plan)
            self.assertEqual(boundary.kind, profile['applicationBoundary']['kind'])
            if boundary.realization == 'localhost-udp-datagram-proxy':
                self.assertFalse(boundary.reliable)
                self.assertFalse(boundary.ordered)
                self.assertEqual(boundary.semantics, 'datagram')
            if boundary.realization == 'seqpacket-fd':
                self.assertIsNone(boundary.reliable)
                self.assertEqual(boundary.semantics, 'record')

    def facade(self):
        facade = object.__new__(Shadow6)
        facade._closed = False
        facade._ensure_attachment_state()
        return facade

    def test_duplicate_survives_handle_close_and_close_does_not_stop_service(self):
        a,b = socket.socketpair(); self.addCleanup(b.close)
        facade = self.facade(); facade._connections = set()
        attachment = type('Attachment', (), {'socket':a, 'close':lambda _self:a.close()})()
        descriptor = BoundaryDescriptor('shadow6.boundary-descriptor.v1','stream','test','stream',None,True,True,None)
        handle = ConnectionHandle(facade,'test',{'lockDigest':'locked'},attachment,descriptor)
        facade._connections.add(handle)
        duplicate = handle.dup_fd(); self.addCleanup(os.close,duplicate)
        self.assertFalse(os.get_inheritable(duplicate))
        handle.close(); handle.close()
        with self.assertRaises(ConnectionError): handle.fileno()
        os.write(duplicate,b'direct'); self.assertEqual(b.recv(6),b'direct')
        self.assertEqual(facade._connections,set())

    def test_cancel_and_admission_happen_before_attachment(self):
        facade = self.facade()
        cancelled = threading.Event(); cancelled.set()
        with patch('Deployment.connection_plan.open_local_session') as opening:
            with self.assertRaises(ConnectionError) as caught:
                facade.connect_handle('test', cancellation=cancelled)
            self.assertEqual(caught.exception.code,'ConnectionCancelled')
            facade._connections = set(range(64))
            with self.assertRaises(ConnectionError) as caught: facade.connect_handle('test')
            self.assertEqual(caught.exception.code,'ApplicationSessionCapacityReached')
            opening.assert_not_called()

    def test_effective_record_limit_cannot_be_widened_or_coerced(self):
        profile = next(p for p in profiles() if p['applicationBoundary']['kind']=='message')
        plan = {'core':profile['core'], 'profileBinding':bind_profile(profile['core'],profile['id']),
                'effectiveLimits':{'max_record':32}}
        self.assertEqual(BoundaryDescriptor.from_plan(plan).max_record,32)
        for limit in (True, 0, profile['limits']['max_record']+1):
            plan['effectiveLimits']['max_record'] = limit
            with self.assertRaises(ConnectionError): BoundaryDescriptor.from_plan(plan)

    def test_drift_while_waiting_fails_closed(self):
        facade = self.facade()
        plans = iter([{'lockDigest':'A','readiness':'listener-ready'},
                      {'lockDigest':'B','readiness':'application-ready'}])
        facade.connection_plan = lambda _name: next(plans)
        with self.assertRaises(ConnectionError) as caught: facade.connect_handle('test',timeout=1)
        self.assertEqual(caught.exception.code,'ReviewedLockChanged')

    def test_late_socket_attachment_after_timeout_is_closed(self):
        from libshadow6.pending import bounded
        import time
        released=threading.Event();opened=threading.Event();closed=threading.Event()
        class Attachment:
            def __init__(self):self.socket,self.peer=socket.socketpair()
            def close(self):self.socket.close();self.peer.close();closed.set()
        def opening():
            opened.set();released.wait(1);return Attachment()
        started=time.monotonic()
        with self.assertRaisesRegex(ConnectionError,'ConnectionTimedOut'):
            bounded(opening,deadline=started+.02,attachment=True)
        self.assertLess(time.monotonic()-started,.25)
        self.assertTrue(opened.is_set());released.set();self.assertTrue(closed.wait(1))
