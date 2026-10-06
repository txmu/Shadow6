import time
import unittest
from unittest import mock

from Deployment import session_handles
from Deployment.service_registry import ServiceRegistry, digest, encoded


class FakeSocket:
    def __init__(self):
        self.timeout = 30
    def gettimeout(self):
        return self.timeout
    def settimeout(self, value):
        self.timeout = value


class FakeStream:
    def __init__(self, incoming=b'hello'):
        self.deadline = time.monotonic() + 300
        self.remaining = 16 * 1024 * 1024
        self.socket = FakeSocket()
        self.incoming = [incoming]
        self.sent = []
        self.closed = False
    def send(self, data):
        self.remaining -= len(data); self.sent.append(bytes(data))
    def receive(self, size):
        data = self.incoming.pop(0) if self.incoming else b''
        data = data[:size]; self.remaining -= len(data); return data
    def close(self):
        self.closed = True


class FakeMessage(FakeStream):
    max_record = 16
    eof = False
    write_closed = False
    def send_record(self, data):
        if len(data) > self.max_record: raise ValueError('OversizedApplicationRecord')
        self.send(data)
    def receive_record(self):
        data = self.incoming.pop(0) if self.incoming else b''
        self.remaining -= len(data)
        return data


class SessionHandleTests(unittest.TestCase):
    def tearDown(self):
        session_handles.sessions.close_all()

    def test_stream_handle_is_bounded_and_close_is_idempotent(self):
        manager = session_handles.SessionHandleManager(limit=2)
        stream = FakeStream(b'abc')
        with mock.patch.object(session_handles, 'open_local_session', return_value=stream):
            opened = manager.open('home/nas', 'sha256:lock', 'sha256:plan', {})
        self.assertEqual(opened['boundary'], 'stream')
        handle = opened['handle']
        self.assertEqual(manager.write(handle, b'xyz', 1000)['written'], 3)
        read = manager.read(handle, 3, 1000)
        self.assertEqual(read['data'], b'abc')
        self.assertFalse(read['eof'])
        self.assertTrue(manager.close(handle)['closed'])
        self.assertFalse(manager.close(handle)['closed'])
        self.assertTrue(stream.closed)

    def test_message_handle_preserves_one_record_and_requires_full_record_bound(self):
        manager = session_handles.SessionHandleManager()
        message = FakeMessage(b'record')
        with mock.patch.object(session_handles, 'LocalMessageSession', FakeMessage), \
             mock.patch.object(session_handles, 'open_local_session', return_value=message):
            opened = manager.open('home/nas', 'sha256:lock', 'sha256:plan', {})
        handle = opened['handle']
        self.assertTrue(opened['recordPreserving'])
        with self.assertRaisesRegex(ValueError, 'MessageReadBoundTooSmall'):
            manager.read(handle, 8, 1000)
        self.assertEqual(manager.read(handle, 16, 1000)['data'], b'record')
        manager.write(handle, b'one-record', 1000)
        self.assertEqual(message.sent, [b'one-record'])

    def test_expired_capacity_and_service_cleanup_are_fail_closed(self):
        manager = session_handles.SessionHandleManager(limit=1)
        first = FakeStream()
        with mock.patch.object(session_handles, 'open_local_session', return_value=first):
            opened = manager.open('home/nas', 'sha256:lock', 'sha256:plan', {})
        second = FakeStream()
        with mock.patch.object(session_handles, 'open_local_session', return_value=second):
            with self.assertRaisesRegex(ValueError, 'Capacity'):
                manager.open('home/other', 'sha256:lock', 'sha256:plan', {})
        self.assertTrue(second.closed)
        self.assertEqual(manager.close_service('home/nas'), 1)
        self.assertTrue(first.closed)
        with self.assertRaisesRegex(ValueError, 'ExpiredOrUnknown'):
            manager.read(opened['handle'], 1, 1000)

    def test_connect_execute_claims_connected_only_after_real_handle_open(self):
        material = {'nativeConfigDigest': 'sha256:x'}
        plan = {'capability': {'sessionLaunch': 'local-application-stream'}}
        plan_digest = digest(encoded(plan))
        class Dummy:
            def connection_inputs(self, name):
                return {'deploymentLock': {'digest': 'sha256:lock'}}, material
            def connect(self, name, **kwargs): return plan
            def status(self, name):
                return {'state':'running', 'runtimeObservation':{'schema':'observed'},
                        'runtime':{'readiness':'application-ready'}}
        opened = {'schema':'shadow6.application-session.v1','handle':'x'*43,'boundary':'stream'}
        with mock.patch.object(session_handles.sessions, 'open', return_value=opened) as attach:
            result = ServiceRegistry.connect_execute.__wrapped__(Dummy(), 'home/nas', confirmed=True,
                expected_plan_digest=plan_digest, expected_material_digest=digest(encoded(material)),
                expected_lock_digest='sha256:lock')
        self.assertEqual(result['sessionState'], 'connected')
        self.assertEqual(result['session'], opened)
        attach.assert_called_once()

    def test_connect_execute_never_fabricates_handle_for_listener_only_runtime(self):
        material = {'nativeConfigDigest': 'sha256:x'}
        plan = {'capability': {'sessionLaunch': 'unavailable'}}
        class Dummy:
            def connection_inputs(self, name):
                return {'deploymentLock': {'digest': 'sha256:lock'}}, material
            def connect(self, name, **kwargs): return plan
            def status(self, name):
                return {'state':'running', 'runtimeObservation':{'schema':'observed'},
                        'runtime':{'readiness':'listener-ready'}}
        with mock.patch.object(session_handles.sessions, 'open') as attach:
            result = ServiceRegistry.connect_execute.__wrapped__(Dummy(), 'home/nas', confirmed=True,
                expected_plan_digest=digest(encoded(plan)), expected_material_digest=digest(encoded(material)),
                expected_lock_digest='sha256:lock')
        self.assertEqual(result['sessionState'], 'transport-ready')
        self.assertNotIn('session', result)
        attach.assert_not_called()


if __name__ == '__main__':
    unittest.main()
