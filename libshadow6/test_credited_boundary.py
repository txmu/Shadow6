"""Real loopback S6NA credit/record socket tests, without a native Core build."""
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from libshadow6 import Shadow6, CreditedPool
from libshadow6.credited_boundary import CreditedBoundary, record_pair

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'Network-Adapter'))
from shadow6_network import DatagramEndpoint, Limits


class CreditedBoundaryTests(unittest.TestCase):
    def test_record_pair_without_unix_family_preserves_records(self):
        # Windows exposes SOCK_SEQPACKET on some builds without AF_UNIX.
        compatible_socket = SimpleNamespace(**{key: value for key, value in vars(socket).items() if key != 'AF_UNIX'})
        with patch('libshadow6.credited_boundary.socket', compatible_socket):
            left, right, mode = record_pair()
        with left, right:
            self.assertEqual(mode, 'datagram')
            left.settimeout(1); right.settimeout(1)
            left.send(b'first'); left.send(b'second-record')
            self.assertEqual(right.recv(32), b'first')
            self.assertEqual(right.recv(32), b'second-record')
            right.send(b'reply')
            self.assertEqual(left.recv(32), b'reply')

    def test_stream_and_record_payload_credit_ownership_and_worker_cleanup(self):
        for kind in ('stream','message'):
            with self.subTest(kind=kind):
                left=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);left.bind(('127.0.0.1',0));left_port=left.getsockname()[1];left.close()
                right=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);right.bind(('127.0.0.1',0));right_port=right.getsockname()[1];right.close()
                limits=Limits(max_message=1024,max_inflight=2048,max_window=2,payload_bytes=128,window_frames=2)
                a=DatagramEndpoint('go',b'k'*32,('127.0.0.1',left_port),('127.0.0.1',right_port),side=0,limits=limits)
                b=DatagramEndpoint('go',b'k'*32,('127.0.0.1',right_port),('127.0.0.1',left_port),side=1,limits=limits)
                self.addCleanup(a.close);self.addCleanup(b.close)
                facade=object.__new__(Shadow6);facade._closed=False;facade._ensure_attachment_state()
                pool=CreditedPool(facade,a,close_when_idle=True)
                session=pool.open(0);boundary=CreditedBoundary(session,kind=kind,max_record=256,lifetime=2)
                stop=threading.Event();errors=[]
                def echo():
                    try:
                        while not stop.is_set():
                            completed,events=b.poll(.01)
                            for stream,data in completed:b.send_flow_controlled(stream,data)
                    except Exception as error:errors.append(error)
                task=threading.Thread(target=echo);task.start()
                try:
                    boundary.socket.settimeout(1)
                    for sequence in range(10):
                        payload=sequence.to_bytes(2,'big')+b'credit-record'
                        boundary.socket.sendall(payload)
                        self.assertEqual(boundary.socket.recv(256),payload)
                    self.assertEqual(boundary.error,None)
                    self.assertLessEqual(len(session._received),64)
                    duplicate=boundary.socket.dup();duplicate.close()
                finally:
                    boundary.close();stop.set();task.join(1)
                self.assertFalse(boundary.thread.is_alive());self.assertFalse(task.is_alive())
                self.assertTrue(session._closed);self.assertTrue(pool.closed);self.assertEqual(errors,[])

    @unittest.skipUnless(os.name=="posix","raw fd detach is POSIX; Windows uses socket.share")
    def test_transferred_descriptor_is_owned_and_closes_the_worker(self):
        # Real adapter/worker remains bounded when the fd lifetime is transferred.
        a=DatagramEndpoint('go',b'k'*32,('127.0.0.1',0),('127.0.0.1',9))
        facade=object.__new__(Shadow6);facade._closed=False;facade._ensure_attachment_state()
        session=CreditedPool(facade,a,close_when_idle=True).open(0)
        boundary=CreditedBoundary(session,kind='stream',max_record=1024,lifetime=1)
        fd=boundary.detach();self.assertFalse(os.get_inheritable(fd));os.close(fd)
        boundary.thread.join(1)
        self.assertFalse(boundary.thread.is_alive());self.assertTrue(session._closed)
