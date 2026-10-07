"""Actual Windows WSADuplicateSocket handle transfer; no emulated fd integers."""
import multiprocessing
import os
import socket
import unittest
from libshadow6.handle_transfer import WindowsHandleTransfer
from libshadow6 import ConnectionError


def recipient(pipe,credential,nonce):
    try:
        raw=pipe.recv_bytes()
        connection=WindowsHandleTransfer.receive(raw,credential=credential,nonce=nonce)
        try:
            connection.settimeout(5);connection.sendall(b'windows-handle')
            pipe.send(connection.recv(32))
            try:WindowsHandleTransfer.receive(raw,credential=credential,nonce=nonce)
            except ConnectionError as error:pipe.send(error.code)
            else:pipe.send('replay-accepted')
        finally:connection.close()
    finally:pipe.close()


class HandleTransferTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='nt','Windows kernel handle backend requires Windows CI')
    def test_same_user_process_transfer_payload_ownership_and_replay(self):
        context=multiprocessing.get_context('spawn')
        parent,child=context.Pipe();credential=b'k'*32;nonce=WindowsHandleTransfer.nonce()
        process=context.Process(target=recipient,args=(child,credential,nonce));process.start();child.close()
        left,right=socket.socketpair()
        try:
            left.settimeout(5);right.settimeout(5)
            parent.send_bytes(WindowsHandleTransfer.export(left,process.pid,credential=credential,nonce=nonce))
            self.assertEqual(right.recv(32),b'windows-handle');right.sendall(b'kernel-reply')
            self.assertTrue(parent.poll(5));self.assertEqual(parent.recv(),b'kernel-reply')
            self.assertTrue(parent.poll(5));self.assertEqual(parent.recv(),'HandleReplayRejected')
            process.join(5);self.assertEqual(process.exitcode,0)
        finally:
            left.close();right.close();parent.close()
            if process.is_alive():process.terminate();process.join(5)

    def test_wrong_platform_and_bad_credentials_fail_closed(self):
        with socket.socket() as connection:
            with self.assertRaises(ConnectionError):
                WindowsHandleTransfer.export(connection,os.getpid(),credential=b'short',nonce='a'*64)
            if os.name!='nt':
                with self.assertRaisesRegex(ConnectionError,'WindowsHandleTransferUnavailable'):
                    WindowsHandleTransfer.export(connection,os.getpid(),credential=b'k'*32,nonce='a'*64)
