"""Real POSIX ancillary transfer and peer identity, including macOS stream IPC."""
import array
import os
import socket
import unittest
from libshadow6.fd_client import peer_identity


@unittest.skipUnless(os.name=='posix','SCM_RIGHTS backend requires POSIX; Windows has its kernel handle gate')
class PosixTransferTests(unittest.TestCase):
    def test_stream_channel_peer_identity_cloexec_and_caller_owned_socket(self):
        channel,receiver=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        left,right=socket.socketpair()
        fd=None
        try:
            self.assertEqual(peer_identity(receiver),os.geteuid())
            channel.sendmsg([b'owned'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[left.fileno()]))])
            body,ancillary,flags,_=receiver.recvmsg(32,socket.CMSG_SPACE(4),getattr(socket,'MSG_CMSG_CLOEXEC',0))
            self.assertEqual(body,b'owned');self.assertFalse(flags&socket.MSG_CTRUNC)
            descriptors=array.array('i');descriptors.frombytes(ancillary[0][2]);self.assertEqual(len(descriptors),1)
            fd=descriptors[0];os.set_inheritable(fd,False);left.close()
            os.write(fd,b'after-source-close');self.assertEqual(right.recv(32),b'after-source-close')
            self.assertFalse(os.get_inheritable(fd))
        finally:
            if fd is not None:os.close(fd)
            channel.close();receiver.close();left.close();right.close()
