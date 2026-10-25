import importlib.util
import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
from types import SimpleNamespace
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('shadowmessager',HERE/'shadowmessager.py')
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)


class MessengerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);root=Path(self.tmp.name)
        first=app.initialize(root/'alice','alice','home/chat')
        second=app.initialize(root/'bob','bob','home/chat',Path(first['session_key_file']))
        self.configs=[]
        for public,peer_name,other in [(first,'bob',second),(second,'alice',first)]:
            path=Path(public['config']);value=json.loads(path.read_text());value.update(peer=peer_name,peer_public_key=other['public_key']);path.write_text(json.dumps(value));self.configs.append(app.load(path))

    def pair(self,semantics='stream',maximum=1024):
        kind=socket.SOCK_STREAM if semantics=='stream' else socket.SOCK_SEQPACKET
        a,b=socket.socketpair(type=kind);self.addCleanup(a.close);self.addCleanup(b.close);a.settimeout(2);b.settimeout(2)
        boundary=SimpleNamespace(semantics=semantics,max_record=maximum)
        return (app.Messenger(self.configs[0],SimpleNamespace(socket=a,boundary=boundary)),
                app.Messenger(self.configs[1],SimpleNamespace(socket=b,boundary=boundary)))

    def test_actual_shadowchat_stream_roundtrip_unicode_and_private_keys(self):
        a,b=self.pair();a.send('你好，Shadow6');self.assertEqual(b.receive(),'你好，Shadow6');b.send('reply');self.assertEqual(a.receive(),'reply')
        self.assertEqual(Path(self.configs[0]['identity_file']).stat().st_mode&0o777,0o600)
        self.assertNotEqual(Path(self.configs[0]['identity_file']).read_bytes(),Path(self.configs[1]['identity_file']).read_bytes())

    @unittest.skipUnless(hasattr(socket,'SOCK_SEQPACKET'),'record sockets unavailable')
    def test_message_profile_fragments_authenticated_chat(self):
        a,b=self.pair('message',256);text='界'*1000
        result=[]
        thread=threading.Thread(target=lambda:result.append(b.receive()));thread.start();a.send(text);thread.join(3)
        self.assertFalse(thread.is_alive());self.assertEqual(result,[text])

    def test_pinned_peer_wrong_name_and_replay_are_rejected(self):
        a,b=self.pair();doc=a.chat.encrypt('bob','hello');wire=app.encode_frame(doc)
        a.wire.send(wire);self.assertEqual(b.receive(),'hello')
        a.wire.send(wire)
        with self.assertRaises(ValueError):b.receive()
        doc=a.chat.encrypt('other','wrong recipient');a.wire.send(app.encode_frame(doc))
        with self.assertRaises(ValueError):b.receive()

    def test_signature_and_ciphertext_tampering_rejected(self):
        a,b=self.pair();doc=a.chat.encrypt('bob','secret');doc['signature']='0'*128;a.wire.send(app.encode_frame(doc))
        with self.assertRaises(ValueError):b.receive()

    def test_oversized_stream_prefix_rejected_before_body(self):
        a,b=self.pair();a.connection.socket.sendall(struct.pack('!I',app.MAX_WIRE+1))
        with self.assertRaises(ValueError):b.receive()
        with self.assertRaises(ValueError):a.send('x'*(app.MAX_MESSAGE+1))

    def test_configuration_permissions_and_existing_identity_preserved(self):
        path=Path(self.configs[0]['identity_file']);path.chmod(0o644)
        with self.assertRaises(ValueError):app.private(path,32)
        with self.assertRaises(ValueError):app.initialize(path.parent,'alice','home/chat')

    def test_content_fabric_attachments_roundtrip_and_limits(self):
        a,b=self.pair()
        cf1='cf1-'+('a'*64)
        cf2={'file_id':'cf1-'+('b'*64)}
        a.send('Check out these files',attachments=[cf1,cf2])
        received=b.receive()
        self.assertIsInstance(received,dict)
        self.assertEqual(received['text'],'Check out these files')
        self.assertEqual(received['attachments'],[cf1,'cf1-'+('b'*64)])
        # Rejection of invalid attachment IDs
        with self.assertRaises(ValueError):
            a.send('Bad attachment',attachments=['invalid-id'])
        with self.assertRaises(ValueError):
            a.send('Bad hash',attachments=['cf1-short'])
        # Rejection of too many attachments (> 4)
        with self.assertRaises(ValueError):
            a.send('Too many',attachments=['cf1-'+(str(i).zfill(64)) for i in range(5)])


if __name__=='__main__':unittest.main()
