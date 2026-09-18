import json,tempfile,unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shadow6_repo import build,verify,source_url,RepositoryServer
import http.client, os, socket, threading, time
from unittest.mock import patch
class RepoTests(unittest.TestCase):
 def test_signed_index(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/"demo.s6pkg").write_bytes(b"package");key=Ed25519PrivateKey.generate();keyfile=root/"key.pem";keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));keyfile.chmod(0o600);pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex();trust=root/"trust.json";trust.write_text(json.dumps({"signers":{"test":pub}}));index=root/"index.json";build(root,index,keyfile,"test");self.assertEqual(verify(index.read_bytes(),trust)["packages"][0]["name"],"demo.s6pkg")
 def test_cleartext_remote_rejected(self):
  with self.assertRaises(ValueError):source_url("http://example.com/repo")
class RepositoryServerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix="shadow6-repo-test.")
  self.root=Path(self.tmp.name)/"public";self.root.mkdir()
  (self.root/"index.json").write_bytes(b'{"packages":[]}')
  (self.root/"demo.s6pkg").write_bytes(b"published package")
  (self.root/"private.pem").write_bytes(b"private marker")
  (self.root/"linked.s6pkg").symlink_to(self.root/"private.pem")
  os.link(self.root/"private.pem", self.root/"hardlink.s6pkg")
  os.mkfifo(self.root/"fifo.s6pkg", 0o600)
  self.server=RepositoryServer(("127.0.0.1",0),self.root)
  self.thread=threading.Thread(target=self.server.serve_forever,kwargs={"poll_interval":.02})
  self.thread.start()
 def tearDown(self):
  self.server.shutdown();self.thread.join(2);self.server.server_close();self.tmp.cleanup()
 def request(self,path,method="GET"):
  connection=http.client.HTTPConnection(*self.server.server_address,timeout=2)
  try:
   connection.request(method,path);response=connection.getresponse()
   return response.status,response.read(),dict(response.getheaders())
  finally:connection.close()
 def test_publications_and_head(self):
  self.assertEqual(self.request("/demo.s6pkg")[:2],(200,b"published package"))
  self.assertEqual(self.request("/index.json")[0],200)
  status,body,headers=self.request("/demo.s6pkg","HEAD")
  self.assertEqual((status,body),(200,b""));self.assertEqual(headers["Content-Length"],"17")
 def test_no_directory_secret_links_or_path_aliases(self):
  for path in ("/","/private.pem","/.git/config","/../private.pem","/%2e%2e/private.pem",
               "/linked.s6pkg","/hardlink.s6pkg","/fifo.s6pkg","/sub/demo.s6pkg",
               "/demo.s6pkg?x=1","/demo.s6pkg%00","/index.json/../private.pem"):
   with self.subTest(path=path):self.assertEqual(self.request(path)[0],404)
 def test_size_bound(self):
  with patch("shadow6_repo.MAX_PACKAGE",3):self.assertEqual(self.request("/demo.s6pkg")[0],404)
 def test_root_descriptor_survives_path_replacement(self):
  self.root.rename(self.root.with_name("original"))
  self.root.mkdir()
  (self.root/"demo.s6pkg").write_bytes(b"replacement")
  self.assertEqual(self.request("/demo.s6pkg")[:2],(200,b"published package"))
 def test_connection_limit_and_absolute_header_deadline(self):
  self.server.connection_timeout=.3
  clients=[]
  try:
   # A trickle of header bytes must not indefinitely renew the timeout.
   slow=socket.create_connection(self.server.server_address,timeout=2);clients.append(slow)
   slow.sendall(b"GET /index.json HTTP/1.0\r\nX: ")
   deadline=time.monotonic()+1
   closed=False
   while time.monotonic()<deadline:
    try:
     slow.sendall(b"x");time.sleep(.05)
     slow.settimeout(.01)
     if slow.recv(1)==b"":closed=True;break
    except socket.timeout:pass
    except OSError:closed=True;break
   self.assertTrue(closed,"slow headers exceeded the absolute deadline")
   # Saturating the same admission gate must reject before starting a handler.
   for _ in range(self.server.max_connections):self.assertTrue(self.server.slots.acquire(timeout=1))
   try:
    excess=socket.create_connection(self.server.server_address,timeout=2);clients.append(excess)
    self.assertEqual(excess.recv(1),b"")
   finally:
    for _ in range(self.server.max_connections):self.server.slots.release()
   self.assertEqual(self.request("/index.json")[0],200)
  finally:
   for client in clients:client.close()

if __name__=="__main__":unittest.main()
