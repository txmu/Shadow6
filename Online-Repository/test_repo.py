import json,tempfile,unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shadow6_repo import build,verify,source_url
class RepoTests(unittest.TestCase):
 def test_signed_index(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/"demo.s6pkg").write_bytes(b"package");key=Ed25519PrivateKey.generate();keyfile=root/"key.pem";keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));keyfile.chmod(0o600);pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex();trust=root/"trust.json";trust.write_text(json.dumps({"signers":{"test":pub}}));index=root/"index.json";build(root,index,keyfile,"test");self.assertEqual(verify(index.read_bytes(),trust)["packages"][0]["name"],"demo.s6pkg")
 def test_cleartext_remote_rejected(self):
  with self.assertRaises(ValueError):source_url("http://example.com/repo")
if __name__=="__main__":unittest.main()
