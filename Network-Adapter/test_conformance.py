import json, os, shutil, subprocess, tempfile, unittest
from pathlib import Path
from shadow6_network import Codec, DATA

HERE=Path(__file__).resolve().parent
class ConformanceTests(unittest.TestCase):
 def test_python_frame_decodes_in_node(self):
  key=bytes(range(32)); frame=Codec(key,1200,0).encode(DATA,7,42,0,1,b"cross-backend")
  request={"key":key.hex(),"payload":1200,"side":1,"frame":frame.hex()}
  result=subprocess.run(["node",str(HERE/"shadow6_network.mjs"),"decode-vector"],input=json.dumps(request),text=True,capture_output=True,timeout=5)
  self.assertEqual(result.returncode,0,result.stderr); decoded=json.loads(result.stdout)
  self.assertEqual((decoded["stream"],decoded["message"],bytes.fromhex(decoded["payload"])),(7,"42",b"cross-backend"))
 def test_node_frame_decodes_in_python(self):
  key=bytes(range(32)); request={"key":key.hex(),"limit":1200,"side":0,"kind":1,"stream":9,"message":"77","index":0,"count":1,"payload":b"node-to-python".hex()}
  result=subprocess.run(["node",str(HERE/"shadow6_network.mjs"),"encode-vector"],input=json.dumps(request),text=True,capture_output=True,timeout=5)
  self.assertEqual(result.returncode,0,result.stderr); frame=bytes.fromhex(json.loads(result.stdout)["frame"])
  kind,stream,message,index,count,payload=Codec(key,1200,1).decode(frame)
  self.assertEqual((kind,stream,message,index,count,payload),(1,9,77,0,1,b"node-to-python"))
 def test_cli_vectors_from_url_sensitive_path(self):
  with tempfile.TemporaryDirectory(prefix="shadow6-node-cli-") as directory:
   script=Path(directory)/"adapter space # percent %.mjs"
   shutil.copyfile(HERE/"shadow6_network.mjs",script)
   key=bytes(range(32)); payload=b"path-regression"
   request={"key":key.hex(),"limit":1200,"side":0,"kind":DATA,"stream":3,"message":"11","index":0,"count":1,"payload":payload.hex()}
   result=subprocess.run(["node",script.name,"encode-vector"],cwd=directory,input=json.dumps(request),text=True,capture_output=True,timeout=5)
   self.assertEqual(result.returncode,0,result.stderr)
   self.assertTrue(result.stdout.strip(),"Node CLI returned no JSON")
   frame=bytes.fromhex(json.loads(result.stdout)["frame"])
   self.assertEqual(Codec(key,1200,1).decode(frame)[-1],payload)
   request={"key":key.hex(),"payload":1200,"side":1,"frame":frame.hex()}
   result=subprocess.run(["node",str(script),"decode-vector"],input=json.dumps(request),text=True,capture_output=True,timeout=5)
   self.assertEqual(result.returncode,0,result.stderr)
   self.assertTrue(result.stdout.strip(),"Node CLI returned no JSON")
   self.assertEqual(bytes.fromhex(json.loads(result.stdout)["payload"]),payload)
 def test_fixed_vector_is_stable(self):
  key=bytes(range(32)); frame=Codec(key,1200,0).encode(DATA,7,42,0,1,b"cross-backend")
  self.assertEqual(frame.hex(),"53364e41010100000000000000000007000000000000002a000000010000000d42e3db28ec08001b41581ea8010d468a5f828ae126237ba96b6b3f53f6")

if __name__=="__main__":unittest.main()
