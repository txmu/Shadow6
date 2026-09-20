import json, os, subprocess, unittest
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
 def test_fixed_vector_is_stable(self):
  key=bytes(range(32)); frame=Codec(key,1200,0).encode(DATA,7,42,0,1,b"cross-backend")
  self.assertEqual(frame.hex(),"53364e41010100000000000000000007000000000000002a000000010000000d42e3db28ec08001b41581ea8010d468a5f828ae126237ba96b6b3f53f6")

if __name__=="__main__":unittest.main()
