import os, tempfile, unittest
from pathlib import Path
from shadow6_network import DatagramEndpoint, POLICIES, ReliableAdapter, load_key

class AdapterTests(unittest.TestCase):
    def test_large_message_reorders_deduplicates_and_retransmits(self):
        now=[0.0]; clock=lambda:now[0]; key=os.urandom(32)
        left=ReliableAdapter("pony",key,0,clock=clock); right=ReliableAdapter("pony",key,1,clock=clock)
        data=os.urandom(32000); frames=left.send(3,data); self.assertGreater(len(frames),1)
        completed=[]; queue=list(reversed(frames))
        while queue:
            frame=queue.pop(0); acks,done,_=right.receive(frame); completed+=done
            for ack in acks: left.receive(ack)
            queue.extend(left.outbound())
        self.assertEqual(completed,[(3,data)])
        right.receive(frames[0])
        self.assertEqual(left.buffered,0)
        left.send(1,b"retry"); now[0]=1.0; self.assertTrue(left.retransmit())
    def test_concurrent_streams_and_extension_allowlist(self):
        key=os.urandom(32); left=ReliableAdapter("ada",key,0,extensions=("trace.sample",)); right=ReliableAdapter("ada",key,1,extensions=("trace.sample",))
        for stream in range(8):
            frames=left.send(stream,bytes([stream])*2000); output=[]
            for frame in frames:
                acks,done,_=right.receive(frame); output+=done
                for ack in acks:left.receive(ack)
            self.assertEqual(output,[(stream,bytes([stream])*2000)])
        _,_,events=right.receive(left.extension(0,"trace.sample",{"enabled":True}))
        self.assertEqual(events[0][1],"trace.sample")
        with self.assertRaises(PermissionError): left.extension(0,"shell",{})
    def test_tamper_and_bounds_fail_closed(self):
        key=os.urandom(32); adapter=ReliableAdapter("carp",key,0); peer=ReliableAdapter("carp",key,1); frame=adapter.send(0,b"safe")[0]
        with self.assertRaises(ValueError): adapter.receive(frame[:-1]+bytes([frame[-1]^1]))
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"key"; path.write_bytes(key); path.chmod(0o600)
            self.assertEqual(load_key(path),key)
            path.chmod(0o644)
            with self.assertRaises(PermissionError): load_key(path)
    def test_idris_companion_carrier_uses_pinned_authenticated_peer(self):
        self.assertEqual(POLICIES["idris"].mode,"native")
        self.assertEqual(POLICIES["idris"].payload,1024)
        key=os.urandom(32)
        first=DatagramEndpoint("idris",key,("127.0.0.1",0),("127.0.0.1",9),0)
        second=DatagramEndpoint("idris",key,("127.0.0.1",0),first.address,1)
        first.peer=second.address
        try:
            first.send(7,os.urandom(5000)); output=[]
            for _ in range(20):
                done,_=second.poll(.1); output+=done
                first.poll(0)
                if output: break
            self.assertEqual(len(output),1); self.assertEqual(len(output[0][1]),5000)
        finally: first.close(); second.close()

if __name__=="__main__": unittest.main()
