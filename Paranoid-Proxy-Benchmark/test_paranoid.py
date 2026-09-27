import contextlib
import io
import json
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import paranoid_proxy_benchmark as benchmark

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        while True:
            data=self.request.recv(65536)
            if not data: return
            self.request.sendall(data)

class Tests(unittest.TestCase):
    def test_catalog_has_unique_bounded_cases(self):
        self.assertEqual(len(benchmark.CATALOG),42)
        self.assertEqual(len({c['id'] for c in benchmark.CATALOG}),42)
        self.assertTrue(all(c['concurrency']<=4 and c.get('bytes',0)<=65536 for c in benchmark.CATALOG))

    def test_endpoint_rejects_credentials_names_wildcards_and_remote_default(self):
        for text in ('tcp://0.0.0.0:80','tcp://user:pass@127.0.0.1:80','tcp://localhost:80','tcp://192.0.2.1:80','tcp://127.0.0.1:80/path','tcp://[ff02::1]:80'):
            with self.subTest(text=text), self.assertRaises(ValueError): benchmark.endpoint(text,('tcp',),False)
        self.assertEqual(benchmark.endpoint('tcp://192.0.2.1:80',('tcp',),True),('tcp','192.0.2.1',80))

    def test_exact_read_rejects_truncation(self):
        left,right=socket.socketpair()
        with left,right:
            left.sendall(b'a');left.shutdown(socket.SHUT_WR)
            with self.assertRaises(EOFError): benchmark.receive_exact(right,2,time.monotonic()+1)

    def test_udp_oversize_is_explicitly_unsupported(self):
        result=benchmark.probe({'kind':'echo','bytes':4096},('udp','127.0.0.1',1),None,time.monotonic()+1,None)
        self.assertEqual(result['status'],'unsupported')

    def test_36_workloads_and_stream_contracts_loopback(self):
        with socketserver.ThreadingTCPServer(('127.0.0.1',0),Echo) as server:
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                output=io.StringIO()
                with patch.object(sys,'argv',['ppb','run','--node',f'tcp://127.0.0.1:{server.server_address[1]}']),contextlib.redirect_stdout(output):
                    self.assertEqual(benchmark.main(),0)
                report=json.loads(output.getvalue())
                self.assertEqual(sum(r['status']=='pass' for r in report['results']),39)
                self.assertEqual(sum(r['status']=='unsupported' for r in report['results']),3)
            finally:
                server.shutdown();thread.join(3)

    def test_single_file_outside_source_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            script=Path(directory)/'ppb.py';script.write_bytes(Path(benchmark.__file__).read_bytes())
            result=subprocess.run([sys.executable,'-B',str(script),'catalog'],cwd=directory,capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(len(json.loads(result.stdout)['cases']),42)

if __name__=='__main__': unittest.main()
