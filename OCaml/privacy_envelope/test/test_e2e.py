"""Loopback E2E of the actual OCaml executable (S6EPE_BINARY is required)."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time
import unittest

KEY = 'test-only-key-0123456789abcdef'


def port(kind=socket.SOCK_STREAM):
    with socket.socket(type=kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def exact(sock, count):
    data = b''
    while len(data) < count:
        block = sock.recv(count-len(data))
        if not block:
            raise EOFError('short stream')
        data += block
    return data


class EnvelopeE2E(unittest.TestCase):
    def setUp(self):
        self.binary = os.environ.get('S6EPE_BINARY')
        if not self.binary:
            self.skipTest('S6EPE_BINARY unavailable; no native verification')
        self.temp = tempfile.TemporaryDirectory(prefix='shadow6-epe-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.children = []
        self.addCleanup(self.stop)
        self.done = threading.Event()
        self.addCleanup(self.done.set)

    def stop(self):
        for child in self.children:
            child.terminate()
        for child in self.children:
            child.wait(timeout=5)
            child.stderr.close()

    def launch(self, name, mode, role, upstream, **options):
        listen = port(socket.SOCK_DGRAM if mode == 'datagram' else socket.SOCK_STREAM)
        metrics = self.root / (name+'.metrics')
        config = self.root / (name+'.conf')
        values = dict(mode=mode, role=role, listen=f'127.0.0.1:{listen}', upstream=f'127.0.0.1:{upstream}', auth_key=KEY,
                      metrics_path=str(metrics), handshake_timeout=1, idle_timeout=2, session_timeout=5, max_frame=4096,
                      max_preauth=2, max_sessions=4)
        values.update(options)
        config.write_text(''.join(f'{k}={v}\n' for k,v in values.items())); config.chmod(0o600)
        process = subprocess.Popen([self.binary, '--config', str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.children.append(process)
        deadline = time.monotonic()+3
        while not metrics.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertIsNone(process.poll(), process.stderr.read() if process.poll() is not None else '')
        self.assertTrue(metrics.exists())
        return listen, metrics

    def echo(self, mode):
        udp = mode == 'datagram'
        sock = socket.socket(type=socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 0)); sock.settimeout(.1)
        if not udp:
            sock.listen(8)
        self.addCleanup(sock.close)
        def loop():
            while not self.done.is_set():
                try:
                    if udp:
                        data, addr = sock.recvfrom(65535); sock.sendto(data, addr)
                    else:
                        client, _ = sock.accept(); client.settimeout(2)
                        with client:
                            while True:
                                data = client.recv(65535)
                                if not data:
                                    break
                                client.sendall(data)
                except (TimeoutError, OSError):
                    pass
        thread = threading.Thread(target=loop, daemon=True); thread.start()
        return sock.getsockname()[1]

    def metrics(self, path, key, minimum):
        deadline = time.monotonic()+3
        while time.monotonic() < deadline:
            result = json.loads(path.read_text())
            if result[key] >= minimum:
                return result
            time.sleep(.05)
        self.fail(f'{key} did not reach {minimum}')

    def test_stream_client_server_bidirectional_large_payload_half_close(self):
        server, metrics = self.launch('server', 'stream', 'server', self.echo('stream'))
        client, _ = self.launch('client', 'stream', 'client', server)
        payload = secrets.token_bytes(100000)
        with socket.create_connection(('127.0.0.1', client), timeout=3) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(exact(sock, len(payload)), payload)
            self.assertEqual(sock.recv(1), b'')
        result = self.metrics(metrics, 'bytes_out', len(payload))
        self.assertEqual(result['authenticated_sessions'], 1)
        self.assertEqual(result['bytes_in'], len(payload))

    def test_fragmented_handshake_wrong_auth_and_capacity_recover(self):
        server, metrics = self.launch('server', 'stream', 'server', self.echo('stream'))
        held = [socket.create_connection(('127.0.0.1', server), timeout=2) for _ in range(2)]
        try:
            for sock in held:
                exact(sock, 32)
            with socket.create_connection(('127.0.0.1', server), timeout=2) as rejected:
                self.assertEqual(rejected.recv(1), b'')
            self.metrics(metrics, 'resource_limit_rejection_count', 1)
        finally:
            for sock in held:
                sock.close()
        time.sleep(.15)
        with socket.create_connection(('127.0.0.1', server), timeout=2) as sock:
            nonce = exact(sock, 32)
            client = secrets.token_bytes(32)
            proof = hmac.digest(KEY.encode(), b'S6EPE/2 client'+nonce+client, 'sha256')
            for byte in client+proof:
                sock.sendall(bytes([byte]))
            self.assertEqual(exact(sock, 32), hmac.digest(KEY.encode(), b'S6EPE/2 server'+nonce+client, 'sha256'))
            sock.sendall(b'hello'); self.assertEqual(exact(sock, 5), b'hello')
        with socket.create_connection(('127.0.0.1', server), timeout=2) as sock:
            exact(sock, 32); sock.sendall(bytes(64)); self.assertEqual(sock.recv(1), b'')
        self.metrics(metrics, 'preauth_rejection_count', 3)

    def test_datagram_roundtrip_boundaries_multiple_peers(self):
        server, metrics = self.launch('server', 'datagram', 'server', self.echo('datagram'))
        client, _ = self.launch('client', 'datagram', 'client', server)
        for _ in range(2):
            with socket.socket(type=socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                for payload in (b'', b'a', secrets.token_bytes(4096)):
                    sock.sendto(payload, ('127.0.0.1', client))
                    self.assertEqual(sock.recv(8192), payload)
        self.metrics(metrics, 'authenticated_sessions', 2)

    def test_datagram_replay_invalid_and_oversize_do_not_kill_server(self):
        server, metrics = self.launch('server', 'datagram', 'server', self.echo('datagram'))
        body = f'{int(time.time()):016x}'.encode()+secrets.token_bytes(32)+b'payload'
        packet = hmac.digest(KEY.encode(), b'S6EPE/2 request'+body, 'sha256')+body
        with socket.socket(type=socket.SOCK_DGRAM) as sock:
            sock.settimeout(.3); address = ('127.0.0.1', server)
            sock.sendto(packet, address); reply = sock.recv(8192)
            self.assertTrue(reply.endswith(b'payload'))
            self.assertEqual(reply[:32], hmac.digest(KEY.encode(), b'S6EPE/2 response'+reply[32:], 'sha256'))
            sock.sendto(packet, address)
            with self.assertRaises(TimeoutError): sock.recv(8192)
            sock.sendto(b'bad', address); sock.sendto(bytes(5000), address)
        self.metrics(metrics, 'replay_rejection_count', 1)
        self.metrics(metrics, 'preauth_rejection_count', 1)
        self.metrics(metrics, 'resource_limit_rejection_count', 1)
        self.assertIsNone(self.children[0].poll())

    def test_config_rejects_symlink_unknown_duplicate_and_public_local_endpoint(self):
        base = 'listen=127.0.0.1:12345\nupstream=127.0.0.1:12346\nauth_key='+KEY+'\n'
        for suffix in ('unknown=x\n', 'mode=stream\nmode=stream\n', 'upstream=8.8.8.8:1\n'):
            config = self.root/'bad'; config.write_text(base+suffix); config.chmod(0o600)
            result = subprocess.run([self.binary, '--config', str(config)], capture_output=True, timeout=2)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(KEY.encode(), result.stderr)
        unrelated = self.root/'unrelated'; unrelated.write_text('KEEP PRIVATE DATA'); unrelated.chmod(0o600)
        config.write_text(base+'metrics_path='+str(unrelated)+'\n')
        self.assertEqual(subprocess.run([self.binary,'--config',str(config)],capture_output=True,timeout=2).returncode,2)
        self.assertEqual(unrelated.read_text(),'KEEP PRIVATE DATA')
        link = self.root/'link'; link.symlink_to(config)
        self.assertEqual(subprocess.run([self.binary, '--config', str(link)], capture_output=True, timeout=2).returncode, 2)


if __name__ == '__main__':
    unittest.main()
