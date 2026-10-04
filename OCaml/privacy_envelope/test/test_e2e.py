"""Loopback E2E of the actual OCaml executable (S6EPE_BINARY is required)."""
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

from wire_v3 import Peer, capsule, open_capsule

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
        values = dict(mode=mode, role=role, listen=f'127.0.0.1:{listen}', upstream=f'127.0.0.1:{upstream}' if isinstance(upstream,int) else upstream, auth_key=KEY,
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
                exact(sock, 88)
            with socket.create_connection(('127.0.0.1', server), timeout=2) as rejected:
                self.assertEqual(rejected.recv(1), b'')
            self.metrics(metrics, 'resource_limit_rejection_count', 1)
        finally:
            for sock in held:
                sock.close()
        time.sleep(.15)
        with socket.create_connection(('127.0.0.1', server), timeout=2) as sock:
            peer = Peer(sock, KEY, fragmented=True)
            peer.send(b'hello')
            self.assertEqual(peer.receive(), (b'hello',0))
            peer.send(b'',tag=3)
            self.assertEqual(peer.receive(), (b'',3))
        with socket.create_connection(('127.0.0.1', server), timeout=2) as sock:
            exact(sock, 88); sock.sendall(bytes(120)); self.assertEqual(sock.recv(1), b'')
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

    def test_stream_ipv6_and_private_unix_handoffs(self):
        with socket.socket(socket.AF_INET6) as reserve:
            reserve.bind(('::1',0)); server_port = reserve.getsockname()[1]
        native_path = self.root/'native.sock'
        client_path = self.root/'client.sock'
        native = socket.socket(socket.AF_UNIX); native.bind(str(native_path));native.listen()
        self.addCleanup(native.close)
        errors=[]
        def echo():
            try:
                native.settimeout(3)
                connection,_ = native.accept()
                with connection:
                    connection.settimeout(3)
                    while True:
                        payload=connection.recv(65536)
                        if not payload:break
                        connection.sendall(payload)
            except OSError as error: errors.append(error)
        thread=threading.Thread(target=echo);thread.start()
        self.launch('server','stream','server','unix:'+str(native_path),listen=f'[::1]:{server_port}')
        self.launch('client','stream','client',f'[::1]:{server_port}',listen='unix:'+str(client_path))
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(3);connection.connect(str(client_path))
            connection.sendall(b'IPv6 encrypted outer / Unix private native');connection.shutdown(socket.SHUT_WR)
            self.assertEqual(exact(connection,len(b'IPv6 encrypted outer / Unix private native')),b'IPv6 encrypted outer / Unix private native')
            self.assertEqual(connection.recv(1),b'')
        thread.join(4);self.assertFalse(thread.is_alive());self.assertEqual(errors,[])

    def test_v3_feature_report_matches_encrypted_wire(self):
        report=json.loads(subprocess.check_output([self.binary,'--feature-report'],timeout=2))
        self.assertEqual(report['wire_version'],3)
        self.assertTrue(report['payload_encryption'])
        self.assertEqual(report['cipher'],'XChaCha20-Poly1305')
        self.assertTrue(report['endpoints']['IPv6'])
        self.assertTrue(report['endpoints']['Unix_stream'])

    def test_datagram_persistent_replay_survives_actual_process_restart(self):
        state=self.root/'replay.state'
        native=self.echo('datagram')
        server,metrics=self.launch('server','datagram','server',native,replay_path=str(state))
        packet=capsule(KEY,b'S6EPE/3 request',b'private-payload-marker',int(time.time()))
        with socket.socket(type=socket.SOCK_DGRAM) as sock:
            sock.settimeout(.5);address=('127.0.0.1',server)
            sock.sendto(packet,address)
            self.assertEqual(open_capsule(KEY,b'S6EPE/3 response',sock.recv(8192)),b'private-payload-marker')
            persisted=state.read_bytes()
            self.assertNotIn(KEY.encode(),persisted)
            self.assertNotIn(b'private-payload-marker',persisted)
            self.assertLess(len(persisted),400000)
            self.assertEqual(state.stat().st_mode & 0o777,0o600)
            self.children[-1].terminate();self.children[-1].wait(timeout=3)
            metrics.unlink()
            self.launch('server','datagram','server',native,replay_path=str(state),listen=f'127.0.0.1:{server}')
            # Establish actual post-restart authenticated forwarding before the
            # negative probe. A metrics file alone is not a packet-path check.
            fresh = b'post-restart-fresh-payload'
            sock.sendto(capsule(KEY,b'S6EPE/3 request',fresh,int(time.time())),address)
            self.assertEqual(open_capsule(KEY,b'S6EPE/3 response',sock.recv(8192)),fresh)
            before = self.metrics(metrics,'bytes_in',len(fresh))
            self.assertEqual(before['bytes_in'],len(fresh))
            # UDP provides no delivery acknowledgement for rejected traffic.
            # Repeat only the exact replay, bounded to five probes, and still
            # require both a rejection observation and zero native delivery.
            observed = None
            for _ in range(5):
                sock.sendto(packet,address)
                with self.assertRaises(TimeoutError):sock.recv(8192)
                current = json.loads(metrics.read_text())
                if current['replay_rejection_count'] >= 1:
                    observed = current
                    break
            self.assertIsNotNone(observed,'no post-restart replay rejection observed')
            self.assertEqual(observed['bytes_in'],len(fresh))
            self.assertEqual(observed['bytes_out'],len(fresh))
            self.assertIsNone(self.children[-1].poll())

    def test_padding_zero_record_cover_limit_and_budget_fail_closed(self):
        server,metrics=self.launch('shaped','stream','server',self.echo('stream'),padding_block=128,jitter_ms=2,cover_interval=1,cover_limit=1)
        with socket.create_connection(('127.0.0.1',server),timeout=3) as sock:
            peer=Peer(sock,KEY)
            peer.send(b'')
            peer.send(b'abc')
            self.assertEqual(peer.receive(),(b'abc',0))
            self.assertEqual(peer.last_record_size,128+17)
            self.assertEqual(peer.receive(),(b'',1))
            peer.send(b'',tag=3)
            self.assertEqual(peer.receive(),(b'',3))
        value=self.metrics(metrics,'shaping_overhead_bytes',120)
        self.assertTrue(value['shaping_enabled'])
        self.assertLessEqual(value['shaping_overhead_bytes'],1048576)
        server,metrics=self.launch('exhausted','stream','server',self.echo('stream'),padding_block=4096,shaping_budget=64)
        with socket.create_connection(('127.0.0.1',server),timeout=3) as sock:
            peer=Peer(sock,KEY);peer.send(b'abc')
            with self.assertRaises(EOFError):peer.receive()
        self.metrics(metrics,'resource_limit_rejection_count',1)

    def test_authenticated_stream_replay_is_rejected_without_native_replay(self):
        server,metrics=self.launch('replay','stream','server',self.echo('stream'))
        with socket.create_connection(('127.0.0.1',server),timeout=3) as sock:
            peer=Peer(sock,KEY);packet=peer.send(b'unique')
            self.assertEqual(peer.receive(),(b'unique',0))
            sock.sendall(packet)
            with self.assertRaises(EOFError):peer.receive()
        value=self.metrics(metrics,'preauth_rejection_count',1)
        self.assertEqual(value['bytes_in'],len(b'unique'))

    def test_datagram_replay_invalid_and_oversize_do_not_kill_server(self):
        server, metrics = self.launch('server', 'datagram', 'server', self.echo('datagram'))
        packet = capsule(KEY, b'S6EPE/3 request', b'payload', int(time.time()))
        with socket.socket(type=socket.SOCK_DGRAM) as sock:
            sock.settimeout(.3); address = ('127.0.0.1', server)
            sock.sendto(packet, address); reply = sock.recv(8192)
            self.assertFalse(reply.endswith(b'payload'))
            self.assertEqual(open_capsule(KEY,b'S6EPE/3 response',reply),b'payload')
            sock.sendto(reply,address)
            with self.assertRaises(TimeoutError): sock.recv(8192)
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
