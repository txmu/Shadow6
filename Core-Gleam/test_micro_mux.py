#!/usr/bin/env python3
"""Real Core-Gleam broker/agent/client micro-mux (UDP) forwarding test."""
import json, os, pathlib, re, socket, subprocess, sys, tempfile, threading, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

binary = pathlib.Path(sys.argv[1]).resolve()


def keypair():
    key = Ed25519PrivateKey.generate()
    return key.private_bytes_raw().hex(), key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]


class UdpEcho:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.s.bind(('127.0.0.1', 0))
        self.s.settimeout(.2); self.port = self.s.getsockname()[1]; self.stop = False
        self.t = threading.Thread(target=self.run, daemon=True); self.t.start()

    def run(self):
        while not self.stop:
            try: data, peer = self.s.recvfrom(65536)
            except (socket.timeout, OSError): continue
            self.s.sendto(data, peer)

    def close(self):
        self.stop = True; self.t.join(2); self.s.close()


bpv, bpu = keypair(); apv, apu = keypair(); cpv, cpu = keypair(); port = free_port(); echo = UdpEcho(); processes = []
with tempfile.TemporaryDirectory(prefix='shadow6-gleam-mux.') as td:
    root = pathlib.Path(td)

    def cfg(name, value):
        p = root / name; p.write_text(json.dumps(value, separators=(',', ':'))); p.chmod(0o600); return p
    common = {'broker_addrs': [f'ws://127.0.0.1:{port}/ws'], 'broker_pubkey': bpu, 'allow_local_discovery': False,
              'transport': 'micro-mux'}
    broker = cfg('broker.json', {'role': 'broker', 'broker': {'listen_addr': f'127.0.0.1:{port}', 'private_key': bpv,
        'agents': [{'id': 'agent', 'pubkey': apu}], 'clients': [{'id': 'client', 'pubkey': cpu, 'allowed_agents': ['agent']}],
        'webhook_url': '', 'stealth_mode': False}, 'agent': None, 'client': None})
    agent = cfg('agent.json', {'role': 'agent', 'broker': None, 'client': None, 'agent': dict(common, id='agent',
        private_key=apv, target_port=echo.port, auto_close_after=30, client_pubkeys={'client': cpu})})
    client = cfg('client.json', {'role': 'client', 'broker': None, 'agent': None, 'client': dict(common, id='client',
        private_key=cpv, target_agent='agent', agent_pubkey=apu, on_success='')})
    try:
        for path in (broker, agent, client):
            checked = subprocess.run([binary, '--config', path, '--check-config'], capture_output=True, text=True, timeout=10)
            assert checked.returncode == 0, checked.stderr
        for path in (broker, agent, client):
            processes.append(subprocess.Popen([binary, '--config', path], stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE, text=True)); time.sleep(.3)
        cp = processes[-1]; deadline = time.time() + 15; match = None
        while time.time() < deadline and not match:
            line = cp.stdout.readline()
            match = re.search(r'proxy listening on 127\.0\.0\.1:(\d+)', line)
            if not line and cp.poll() is not None:
                raise AssertionError(f'client exited: {cp.stderr.read()}')
        assert match, 'client proxy was not published'
        proxy = ('127.0.0.1', int(match.group(1)))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as app:
            app.bind(('127.0.0.1', 0)); app.settimeout(3)
            for size in (1, 512, 1400, 16384, 65000):
                payload = os.urandom(size)
                for _ in range(5):
                    app.sendto(payload, proxy)
                    try: data, _ = app.recvfrom(65536)
                    except socket.timeout: continue
                    break
                else:
                    raise AssertionError(f'no micro-mux echo for {size} bytes')
                assert data == payload, f'corrupted {size}-byte datagram'
            # Cross multiple 32-credit boundaries on both sockets. A missing
            # udp_passive rearm would stall after the first window.
            for sequence in range(70):
                payload = sequence.to_bytes(4, 'big') + b'credit-rearm'
                app.sendto(payload, proxy)
                data, _ = app.recvfrom(65536)
                assert data == payload, f'credit rearm/order failed at {sequence}'
        print('Core-Gleam real broker/agent/client micro-mux forwarding passed')
    finally:
        for p in reversed(processes):
            if p.poll() is None: p.terminate()
            try: p.communicate(timeout=2)
            except subprocess.TimeoutExpired: p.kill(); p.communicate(timeout=2)
        echo.close()
