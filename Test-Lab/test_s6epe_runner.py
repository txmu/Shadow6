"""Trust, actual attachment I/O, matrix and owned directional network tests."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import tarfile
import hashlib
import unittest
import time
import threading
from unittest.mock import patch
import artifacts

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from carrier_endpoint import configuration, exact, sctp_socket, sctp_send, sctp_receive, forward_records
from s6epe import endpoint_config, matrix, RawCarrier, TLSCarrier, SCTPCarrier, WebRTCCarrier, flow_ownership, accounted_metrics
from network import NamespacePair, capabilities, DirectionalImpairment, SCENARIOS
from shadow6_test_lab import Capture
from profile_registry import profiles, select_profile
from service_storage import private_read, strict_json
from Deployment.service_composition import validate_envelope_pair

def free_port():
    with socket.socket() as connection:
        connection.bind(('127.0.0.1', 0)); return connection.getsockname()[1]

class AttachmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='s6lab-tests-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
    def test_forward_records_pipelines_delayed_replies(self):
        stopping = threading.Event()
        counted, errors = [], []
        with socket.socket(type=socket.SOCK_DGRAM) as listener, \
             socket.socket(type=socket.SOCK_DGRAM) as upstream, \
             socket.socket(type=socket.SOCK_DGRAM) as remote, \
             socket.socket(type=socket.SOCK_DGRAM) as client:
            for connection in (listener, remote, client):
                connection.bind(('127.0.0.1', 0))
                connection.settimeout(2)
            upstream.connect(remote.getsockname())
            def relay():
                try:
                    forward_records(listener, upstream, limit=512,
                        deadline=time.monotonic() + 5, stopping=stopping, count=counted.append)
                except Exception as error: errors.append(error)
            thread = threading.Thread(target=relay)
            thread.start()
            try:
                payloads = [b'first', b'', b'last']
                for payload in payloads: client.sendto(payload, listener.getsockname())
                # The remote receives the whole burst before releasing any echo.
                arrivals = [remote.recvfrom(513) for _ in payloads]
                self.assertEqual([data for data, _ in arrivals], payloads)
                for data, address in reversed(arrivals): remote.sendto(data, address)
                self.assertEqual([client.recv(513) for _ in payloads], list(reversed(payloads)))
            finally:
                stopping.set(); thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(counted, list(reversed(payloads)))
    def launch(self, profile, kind, port, peer=1):
        path = self.root / (kind + '.json')
        value = endpoint_config(path, profile, kind, port, peer)
        process = subprocess.Popen([sys.executable, str(HERE / 'carrier_endpoint.py'), '--config', str(path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def close():
            process.terminate()
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=3)
            process.stdout.close(); process.stderr.close()
        self.addCleanup(close)
        event = strict_json(process.stdout.readline(16385))
        self.assertEqual(event['event'], 'shadow6.lab-carrier-endpoint-ready.v1')
        self.assertEqual(event['pid'], process.pid)
        self.assertTrue(event['processIdentity'])
        return value
    def test_stream_datagram_attachment_real_4096_byte_echo_and_metrics(self):
        profile = select_profile('go', 'go-kcp')
        peer, local = free_port(), free_port()
        self.launch(profile, 'echo-udp', peer)
        value = self.launch(profile, 'stream-to-datagram', local, peer)
        payload = bytes(range(256)) * 16
        with socket.create_connection(('127.0.0.1', local), timeout=3) as connection:
            connection.settimeout(3); connection.sendall(payload)
            self.assertEqual(exact(connection, len(payload)), payload)
        # Receiving the echo precedes the worker's atomic metrics publication.
        # Wait for evidence, not a scheduler-dependent fixed sleep.
        deadline = time.monotonic() + 3
        while True:
            observation = strict_json(private_read(value['metrics']))
            if observation['bytesOut'] >= len(payload) or time.monotonic() >= deadline:
                break
            time.sleep(.01)
        self.assertEqual((observation['bytesIn'], observation['bytesOut'], observation['failures']), (4096, 4096, 0))
    def test_record_stream_attachment_preserves_distinct_empty_and_nonempty_records(self):
        profile = select_profile('gleam', 'gleam-micro-mux')
        peer, local = free_port(), free_port()
        self.launch(profile, 'echo-record-stream', peer)
        self.launch(profile, 'record-to-stream', local, peer)
        with socket.socket(type=socket.SOCK_DGRAM) as connection:
            connection.settimeout(3)
            for payload in (b'', b'first', bytes(range(256)) * 2, b'last'):
                connection.sendto(payload, ('127.0.0.1', local))
                self.assertEqual(connection.recv(8192), payload)
    def test_real_kernel_sctp_keeps_message_and_metadata(self):
        try: probe = sctp_socket(); probe.close()
        except OSError as error: self.skipTest('Linux SCTP unavailable: ' + str(error))
        profile = select_profile('cpp', 'cpp-sctp-tls13')
        port = free_port(); self.launch(profile, 'echo-sctp', port)
        with sctp_socket() as connection:
            connection.settimeout(3); connection.connect(('127.0.0.1', port))
            for payload in (b'first', bytes(range(256)) * 16, b'last'):
                sctp_send(connection, payload)
                self.assertEqual(sctp_receive(connection, 8192), payload)
    def test_contract_drift_unknown_field_and_wrong_boundary_fail_closed(self):
        profile = select_profile('pony', 'pony-udp')
        path = self.root / 'config.json'
        value = endpoint_config(path, profile, 'record-to-stream', 18001)
        self.assertEqual(configuration(json.dumps(value).encode())['profile'], 'pony-udp')
        for patch in ({'profileDigest': 'sha256:' + '0' * 64}, {'unknown': True},
                      {'kind': 'stream-to-datagram'}, {'host': '0.0.0.0'}, {'ttl': True}):
            with self.assertRaises(ValueError): configuration(json.dumps({**value, **patch}).encode())

class CarrierMatrixTests(unittest.TestCase):
    def test_accounting_waits_for_publication_without_accepting_short_counts(self):
        stale = {'observation': 'current', 'authenticated_sessions': 1, 'bytes_in': 100, 'bytes_out': 50}
        complete = {**stale, 'bytes_out': 100}
        with patch('s6epe.read_metrics', side_effect=[stale, complete]) as reader, \
             patch('s6epe.time.sleep'):
            self.assertEqual(accounted_metrics('/unused', 100), complete)
            self.assertEqual(reader.call_count, 2)
        with patch('s6epe.read_metrics', return_value=stale):
            self.assertEqual(accounted_metrics('/unused', 100, timeout=0), stale)
    def test_idris_existing_release_fasl_uses_verified_companion_modes_without_byte_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); staged = root / 'producer'; core = root / 'Core-Idris'; companion = root / 'companion'
            companion.mkdir()
            payloads = {'shadow6-idris': b'fixture launcher', 'shadow6-idris_app/shadow6-idris.so': b'fixture executable Chez image'}
            checksums = hashlib.sha256(b'').hexdigest() + '  SHA256SUMS\n'
            for relative, payload in payloads.items():
                path = staged / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(payload); path.chmod(0o755)
                target = core / relative; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(payload); target.chmod(0o644)
                checksums += hashlib.sha256(payload).hexdigest() + '  ' + relative + '\n'
            (staged / 'SHA256SUMS').write_text(checksums); (staged / 'SHA256SUMS').chmod(0o644)
            with tarfile.open(companion / 'core-idris-runtime.tar.gz', 'w:gz') as archive:
                for path in staged.rglob('*'):
                    if path.is_file(): archive.add(path, arcname=str(path.relative_to(staged)))
            (companion / 'core-idris-runtime.tar.gz').chmod(0o644)
            self.assertEqual(artifacts.merge_runtime_companions(root, idris_artifact=companion, s6epe_artifact=None), [])
            for relative, payload in payloads.items():
                self.assertEqual((core / relative).read_bytes(), payload)
                self.assertEqual((core / relative).stat().st_mode & 0o777, 0o755)
            (core / 'shadow6-idris_app/shadow6-idris.so').write_bytes(b'tampered')
            with self.assertRaises(ValueError): artifacts.merge_runtime_companions(root, idris_artifact=companion, s6epe_artifact=None)

    def test_idris_portable_header_requires_the_exact_verified_companion_body(self):
        original = b'#!/home/linuxbrew/.linuxbrew/bin/chez --program\nverified-fasl-body'
        portable = b'#!/usr/bin/env -S chezscheme --program\nverified-fasl-body'
        for replacement in (portable, portable.replace(b'body', b'evil'),
                            portable.replace(b'chezscheme', b'other-tool')):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); staged = root / 'producer'; companion = root / 'companion'
                companion.mkdir()
                relative = Path('shadow6-idris_app/shadow6-idris.so')
                source = staged / relative; source.parent.mkdir(parents=True)
                source.write_bytes(original); source.chmod(0o755)
                (staged / 'SHA256SUMS').write_text(hashlib.sha256(original).hexdigest() + '  ' + relative.as_posix() + '\n')
                (staged / 'SHA256SUMS').chmod(0o644)
                target = root / 'Core-Idris' / relative; target.parent.mkdir(parents=True)
                target.write_bytes(replacement); target.chmod(0o644)
                with tarfile.open(companion / 'core-idris-runtime.tar.gz', 'w:gz') as archive:
                    archive.add(staged / 'SHA256SUMS', arcname='SHA256SUMS')
                    archive.add(source, arcname=relative.as_posix())
                if replacement == portable:
                    self.assertEqual(artifacts.merge_runtime_companions(root,
                        idris_artifact=companion, s6epe_artifact=None), [])
                    self.assertEqual(target.read_bytes(), replacement)
                    self.assertEqual(target.stat().st_mode & 0o777, 0o755)
                else:
                    with self.assertRaisesRegex(ValueError, 'differs'):
                        artifacts.merge_runtime_companions(root, idris_artifact=companion, s6epe_artifact=None)

    def test_component_passport_binds_same_run_and_restores_only_actions_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); runtime = root / 'runtime'
            for relative in artifacts.expected_files():
                file = root / relative; file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b'unit-test-core'); file.chmod(0o755)
            artifacts.write_manifest(root, root / artifacts.MANIFEST, commit='a' * 40, run_id='314', run_attempt='1')
            for relative in artifacts.S6EPE_RUNTIME_FILES:
                file = runtime / relative; file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b'unit-test-component'); file.chmod(0o755)
            passport = artifacts.write_s6epe_manifest(runtime, commit='a' * 40, run_id='314', run_attempt='1', architecture=os.uname().machine)
            for relative in artifacts.S6EPE_RUNTIME_FILES: (runtime / relative).chmod(0o644)
            self.assertEqual(artifacts.admit_s6epe_runtime(runtime, root)['runId'], '314')
            self.assertTrue(all((runtime / relative).stat().st_mode & 0o777 == 0o755 for relative in artifacts.S6EPE_RUNTIME_FILES))
            original = json.dumps(passport)
            for patch in ({'runId': '315'}, {'commit': 'b' * 40}, {'runAttempt': '2'}, {'unknown': True}):
                (runtime / artifacts.S6EPE_MANIFEST).write_text(json.dumps({**passport, **patch}))
                with self.assertRaises(ValueError): artifacts.admit_s6epe_runtime(runtime, root)
            (runtime / artifacts.S6EPE_MANIFEST).write_text(original)
            (runtime / artifacts.S6EPE_RUNTIME_FILES[0]).write_bytes(b'tampered')
            with self.assertRaises(ValueError): artifacts.admit_s6epe_runtime(runtime, root)

    def test_no_bypass_requires_both_owned_flow_endpoints_and_exact_network_side(self):
        pair = NamespacePair(); pair.created = [pair.a, pair.b]
        flows = [{'transport': 'udp', 'endpointA': {'address': '198.18.6.1', 'port': 1234},
                  'endpointB': {'address': '198.18.6.2', 'port': 4321}}]
        samples = [{'namespace': side, 'component': 'carrier', 'sockets': [{'transport': 'udp', 'host': host, 'port': port}], 'peers': []}
            for side, host, port in ((pair.a, '198.18.6.1', 1234), (pair.b, '198.18.6.2', 4321))]
        self.assertEqual(flow_ownership(flows, samples, pair, 'udp', {'carrier'})['status'], 'PASS')
        self.assertEqual(flow_ownership(flows, samples[:1], pair, 'udp', {'carrier'})['status'], 'FAIL')
        self.assertEqual(flow_ownership(flows, samples, pair, 'tcp', {'carrier'})['status'], 'FAIL')
        self.assertEqual(flow_ownership(flows, samples, pair, 'udp', {'other-process'})['status'], 'FAIL')
    def test_failure_recovery_metadata_matches_its_latency_only_authority(self):
        spec = SCENARIOS['failure-recovery']
        self.assertFalse(any(phase[direction].get('loss_percent', 0) for phase in spec['phases'] for direction in ('a_to_b', 'b_to_a')))
        pair = NamespacePair(); impairment = DirectionalImpairment(pair, 'failure-recovery')
        self.assertEqual(impairment.evidence()['requestedPhases'][1], 'bounded increased delay')

    def test_kernel_uint64_measurements_are_portable_strings_without_weakening_control_json(self):
        body = b'{"seed":18446744073709551615,"delay":0.001}'
        with self.assertRaises(ValueError): strict_json(body, allow_measurement_floats=True)
        self.assertEqual(strict_json(body, allow_measurement_floats=True,
            uint64_measurements_as_strings=True), {'seed': '18446744073709551615', 'delay': .001})
        for body in (b'{"seed":18446744073709551616}', b'{"seed":1,"seed":2}', b'{"seed":NaN}'):
            with self.assertRaises(ValueError): strict_json(body, allow_measurement_floats=True,
                uint64_measurements_as_strings=True)
    def test_missing_release_component_keeps_every_legal_combination_blocked(self):
        availability = [{'core': p['core'], 'profile': p['id'], 'availability': 'AVAILABLE',
                         'artifactSha256': 'sha256:' + 'a' * 64} for p in profiles()]
        with tempfile.TemporaryDirectory() as root:
            result = matrix(availability, {}, root, ['clean'], Path(root), 'fixture', payload_bytes=4096, requests=2)
        self.assertEqual(len(result), 16)
        self.assertEqual({r['status'] for r in result}, {'BLOCKED'})
        self.assertEqual(len({(r['core'], r['profile'], r['carrier']) for r in result}), 16)
        self.assertEqual({r['carrier'] for r in result}, {'raw', 'tls', 'sctp', 'webrtc'})
        self.assertTrue(all(r['reason'] and r['stages']['sourceLegal']['status'] == 'source-legal' for r in result))
    def test_carrier_adapters_are_distinct_and_reject_mode_substitution(self):
        self.assertEqual(len({RawCarrier, TLSCarrier, SCTPCarrier, WebRTCCarrier}), 4)
        for adapter in (RawCarrier('message'), TLSCarrier('datagram'), SCTPCarrier('stream'), WebRTCCarrier('stream')):
            with self.assertRaises(ValueError): adapter.admit({}, Path('/unused'))
    def test_pair_contract_rejects_drift_and_public_native_side(self):
        client = {'role': 'client', 'mode': 'datagram', 'carrier': 'raw',
                  'listen': '127.0.0.1:18001', 'upstream': '198.18.6.2:18002'}
        server = {'role': 'server', 'mode': 'datagram', 'carrier': 'raw',
                  'listen': '198.18.6.2:18002', 'upstream': '127.0.0.1:18003'}
        self.assertFalse(validate_envelope_pair(client, server)['runtimeCapabilityClaim'])
        for patch in ({'carrier': 'tls'}, {'listen': '0.0.0.0:18001'}, {'upstream': '198.18.6.2:18004'}):
            with self.assertRaises(ValueError): validate_envelope_pair({**client, **patch}, server)
    def test_host_capture_is_rejected_even_for_a_small_file(self):
        with self.assertRaises(ValueError): Capture(Path('/tmp/unused.pcap'), namespace=None)

class DirectionalKernelTests(unittest.TestCase):
    def test_owned_pair_clean_and_directional_netem_are_observed_and_cleaned(self):
        caps = capabilities()
        if not caps['netnsNetem']: self.skipTest(caps['reason'])
        original = os.readlink('/proc/self/ns/net')
        with NamespacePair() as pair:
            pair.apply({}, {})
            clean = pair.observe(); self.assertEqual(set(clean), {'aToB', 'bToA'})
            pair.apply({'latency_ms': 1, 'jitter_ms': 1}, {'latency_ms': 7, 'rate_kbit': 1024, 'queue_limit': 100})
            observed = pair.observe()
            self.assertNotEqual(observed['aToB'], observed['bToA'])
            names = [pair.a, pair.b]
        self.assertEqual(os.readlink('/proc/self/ns/net'), original)
        for name in names: self.assertFalse(Path('/run/netns', name).exists())

if __name__ == '__main__': unittest.main()
