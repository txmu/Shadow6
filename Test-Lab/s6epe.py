"""Actual S6EPE endpoints on an owned, directional veth WAN.

Placement is after the real Native Agent application target. The Native trio
stays private in A; only S6EPE carrier peers cross to B. Lab attachments adapt
the explicitly declared application boundary and never parse Core native wire.
"""
from __future__ import annotations
import hashlib
from contextlib import ExitStack
import json
import itertools
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'Deployment'))
sys.path.insert(0, str(ROOT / 'Control-Center'))
from artifacts import sha256_file, _read_file, admit_s6epe_runtime
from network import NamespacePair, SCENARIOS, capabilities, DirectionalImpairment
from fingerprint import analyze
from privacy_envelope import compatibility, feature_availability, read_metrics
from service_storage import private_read, strict_json, atomic_write
from service_runtime import identity, parse_envelope, feature_report
from service_composition import validate_composition, validate_envelope_pair
from runtime_observation import sockets, control_connections
from profile_registry import profiles, profile_digest
from webrtc_broker import SignallingBroker

STAGES = ('sourceLegal', 'nativeArtifact', 'carrierArtifact', 'runtimeReady',
          'correctness', 'WAN', 'PCAP', 'wireClassification', 'leakScan')

class RequirementMissing(RuntimeError): pass

class Side:
    def __init__(self, pair, name, interface):
        if name not in pair.created or interface not in {'s6tl-a', 's6tl-b'}:
            raise ValueError('unowned namespace side')
        self.pair, self.name, self.interface = pair, name, interface
    def exec(self, argv): return self.pair.exec(self.name, argv)

def endpoint_config(path, profile, kind, port, peer=1, host='127.0.0.1', namespace_identity=None):
    value = {'schema': 'shadow6.lab-carrier-attachment.v2', 'core': profile['core'],
        'profile': profile['id'], 'profileDigest': profile_digest(profile), 'kind': kind,
        'host': host, 'port': port, 'peerPort': peer, 'ttl': 240,
        'peerHost': '198.18.6.2' if kind in {'forward-stream', 'forward-record'} else '127.0.0.1',
        'namespaceIdentity': namespace_identity or os.readlink('/proc/self/ns/net'),
        'maxRecord': 8192, 'metrics': str(path.with_suffix('.observation.json'))}
    atomic_write(path, json.dumps(value, allow_nan=False).encode())
    return value

class Process:
    def __init__(self, side, argv, root, label):
        from feature_contract import runtime_environment
        binary = Path(argv[0])
        environment = runtime_environment(binary.parent.parent, binary.relative_to(binary.parent.parent))
        self.out = tempfile.TemporaryFile(); self.err = tempfile.TemporaryFile()
        self.process = subprocess.Popen(side.exec(argv), cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=self.out, stderr=self.err, start_new_session=True, env=environment)
        self.label, self.side = label, side
        self.expected_executable = str(Path(argv[0]).resolve())
        self.initial_identity = identity(self.process.pid)
        self.events = []; self.offset = 0
        if self.initial_identity is None: raise ValueError('endpoint process identity unavailable')
    def poll_events(self):
        self.out.seek(self.offset)
        while True:
            line = self.out.readline(16385)
            if not line: break
            if len(line) > 16384: raise ValueError('endpoint output frame bound')
            if not line.endswith(b'\n'): break
            self.offset += len(line)
            if self.offset > 262144: raise ValueError('endpoint output aggregate bound')
            if line.startswith(b'{'): self.events.append(strict_json(line))
        if len(self.events) > 128: raise ValueError('endpoint event bound')
    def ready(self, expected, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.poll_events()
            matches = [event for event in self.events if event.get('event') == expected]
            if matches:
                event = matches[-1]
                if event.get('pid') != self.process.pid: raise ValueError('ready process identity mismatch')
                self.snapshot()
                return event
            if self.process.poll() is not None:
                raise RuntimeError(self.label + ' exited before structured readiness')
            time.sleep(.05)
        raise TimeoutError(self.label + ' structured readiness deadline')
    def snapshot(self):
        if self.process.poll() is not None or identity(self.process.pid) != self.initial_identity:
            raise ValueError('endpoint exited or process identity changed: ' + self.label)
        executable = os.readlink(f'/proc/{self.process.pid}/exe')
        if executable != self.expected_executable:
            raise ValueError('endpoint executable identity mismatch: ' + self.label)
        endpoint = sockets(self.process.pid)
        peers = control_connections(self.process.pid) + control_connections(self.process.pid, 'udp')
        inodes = []
        descriptors = list(itertools.islice(Path(f'/proc/{self.process.pid}/fd').iterdir(), 4097))
        if len(descriptors) > 4096: raise ValueError('endpoint FD observation bound')
        for fd in descriptors:
            try:
                link = os.readlink(fd)
                if link.startswith('socket:['): inodes.append(link[8:-1])
            except OSError: pass
        if len(inodes) > 4096: raise ValueError('endpoint socket observation bound')
        # One-to-one SCTP associations retain exact local/remote ownership.
        try:
            with Path(f'/proc/{self.process.pid}/net/sctp/assocs').open() as stream:
                table = stream.read(262145)
            if len(table) > 262144: raise ValueError('SCTP observation bound')
            lines = table.splitlines(); header = lines[0].split()
            for line in lines[1:]:
                fields = line.split()
                if fields[header.index('INODE')] not in inodes: continue
                begin = header.index('LADDRS'); divider = fields.index('<->')
                for left in fields[begin:divider]:
                    for right in fields[divider + 1:]:
                        peers.append({'transport': 'sctp', 'host': left,
                            'port': int(fields[header.index('LPORT')]), 'remoteHost': right,
                            'remotePort': int(fields[header.index('RPORT')]),
                            'observation': 'process-owned-sctp-association'})
        except FileNotFoundError: pass
        return {'component': self.label, 'pid': self.process.pid,
            'executable': executable,
            'processIdentity': self.initial_identity, 'namespace': self.side.name,
            'namespaceIdentity': os.readlink(f'/proc/{self.process.pid}/ns/net'),
            'sockets': endpoint, 'peers': peers, 'socketInodes': sorted(inodes)}
    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try: self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=3)
        self.out.close(); self.err.close()

class SocketObserver:
    """Bounded historical socket evidence sampled only from owned children."""
    def __init__(self, processes):
        self.processes = processes; self.samples = {}; self.errors = []
        self.stopping = threading.Event(); self.thread = threading.Thread(target=self._run, daemon=True)
    def start(self): self.thread.start(); return self
    def _run(self):
        while not self.stopping.is_set():
            for process in self.processes:
                try:
                    sample = process.snapshot()
                    entry = self.samples.setdefault(process.label, {**sample, 'sockets': [], 'peers': []})
                    for field in ('sockets', 'peers'):
                        for endpoint in sample[field]:
                            if endpoint not in entry[field]: entry[field].append(endpoint)
                        if len(entry[field]) > 256: raise ValueError('socket evidence aggregate bound')
                except (OSError, ValueError, IndexError) as error:
                    self.errors.append(type(error).__name__); self.stopping.set(); return
            self.stopping.wait(.05)
    def close(self):
        self.stopping.set(); self.thread.join(timeout=3)
    def evidence(self): return list(self.samples.values())

def flow_ownership(flows, ownership, pair, transport, allowed):
    def owned(endpoint, side):
        for owner in ownership:
            if owner['namespace'] != side or owner['component'] not in allowed: continue
            for observed in owner['sockets'] + owner['peers']:
                if observed['transport'] != transport or observed.get('port') != endpoint['port']: continue
                if observed.get('host') in {endpoint['address'], '0.0.0.0', '::'}: return True
        return False
    valid = bool(flows) and all(flow['transport'] == transport and
        flow['endpointA']['address'] == '198.18.6.1' and flow['endpointB']['address'] == '198.18.6.2' and
        owned(flow['endpointA'], pair.a) and owned(flow['endpointB'], pair.b) for flow in flows)
    return {'status': 'PASS' if valid else 'FAIL', 'scope': 'observed application probe flows on owned veth',
        'flows': flows, 'processOwnedSocketSamples': ownership, 'corePrivateSide': pair.a,
        'ownedWanOnly': valid}

class RawCarrier:
    name = 'raw'
    def admit(self, report, runtime):
        if self.mode not in {'stream', 'datagram'}: raise ValueError('raw mode mismatch')
        if 'raw' not in report['carriers'][self.mode]: raise RequirementMissing('raw carrier absent from Feature Report')
    def __init__(self, mode): self.mode = mode
    def material(self, root): return {}
    def echo_kind(self, message):
        return 'echo-udp' if self.mode == 'datagram' else 'echo-record-stream' if message else 'echo-tcp'
    def attachment_kind(self, message):
        if self.mode == 'datagram': return None if message else 'stream-to-datagram'
        return 'record-to-stream' if message else None
    def expected_transport(self): return 'udp' if self.mode == 'datagram' else 'tcp'

class TLSCarrier(RawCarrier):
    name = 'tls'
    def admit(self, report, runtime):
        if self.mode != 'stream': raise ValueError('TLS requires stream mode')
        if 'tls13-mtls' not in report['carriers']['stream']: raise RequirementMissing('TLS1.3 carrier unavailable')
    def material(self, root):
        sys.path.insert(0, str(ROOT / 'OCaml/privacy_envelope/test'))
        from tls_fixtures import identities
        for name, data in identities().items(): atomic_write(root / (name + '.pem'), data)
        return {role: {'tls_cert': str(root / (role + '_cert.pem')),
            'tls_key': str(root / (role + '_key.pem')), 'tls_ca': str(root / 'ca.pem'),
            'tls_peer_name': 'epe-client' if role == 'server' else 'epe-server'} for role in ('server', 'client')}

class SCTPCarrier(RawCarrier):
    name = 'sctp'
    def admit(self, report, runtime):
        from carrier_endpoint import sctp_socket
        if self.mode != 'message': raise ValueError('SCTP requires message mode')
        if 'sctp' not in report['carriers']['message_adapters']: raise RequirementMissing('SCTP provider unavailable')
        try:
            with sctp_socket(): pass
        except OSError as error: raise RequirementMissing('Linux SCTP unavailable: ' + str(error)) from error
    def echo_kind(self, message): return 'echo-sctp'
    def attachment_kind(self, message):
        if message: raise ValueError('SCTP stream facade must not consume a record Core')
        return 'stream-to-sctp'
    def expected_transport(self): return 'sctp'

class WebRTCCarrier(RawCarrier):
    name = 'webrtc'
    def admit(self, report, runtime):
        if self.mode != 'message': raise ValueError('WebRTC requires message mode')
        if 'webrtc' not in report['carriers']['message_adapters']: raise RequirementMissing('WebRTC provider unavailable')
        self.peer = runtime / 'shadow6-lab-webrtc-peer'
        self.peer_digest = 'sha256:' + sha256_file(self.peer)
        self.provider_digest = 'sha256:' + sha256_file(runtime / 'lib/libdatachannel.so.0.23')
        peer = feature_report(str(self.peer), require_core=False)
        if peer != {'schema': 'shadow6.lab-webrtc-peer.v1', 'wire_version': 3,
                    'carrier': 'webrtc', 'provider_available': True}:
            raise RequirementMissing('release WebRTC Lab peer/provider Feature Report mismatch')
    def expected_transport(self): return 'udp'

ADAPTERS = {'raw': RawCarrier, 'tls': TLSCarrier, 'sctp': SCTPCarrier, 'webrtc': WebRTCCarrier}

def accounted_metrics(path, expected, *, timeout=2):
    """Wait for the bounded, periodically published authenticated counters."""
    deadline = time.monotonic() + timeout
    while True:
        telemetry = read_metrics(path)
        if (telemetry['observation'] == 'current' and telemetry['authenticated_sessions'] >= 1
                and min(telemetry['bytes_in'], telemetry['bytes_out']) >= expected):
            return telemetry
        if time.monotonic() >= deadline:
            return telemetry
        time.sleep(.05)

def envelope_config(path, adapter, role, listen, upstream, key, tls=None, signal_path=None):
    value = {'mode': adapter.mode, 'role': role, 'carrier': adapter.name,
        'listen': listen, 'upstream': upstream, 'auth_key': key, 'max_frame': 8192,
        'handshake_timeout': 30, 'idle_timeout': 300, 'session_timeout': 300,
        'max_preauth': 1, 'max_sessions': 1, 'metrics_path': str(path.with_suffix('.metrics.json'))}
    if adapter.mode == 'datagram': value['replay_path'] = str(path.with_suffix('.replay'))
    if adapter.mode == 'message': value.update(message_channels='0:ordered:reliable', sctp_streams=4)
    if tls: value.update(tls)
    if signal_path: value.update(signal_path=str(signal_path), signal_id='lab')
    content = ''.join(f'{k}={v}\n' for k, v in value.items()).encode()
    fields = parse_envelope(content)
    if role == 'server': validate_composition(privacy='envelope', envelope=fields)
    atomic_write(path, content)
    return value

def matrix(availability, by_profile, artifact_root, scenarios, output, run_id, *,
           payload_bytes, requests, execute=True, selected=None):
    installed = {(row['core'], row['profile']): row for row in availability}
    rows = []
    for profile in profiles():
        legal = compatibility(profile['core'])
        for carrier in legal['carriers']:
            row = {'core': profile['core'], 'profile': profile['id'], 'profileDigest': profile_digest(profile),
                'nativeTransport': profile['nativeTransport'], 'applicationBoundary': profile['applicationBoundary'],
                'mode': legal['mode'], 'carrier': carrier, 'legal': True, 'status': 'BLOCKED',
                'placement': 'after-native-agent-application-target',
                'stages': {stage: {'status': 'BLOCKED', 'reason': 'prerequisite has not been admitted'} for stage in STAGES},
                'results': []}
            row['stages']['sourceLegal'] = {'status': 'source-legal', 'authority': 'Control-Center/privacy_envelope.py'}
            native = installed[(profile['core'], profile['id'])]
            row['stages']['nativeArtifact'] = {'status': native['availability'], 'sha256': native.get('artifactSha256')}
            try:
                runtime = Path(artifact_root) / 'runtime-artifacts/shadow6-s6epe-linux-runtime'
                passport = admit_s6epe_runtime(runtime, artifact_root)
                binary = runtime / 'shadow6-privacy-envelope'
                digest = 'sha256:' + sha256_file(binary)
                report = feature_report(str(binary), require_core=False)
                if not feature_availability(report)['available']:
                    raise RequirementMissing('S6EPE release artifact does not implement encrypted wire v3')
                if report.get('structured_readiness') != {'listener': 'shadow6.envelope-listener-ready.v1',
                        'session': 'shadow6.envelope-session-ready.v1'}:
                    raise RequirementMissing('S6EPE release artifact lacks the structured endpoint readiness contract')
                adapter = ADAPTERS[carrier](legal['mode']); adapter.admit(report, runtime)
                row['stages']['carrierArtifact'] = {'status': 'artifact-available', 'sha256': digest,
                    'provenance': passport,
                    'featureReport': report, 'runtimeFiles': ({'peerSha256': adapter.peer_digest,
                        'providerSha256': adapter.provider_digest} if carrier == 'webrtc' else {})}
                if native['availability'] != 'AVAILABLE': raise RequirementMissing(native.get('reason') or 'Core artifact unavailable')
                caps = capabilities()
                if not caps['netnsNetem'] or not caps['namespaceCapture']:
                    raise RequirementMissing(caps['reason'] or 'owned namespace tcpdump capability unavailable')
                if selected is not None and (profile['core'], profile['id']) not in selected:
                    row.update(status='SKIP', reason='explicit operator Profile selection'); rows.append(row); continue
                if not execute:
                    row.update(status='AVAILABLE', reason='read-only preflight; endpoint execution not performed'); rows.append(row); continue
                for scenario in scenarios:
                    row['results'].append(case(profile, by_profile[(profile['core'], profile['id'])][0],
                        binary, adapter, scenario, Path(output), run_id,
                        payload_bytes=payload_bytes, requests=requests, expected_artifact_digest=digest))
                row['status'] = 'FAIL' if any(r['status'] == 'FAIL' for r in row['results']) else 'BLOCKED' if any(
                    r['status'] == 'BLOCKED' for r in row['results']) else 'PASS'
                for stage in STAGES[3:]:
                    evidence = [r['stages'][stage] for r in row['results']]
                    row['stages'][stage] = {'status': 'PASS' if all(e['status'] == 'PASS' for e in evidence) else
                        'FAIL' if any(e['status'] == 'FAIL' for e in evidence) else 'BLOCKED',
                        'scenarioEvidence': [{'scenario': r['scenario'], 'status': r['stages'][stage]['status']} for r in row['results']]}
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                row.update(reason=f'{type(error).__name__}: {error}',
                    action='Supply the same-run S6EPE executable, Lab peer and provider with a valid runtime passport; inspect declared host requirements before retrying. Source legality is not runtime evidence.')
            rows.append(row)
    return rows

def case(profile, core_binary, epe_binary, adapter, scenario, output, run_id, *, payload_bytes, requests, expected_artifact_digest, worker_timeout=180):
    if type(worker_timeout) is not int or not 1 <= worker_timeout <= 180:
        raise ValueError('S6EPE worker timeout outside bounded budget')
    from shadow6_test_lab import Capture, _worker, _write_json
    row = {'scenario': scenario, 'status': 'FAIL', 'networkKind': 'directional-veth-simulated',
        'stages': {stage: {'status': 'BLOCKED', 'reason': 'upstream stage did not complete'} for stage in STAGES[3:]}}
    root_output = output / 's6epe' / profile['id'] / adapter.name / scenario
    root_output.mkdir(parents=True, exist_ok=True)
    processes = []; captures = []; broker = None; impairment = None
    observer = None
    with NamespacePair() as pair, tempfile.TemporaryDirectory(prefix='s6lab-') as private, ExitStack() as lifecycle:
        private = Path(private)
        a, b = Side(pair, pair.a, 's6tl-a'), Side(pair, pair.b, 's6tl-b')
        key = secrets.token_hex(32)
        message = profile['applicationBoundary']['kind'] == 'message'
        def launch(side, argv, label):
            child = Process(side, argv, private, label); processes.append(child)
            lifecycle.callback(child.close)
            return child
        def attachment(side, kind, port, peer=1, host='127.0.0.1', label='attachment'):
            path = private / (label + '.json')
            config = endpoint_config(path, profile, kind, port, peer, host,
                namespace_identity=f'net:[{Path("/run/netns", side.name).stat().st_ino}]')
            child = launch(side, [sys.executable, str(HERE / 'carrier_endpoint.py'), '--config', str(path)], label)
            event = child.ready('shadow6.lab-carrier-endpoint-ready.v1')
            if (event['host'], event['port']) != (host, port): raise ValueError('attachment endpoint readiness mismatch')
            if not any(s['port'] == port and s.get('host') == host for s in child.snapshot()['sockets']):
                raise ValueError('attachment ready listener is not process-owned')
            return config, child
        try:
            if 'sha256:' + sha256_file(epe_binary) != expected_artifact_digest:
                raise ValueError('S6EPE artifact drift before endpoint launch')
            impairment = DirectionalImpairment(pair, scenario).start()
            for side, location, interface in ((a, 'outer-A', 's6tl-a'), (b, 'outer-B', 's6tl-b'),
                    (a, 'inner-A', 'lo'), (b, 'inner-B', 'lo')):
                capture = Capture(root_output / (location + '.pcap'), namespace=side, interface=interface, snaplen=8192)
                captures.append((location, side, capture))
                lifecycle.callback(capture.stop)
                if not capture.start(): raise RequirementMissing(capture.reason or 'bounded capture unavailable')
            material = adapter.material(private)
            host = '::1' if profile['core'] == 'hare' else '127.0.0.1'
            if adapter.name != 'webrtc':
                attachment(b, adapter.echo_kind(message), 18401, label='echo-B')
                server = envelope_config(private / 'server.conf', adapter, 'server', '198.18.6.2:18402',
                    '127.0.0.1:18401', key, material.get('server'))
                server_process = launch(b, [str(epe_binary), '--config', str(private / 'server.conf')], 'S6EPE-B')
                server_process.ready('shadow6.envelope-listener-ready.v1')
                local = f'[{host}]:18403' if ':' in host else f'{host}:18403'
                client = envelope_config(private / 'client.conf', adapter, 'client', local, '198.18.6.2:18402', key, material.get('client'))
                row['pairComposition'] = validate_envelope_pair(parse_envelope(private_read(private / 'client.conf')),
                    parse_envelope(private_read(private / 'server.conf')))
                client_process = launch(a, [str(epe_binary), '--config', str(private / 'client.conf')], 'S6EPE-A')
                client_process.ready('shadow6.envelope-listener-ready.v1')
                kind = adapter.attachment_kind(message)
                if kind:
                    attachment(a, kind, 18404, peer=18403, host=host, label='facade-A')
                    target_port = 18404
                else: target_port = 18403
            else:
                signal_path = private / 'signal.sock'
                broker = SignallingBroker(str(signal_path), 'lab', max_sessions=1).start()
                server = envelope_config(private / 'server.conf', adapter, 'server', '198.18.6.2:18402',
                    '127.0.0.1:18401', key, signal_path=signal_path)
                server_process = launch(b, [str(epe_binary), '--config', str(private / 'server.conf')], 'S6EPE-B')
                until = time.monotonic() + 30; sid = None
                while time.monotonic() < until:
                    with broker.lock:
                        offers = [name for name, value in broker.sessions.items() if value['legs']['E']['offer']]
                    if len(offers) == 1: sid = offers[0]; break
                    if server_process.process.poll() is not None: raise RuntimeError('WebRTC server exited during S6SG1 startup')
                    time.sleep(.02)
                if sid is None: raise TimeoutError('fresh S6SG1 session offer unavailable')
                for side, leg, address in ((b, 'native', '127.0.0.1'), (a, 'outer', '198.18.6.1')):
                    path = private / (leg + '.conf')
                    envelope_config(path, adapter, 'server', address + ':18402', '127.0.0.1:18403', key, signal_path=signal_path)
                    launch(side, [str(adapter.peer), '--config', str(path), '--leg', leg, '--session-id', sid],
                        'WebRTC-' + leg)
                for peer in processes[-2:]:
                    event = peer.ready('shadow6.lab-webrtc-peer-ready.v1')
                    if event.get('dataChannelReady') is not True: raise ValueError('DataChannel not ready')
                ready = server_process.ready('shadow6.envelope-session-ready.v1')
                if ready.get('sessionId') != sid or ready.get('authenticated') is not True:
                    raise ValueError('WebRTC authenticated session binding mismatch')
                target_port = 18403
            before = [process.snapshot() for process in processes]
            materials = {path.name: 'sha256:' + hashlib.sha256(private_read(path)).hexdigest()
                for path in private.iterdir() if path.suffix in {'.conf', '.pem', '.json'} and not path.name.endswith('.observation.json')
                and not path.name.endswith('.metrics.json')}
            row['runtimeMaterialDigests'] = materials
            row['artifactSha256'] = expected_artifact_digest
            row['stages']['runtimeReady'] = {'status': 'listener-ready', 'observations': before,
                'composition': ['Core private native trio', 'typed Agent target attachment', 'S6EPE', 'veth WAN', 'S6EPE', 'echo'],
                'placement': 'after-native-agent-application-target', 'productionAdapterClaim': False}
            observer = SocketObserver(processes).start()
            result = _worker(profile, core_binary, payload_bytes=payload_bytes,
                requests=max(requests, 12) if scenario == 'failure-recovery' else requests,
                namespace=a, timeout=worker_timeout, rtt_ms=250 if scenario == 'failure-recovery' else 0,
                on_ready=impairment.workload_ready, target_port=target_port)
            observer.close()
            row['coreRuntimeObservation'] = result.get('runtimeObservation')
            row['probeFailures'] = result.get('probeFailures', [])
            row['workerDiagnostics'] = result.get('workerDiagnostics')
            row['applicationGame'] = result.get('applicationGame')
            row['stages']['correctness'] = result.get('correctness') or {'status': result['status'], 'reason': result.get('reason')}
            row['metrics'] = result.get('metrics')
            if result['status'] != 'PASS': raise RuntimeError(result.get('reason') or 'Core application correctness failed')
            if observer.errors: raise ValueError('owned endpoint socket observation failed: ' + ','.join(observer.errors))
            after = [process.snapshot() for process in processes]
            if 'sha256:' + sha256_file(epe_binary) != expected_artifact_digest:
                raise ValueError('S6EPE artifact drift during application probe')
            for name, digest in materials.items():
                if 'sha256:' + hashlib.sha256(private_read(private / name)).hexdigest() != digest:
                    raise ValueError('endpoint configuration/TLS material drift during application probe')
            if adapter.name == 'webrtc' and ('sha256:' + sha256_file(adapter.peer) != adapter.peer_digest or
                    'sha256:' + sha256_file(adapter.peer.parent / 'lib/libdatachannel.so.0.23') != adapter.provider_digest):
                raise ValueError('WebRTC peer/provider material drift')
            expected = row['stages']['correctness']['bytesSent'] + (row.get('applicationGame') or {}).get('bytesSent', 0)
            telemetry = accounted_metrics(server['metrics_path'], expected)
            if telemetry['observation'] != 'current' or telemetry['authenticated_sessions'] < 1:
                raise ValueError('fresh authenticated S6EPE metrics unavailable')
            if adapter.name == 'webrtc' and (telemetry.get('active_sessions', 0) < 1 or
                    not any(s['transport'] == 'udp' for s in server_process.snapshot()['sockets'])):
                raise ValueError('fresh active authenticated WebRTC session/owned UDP socket unavailable')
            if min(telemetry['bytes_in'], telemetry['bytes_out']) < expected:
                raise ValueError('S6EPE application byte accounting does not cover Core probe')
            row['endpointOwnership'] = after; row['privacyTelemetry'] = telemetry
            row['stages']['runtimeReady']['status'] = 'PASS'
            row['stages']['runtimeReady']['authenticatedSession'] = telemetry
            row['stages']['runtimeReady']['coreRuntimeObservationRef'] = 'coreRuntimeObservation'
            impairment.close()
            if impairment.evidence()['status'] != 'PASS':
                raise ValueError('directional impairment phase not applied')
            row['stages']['WAN'] = impairment.evidence()
            row['status'] = 'PASS'
        except RequirementMissing as error: row.update(status='BLOCKED', reason=str(error))
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            row.update(status='FAIL', reason=f'{type(error).__name__}: {error}')
        finally:
            if observer is not None: observer.close()
            if impairment is not None: impairment.close()
            outer = []; inner = []; ownership = observer.evidence() if observer is not None else []
            for location, side, capture in captures:
                path = capture.stop()
                if path is None: continue
                try:
                    raw = _read_file(path, maximum=4 * 1024 * 1024)
                    metadata = {'schema': 'shadow6.test-lab-capture.v1', 'runId': run_id,
                        'core': profile['core'], 'profile': profile['id'], 'carrier': adapter.name,
                        'scenario': scenario, 'linkType': 'carrier' if location.startswith('outer') else 'native',
                        'placement': location, 'namespace': side.name, 'interface': capture.interface,
                        'startedAtUnix': capture.started_at, 'endedAtUnix': capture.ended_at,
                        'capturePid':capture.capture_pid, 'captureProcessIdentity':capture.process_identity,
                        'captureNamespaceIdentity':capture.namespace_identity,
                        'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'snaplen': 8192}
                    _write_json(path.with_suffix('.capture.json'), metadata)
                    fingerprint = analyze(path, run_id=run_id, core=profile['core'], profile=profile['id'],
                        link_type=metadata['linkType'], scenario=scenario,
                        forbidden_literals=[key.encode(), bytes(range(32))] if location.startswith('outer') else [])
                    _write_json(path.with_suffix('.fingerprint.json'), fingerprint)
                    if location.startswith('outer'): outer.append({'metadata': metadata, 'fingerprint': fingerprint})
                    else: inner.append({'metadata': metadata, 'fingerprint': fingerprint})
                except (OSError, ValueError) as error:
                    row.update(status='FAIL', reason='PCAP evidence invalid: ' + type(error).__name__)
            row['stages']['PCAP'] = {'status': 'PASS' if len(outer) == 2 and len(inner) == 2 and all(
                item['fingerprint']['capture']['pcapPackets'] > 0 for item in outer) else 'FAIL',
                'evidence': [item['metadata'] for item in outer], 'innerComparison': [item['metadata'] for item in inner]}
            if outer:
                row['stages']['wireClassification'] = {'status': 'PASS', 'observed': sorted(set(
                    label for item in outer for label in item['fingerprint']['classification']['observed'])),
                    'dataChannelRuntimeObserved': adapter.name == 'webrtc' and row['stages']['runtimeReady']['status'] == 'PASS',
                    'dpiResistanceInferred': False}
                hits = [literal for item in outer for literal in item['fingerprint']['leakScan']['forbiddenLiterals'] if literal['hit']]
                row['stages']['leakScan'] = {'status': 'FAIL' if hits else 'PASS',
                    'evidence': [item['fingerprint']['leakScan'] for item in outer], 'literalValuesRedacted': True}
                if hits: row.update(status='FAIL', reason='forbidden application/key literal observed on outer carrier')
                # Both ends of every observed WAN flow must belong to actual
                # carrier processes sampled during the application probe.
                flows = [flow for flow in outer[0]['fingerprint']['flows']]
                row['noBypass'] = flow_ownership(flows, ownership, pair, adapter.expected_transport(),
                    {'S6EPE-A', 'S6EPE-B', 'WebRTC-outer'})
                row['noBypass']['carrierOnlyWan'] = row['noBypass']['status'] == 'PASS'
                if row['noBypass']['status'] != 'PASS':
                    row.update(status='FAIL', reason='outer flow ownership/placement does not prove no bypass')
                wire = row['stages']['wireClassification']['observed']
                if adapter.name == 'tls' and 'tls-record-observed' not in wire:
                    row.update(status='FAIL', reason='TLS carrier PCAP contains no observable TLS record')
                    row['stages']['wireClassification']['status'] = 'FAIL'
                if adapter.name == 'webrtc' and 'dtls-record-observed' not in wire:
                    row.update(status='FAIL', reason='WebRTC carrier PCAP contains no observable DTLS record')
                    row['stages']['wireClassification']['status'] = 'FAIL'
            if row['stages']['PCAP']['status'] != 'PASS' and row['status'] == 'PASS':
                row.update(status='FAIL', reason='dual outer PCAP evidence unavailable')
            diagnostics = {}
            for process in reversed(processes):
                process.err.seek(0, os.SEEK_END)
                process.err.seek(max(0, process.err.tell() - 4096))
                diagnostic = process.err.read(4096).decode('utf-8', 'replace')
                if diagnostic: diagnostics[process.label] = diagnostic
                process.close()
            if diagnostics:
                _write_json(root_output / 'endpoint-diagnostics.json', diagnostics)
                row['endpointDiagnostics'] = diagnostics
            if broker: broker.close()
    return row
