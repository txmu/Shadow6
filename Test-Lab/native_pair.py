"""The full Profile Native trio in A, with its actual Agent target across veth.

Core control/native data sockets remain private in A. The exposed WAN hop is
the Agent application target, explicitly labelled separately from Core wire.
"""
import hashlib
from contextlib import ExitStack
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from artifacts import _read_file
from fingerprint import analyze
from network import NamespacePair, DirectionalImpairment, capabilities
from s6epe import Side, Process, SocketObserver, endpoint_config, flow_ownership
from service_storage import private_read, strict_json

HERE = Path(__file__).resolve().parent

def case(profile, binary, scenario, output, run_id, *, capture_enabled, payload_bytes, requests):
    from shadow6_test_lab import Capture, _worker, _write_json
    row = {'core': profile['core'], 'profile': profile['id'],
        'nativeTransport': profile['nativeTransport'], 'applicationBoundary': profile['applicationBoundary'],
        'scenario': scenario, 'networkKind': 'simulated-directional-veth', 'status': 'FAIL',
        'placement': 'native-agent-application-target-wan',
        'capture': {'status': 'SKIP', 'pcap': None}, 'wireFingerprintScope': 'private Native sockets on inner-A'}
    caps = capabilities()
    if not caps['netnsNetem'] or not caps['namespaceCapture']:
        row.update(status='BLOCKED', reason=caps['reason'] or 'owned namespace tcpdump capability unavailable')
        return row
    destination = Path(output) / 'native-pair' / profile['id'] / scenario
    destination.mkdir(parents=True, exist_ok=True)
    children = []; captures = []; observer = None; impairment = None
    try:
        with NamespacePair() as pair, tempfile.TemporaryDirectory(prefix='s6-native-pair-') as private, ExitStack() as lifecycle:
            private = Path(private)
            a, b = Side(pair, pair.a, 's6tl-a'), Side(pair, pair.b, 's6tl-b')
            message = profile['applicationBoundary']['kind'] == 'message'
            transport = 'udp' if message else 'tcp'
            try:
                impairment = DirectionalImpairment(pair, scenario).start()
                for side, label, kind, host, port, peer in (
                        (b, 'Native-echo-B', 'echo-udp' if message else 'echo-tcp', '198.18.6.2', 18501, 1),
                        (a, 'Native-forward-A', 'forward-record' if message else 'forward-stream',
                         '::1' if profile['core'] == 'hare' else '127.0.0.1', 18502, 18501)):
                    path = private / (label + '.json')
                    config = endpoint_config(path, profile, kind, port, peer, host,
                        namespace_identity=f'net:[{Path("/run/netns", side.name).stat().st_ino}]')
                    process = Process(side, [sys.executable, str(HERE / 'carrier_endpoint.py'), '--config', str(path)], private, label)
                    children.append(process)
                    lifecycle.callback(process.close)
                    event = process.ready('shadow6.lab-carrier-endpoint-ready.v1')
                    if event['port'] != port or event['host'] != host or event['transport'] != transport:
                        raise ValueError('Native target structured endpoint mismatch')
                    if not any(endpoint.get('host') == host and endpoint.get('port') == port for endpoint in process.snapshot()['sockets']):
                        raise ValueError('Native target listener ownership unavailable')
                    if label == 'Native-echo-B': echo_config = config
                for side, location, interface in ((a, 'outer-A', 's6tl-a'), (b, 'outer-B', 's6tl-b'), (a, 'inner-A', 'lo')):
                    capture = Capture(destination / (location + '.pcap'), namespace=side, interface=interface, snaplen=8192)
                    captures.append((location, side, capture))
                    lifecycle.callback(capture.stop)
                    if not capture.start(): raise ValueError(capture.reason or 'Native pair capture unavailable')
                observer = SocketObserver(children).start()
                result = _worker(profile, binary, payload_bytes=payload_bytes,
                    requests=max(requests, 12) if scenario == 'failure-recovery' else requests,
                    namespace=a, timeout=180, rtt_ms=250 if scenario == 'failure-recovery' else 0,
                    on_ready=impairment.workload_ready, target_port=18502)
                observer.close()
                if observer.errors: raise ValueError('Native pair socket observation failed')
                row.update(status=result['status'], correctness=result.get('correctness'), metrics=result.get('metrics'),
                    applicationGame=result.get('applicationGame'),
                    reason=result.get('reason'), runtimeObservation=result.get('runtimeObservation'))
                if result['status'] == 'PASS':
                    namespaces = result['runtimeObservation']
                    expected = f'net:[{Path("/run/netns", pair.a).stat().st_ino}]'
                    if namespaces.get('namespaceIdentity') != expected or not all(
                            child['namespaceIdentity'] == expected for role in namespaces['roles'].values()
                            for child in role['processNamespaces']):
                        raise ValueError('complete Native trio namespace evidence mismatch')
                    echo = strict_json(private_read(echo_config['metrics']))
                    expected_bytes = result['correctness']['bytesSent'] + (result.get('applicationGame') or {}).get('bytesSent', 0)
                    if min(echo['bytesIn'], echo['bytesOut']) != expected_bytes:
                        raise ValueError('Native application bytes did not traverse remote B target')
                    row['targetObservation'] = echo
                impairment.close()
                row['wan'] = impairment.evidence()
                row['effectiveImpairments'] = row['wan']['phases']
                if scenario == 'failure-recovery':
                    row['failureInjection'] = {**row['wan'], 'status': 'applied' if row['wan']['status'] == 'PASS' else 'incomplete'}
                if row['wan']['status'] != 'PASS': raise ValueError('Native directional impairment incomplete')
                row['namespaceLabels'] = {'coreTrio': pair.a, 'applicationTarget': pair.b}
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                row.update(status='FAIL', reason=f'{type(error).__name__}: {error}')
            finally:
                if observer is not None: observer.close()
                if impairment is not None: impairment.close()
                outer = []; inner = []
                for location, side, capture in captures:
                    path = capture.stop()
                    if path is None: continue
                    try:
                        raw = _read_file(path, maximum=4 * 1024 * 1024)
                        metadata = {'schema': 'shadow6.test-lab-capture.v1', 'runId': run_id,
                            'core': profile['core'], 'profile': profile['id'], 'scenario': scenario,
                            'linkType': 'native' if location == 'inner-A' else 'application-target-wan',
                            'placement': location, 'namespace': side.name, 'interface': capture.interface,
                            'startedAtUnix': capture.started_at, 'endedAtUnix': capture.ended_at,
                            'capturePid':capture.capture_pid, 'captureProcessIdentity':capture.process_identity,
                            'captureNamespaceIdentity':capture.namespace_identity,
                            'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'snaplen': 8192}
                        fingerprint = analyze(path, run_id=run_id, core=profile['core'], profile=profile['id'],
                            link_type=metadata['linkType'], scenario=scenario)
                        _write_json(path.with_suffix('.capture.json'), metadata)
                        _write_json(path.with_suffix('.fingerprint.json'), fingerprint)
                        (inner if location == 'inner-A' else outer).append((metadata, fingerprint))
                    except (OSError, ValueError) as error:
                        row.update(status='FAIL', reason='Native capture analysis failed: ' + type(error).__name__)
                if len(outer) == 2 and len(inner) == 1 and all(f['capture']['pcapPackets'] > 0 for _, f in outer + inner):
                    row['capture'] = {'status': 'PASS', 'pcap': str(destination / 'outer-A.pcap'),
                        'dualOuter': [meta for meta, _ in outer], 'innerComparison': [meta for meta, _ in inner],
                        'namespace': pair.a, 'noHostInterfaceCapture': True}
                    row['noBypass'] = flow_ownership(outer[0][1]['flows'], observer.evidence() if observer else [],
                        pair, transport, {'Native-forward-A', 'Native-echo-B'})
                    row['noBypass']['placement'] = 'native-agent-application-target-wan'
                    row['wireClassification'] = inner[0][1]['classification']['observed']
                    row['applicationWanClassification'] = outer[0][1]['classification']['observed']
                    row['leakScan'] = inner[0][1]['leakScan']
                    if row['noBypass']['status'] != 'PASS': row.update(status='FAIL', reason='Native pair outer flow ownership mismatch')
                else:
                    row['capture']['status'] = 'FAIL'
                    if row['status'] == 'PASS': row.update(status='FAIL', reason='Native pair dual outer/inner PCAP missing')
                for child in reversed(children): child.close()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        row.update(status='BLOCKED', reason='owned pair runtime unavailable: ' + type(error).__name__ + ': ' + str(error))
    return row
