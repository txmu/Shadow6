"""Isolated subprocess entry point; invokes the repository's real native runner."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import socket
import signal
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Deployment"))
sys.path.insert(0, str(ROOT / "integration"))
sys.path.insert(0, str(ROOT / "Crosed"))
sys.path.insert(0, str(ROOT / "Control-Center"))
from profile_registry import select_profile
from core_catalog import CoreCatalog
from service_registry import ServiceRegistry
from service_storage import atomic_write
from protocol_context import minimal_context
from connection_plan import open_local_session


def named_workload(profile, binary, payload_bytes, requests, rtt_ms, target_port=None):
    """Use the same locked supervisor and attachment path as deployed services."""
    import stack_test
    from native_configs import generate_commands
    engine = 'shadow6-' + profile['benchmarkAlias']
    stack_test.CORE_BINARIES[engine] = binary
    family = socket.AF_INET6 if profile['core'] == 'hare' else socket.AF_INET
    message = profile['applicationBoundary']['kind'] == 'message'
    target = stack_test.DatagramEchoTarget(family) if message else stack_test.EchoTarget()
    if target_port is not None:
        if type(target_port) is not int or not 1 <= target_port <= 65535:
            raise ValueError('invalid owned carrier attachment port')
        class OwnedCarrierTarget:
            def start(self): return target_port
            def close(self): pass
        target = OwnedCarrierTarget()
    payload = bytes(index % 251 for index in range(payload_bytes))
    with tempfile.TemporaryDirectory(prefix='shadow6-lab-named-') as directory:
        directory = Path(directory)
        catalog = CoreCatalog(binary.parents[1], descriptor_path=directory / 'cores.json')
        registry = ServiceRegistry(directory / 'services.json', catalog)
        names = {role: 'lab/' + role for role in profile['roles']}
        created = []
        try:
            target_port = target.start()
            output = directory / 'configs'
            if profile['realization']['launcher'] == 'native-files':
                documents = {}
                generate_commands(engine, binary, output, target_port, normalized_documents=documents)
                configs = {}
                for role, document in documents.items():
                    configs[role] = output / (role + '.json')
                    atomic_write(configs[role], json.dumps(document, allow_nan=False).encode())
            else:
                asyncio.run(stack_test.generate_configs(engine, output, target_port, stack_test.free_port()))
                configs = {role: output / (role + '.json' if profile['core'] == 'cpp'
                    else 'it-' + engine + '-' + role + '.json') for role in profile['roles']}
            for role in ('broker', 'agent', 'client'):
                context = minimal_context(profile['core'])
                context['role'] = role
                registry.setup(names[role], core=profile['core'], profile=profile['id'],
                    config={'config_path': str(configs[role])}, context=context)
                created.append(names[role])
                registry.run(names[role])
            deadline = time.monotonic() + 30
            while True:
                current = {role: registry.status(name) for role, name in names.items()}
                if any(item['state'] in {'failed', 'stale', 'exited'} for item in current.values()):
                    raise ValueError('Named Core lifecycle failed before application readiness')
                if (all(item['state'] == 'running' for item in current.values()) and
                        current['client'].get('runtime', {}).get('readiness') == 'application-ready'):
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError('Named Core structured/owned ApplicationBoundary readiness timeout')
                time.sleep(0.1)
            evidence = {}
            for role, item in current.items():
                if item['profileBinding']['profile'] != profile['id'] or not item.get('runtimeObservation'):
                    raise ValueError('Named Core Profile binding or RuntimeObservation unavailable')
                evidence[role] = {'profileBinding': item['profileBinding'],
                    'deploymentLockDigest': item['deploymentLock']['digest'],
                    'runtimeObservation': item['runtimeObservation'],
                    'processNamespaces': [{'pid': child['pid'], 'processIdentity': child['processIdentity'],
                        'namespaceIdentity': os.readlink(f"/proc/{child['pid']}/ns/net")}
                        for child in item['runtimeObservation']['processes']]}
                if any(child['namespaceIdentity'] != os.readlink('/proc/self/ns/net')
                        for child in evidence[role]['processNamespaces']):
                    raise ValueError('Native Core child escaped its owned workload namespace')
            print(json.dumps({'event': 'shadow6.test-lab-workload-ready.v1',
                'core': profile['core'], 'profile': profile['id']}, allow_nan=False), flush=True)
            latencies = []
            sent = received_count = 0
            received_digest = None
            record_bytes = min(payload_bytes, profile['applicationBoundary'].get('max_record', payload_bytes), 512) if message else payload_bytes
            started = time.monotonic()
            with open_local_session(registry.connect(names['client'], core=profile['core'])) as session:
                session.socket.settimeout(10)
                for _ in range(requests):
                    request_started = time.monotonic()
                    echoed = bytearray()
                    for offset in range(0, payload_bytes, record_bytes):
                        part = payload[offset:offset + record_bytes]
                        if message:
                            session.send_record(part)
                            reply = session.receive_record()
                        else:
                            session.send(part)
                            reply = bytearray()
                            while len(reply) < len(part):
                                chunk = session.receive(len(part) - len(reply))
                                if not chunk: raise EOFError('application echo ended early')
                                reply.extend(chunk)
                            reply = bytes(reply)
                        if reply != part: raise ValueError('exact application record/stream mismatch')
                        sent += len(part)
                        received_count += len(reply)
                        echoed.extend(reply)
                    if len(echoed) != payload_bytes or bytes(echoed) != payload:
                        raise ValueError('exact logical application echo mismatch')
                    received_digest = hashlib.sha256(echoed).hexdigest()
                    latencies.append(time.monotonic() - request_started)
                    if rtt_ms: time.sleep(rtt_ms / 1000)
                # Check while the attachment is still open. Closing a declared
                # one-flow/record attachment can legitimately drain and stop
                # its Core; that must not be mistaken for mid-probe PID drift.
                observation_deadline = time.monotonic() + 3
                while True:
                    final = {role: registry.status(name) for role, name in names.items()}
                    for role, item in final.items():
                        if (item['state'] in {'stale', 'failed', 'exited'} or
                                item.get('deploymentLock', {}).get('digest') != evidence[role]['deploymentLockDigest'] or
                                item.get('runtime', {}).get('processIdentity') != current[role]['runtime']['processIdentity']):
                            raise ValueError('Named Core identity/material changed during probe: ' + role + '/' + item['state'])
                    if all(item['state'] == 'running' and item.get('runtimeObservation') for item in final.values()):
                        break
                    # Socket transitions can invalidate an old 200 ms sample.
                    # Require a new authoritative sample; never reuse the old one.
                    if time.monotonic() >= observation_deadline:
                        raise ValueError('Named Core health observation unavailable during probe: '
                            + json.dumps({role: {'state': item['state'], 'diagnostic': item.get('runtimeDiagnostic')}
                                          for role, item in final.items()}, sort_keys=True))
                    time.sleep(0.1)
                for role, item in final.items():
                    evidence[role]['runtimeObservation'] = item['runtimeObservation']
                duration = time.monotonic() - started
            result = stack_test.benchmark_metrics(payload, latencies, duration)
            result.update(bytes_sent=sent, bytes_received=received_count,
                exact_echo={'payload_sha256': hashlib.sha256(payload).hexdigest(),
                    'received_sha256': received_digest, 'byte_for_byte': True,
                    'verified_requests': len(latencies), 'record_bytes': record_bytes},
                runtime_observation={'status': 'observed', 'scope': 'during-application-probe',
                    'retainedLiveCapability': False, 'roles': evidence,
                    'namespaceIdentity': os.readlink('/proc/self/ns/net')},
                pacing_ms=rtt_ms)
            return result
        finally:
            errors = []
            for name in reversed(created):
                try: registry.stop(name)
                except (ValueError, OSError) as error: errors.append(type(error).__name__)
            target.close()
            if errors: raise RuntimeError('Named Core cleanup failed: ' + ','.join(errors))


def run(core: str, profile_id: str, binary: Path, payload_bytes: int, requests: int, rtt_ms: int, target_port=None):
    profile = select_profile(core, profile_id)
    if type(payload_bytes) is not int or not 1 <= payload_bytes <= 65536:
        raise ValueError("payload-bytes must be 1..65536")
    if type(requests) is not int or not 1 <= requests <= 100:
        raise ValueError("requests must be 1..100")
    if not binary.is_file() or binary.is_symlink():
        raise FileNotFoundError("registered Core artifact is not a regular file")
    if type(rtt_ms) is not int or not 0 <= rtt_ms <= 250:
        raise ValueError("rtt-ms must be 0..250")
    result = named_workload(profile, binary.absolute(), payload_bytes, requests, rtt_ms, target_port)
    exact = result.get('exact_echo', {}) if isinstance(result, dict) else {}
    if (not isinstance(result, dict) or result.get("success_rate") != 1.0 or
            result.get("bytes_received") != payload_bytes * requests or
            result.get('bytes_sent') != payload_bytes * requests or
            exact.get('byte_for_byte') is not True or exact.get('verified_requests') != requests or
            exact.get('payload_sha256') != exact.get('received_sha256')):
        raise ValueError("native application workload did not satisfy bounded correctness contract")
    return {"status": "PASS", "core": core, "profile": profile_id,
            "nativeTransport": profile["nativeTransport"],
            "applicationBoundary": profile["applicationBoundary"],
            "correctness": {"status": "PASS", "workload": "named-service-profile-echo-v1",
                "payloadBytes": payload_bytes, "requests": requests,
                "bytesSent": result["bytes_sent"], "bytesReceived": result["bytes_received"],
                "payloadSha256": exact['payload_sha256'],
                "receivedSha256": exact['received_sha256'],
                "byteForByte": exact['byte_for_byte'],
                "recordBytes": exact['record_bytes'],
                "verifiedRequests": exact['verified_requests'],
                "successRate": result["success_rate"]},
            "metrics": {"durationSeconds": result["duration_seconds"],
                "goodputBitsPerSecond": result["throughput_bps"],
                "rttP95Seconds": result["latency_p95_seconds"],
                "rttAverageSeconds": result["latency_avg_seconds"],
                'testPacingMs': result['pacing_ms'],
                "cpuSeconds": None, "peakRssBytes": None,
                "unavailableMetrics": ["native process CPU/RSS counters", "Core-internal transport counters"]},
            "runtimeObservation": result['runtime_observation'],
            "adapter": None, "carrier": "native"}


def main():
    def terminate(_signal, _frame):
        raise TimeoutError('bounded worker terminated; stopping owned Named Services')
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--payload-bytes", type=int, default=4096)
    parser.add_argument("--requests", type=int, default=4)
    parser.add_argument("--rtt-ms", type=int, default=0)
    parser.add_argument("--target-port", type=int)
    args = parser.parse_args()
    try:
        result = run(args.core, args.profile, args.binary, args.payload_bytes, args.requests, args.rtt_ms, args.target_port)
    except PermissionError as error:
        result = {"status": "BLOCKED", "core": args.core, "profile": args.profile,
                  "reason": f"test host denied the requested socket/process capability: {error}"}
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        result = {"status": "FAIL", "core": args.core, "profile": args.profile,
                  "reason": f"{type(error).__name__}: {error}"}
        print(json.dumps(result, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
