"""Required real Native Profile lifecycle gate against already-built artifacts.

No builds, skips, wire codecs, alternate engines or benchmark process launchers.
Configuration fixtures share the existing native realization helpers; every
process is launched and observed by the public Named Service lifecycle.
"""
import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import nullcontext

SOURCE_ROOT = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get('SHADOW6_NAMED_TEST_ROOT', SOURCE_ROOT)).resolve()
if not (ROOT / 'Makefile').is_file():
    raise ValueError('Named Profile test root must be an explicit Shadow6 tree')
ENTRY_ROOT = ROOT if (ROOT / 'CLI/shadow6_connect.py').is_file() else SOURCE_ROOT
sys.path.insert(0, str(SOURCE_ROOT))
sys.path.insert(0, str(SOURCE_ROOT / 'integration'))
from Deployment.core_catalog import CoreCatalog
from Deployment.profile_registry import profiles
from Deployment.protocol_context import minimal_context, pack_protocol
from Deployment.service_registry import ServiceRegistry
from Deployment.service_storage import atomic_write, strict_json
from Deployment import service_runtime
from libshadow6 import Shadow6
from native_configs import generate_commands
from stack_test import (generate_configs, EchoTarget, DatagramEchoTarget,
                        free_port)


class NamedProfileTests(unittest.TestCase):
    def check_profile(self, profile):
        binary = ROOT / profile['artifact']
        self.assertTrue(binary.is_file(), 'required installed artifact missing: ' + str(binary))
        family = socket.AF_INET6 if profile['core'] == 'hare' else socket.AF_INET
        message = profile['applicationBoundary']['kind'] == 'message'
        target = DatagramEchoTarget(family) if message else EchoTarget()
        self.addCleanup(target.close)
        temporary = tempfile.TemporaryDirectory(prefix='shadow6-named-profile-')
        self.addCleanup(temporary.cleanup)
        with nullcontext(temporary.name) as directory:
            directory = Path(directory)
            registry = ServiceRegistry(directory / 'services.json', CoreCatalog(ROOT))
            names = {role: 'native/' + role for role in profile['roles']}
            def cleanup():
                for role in ('client', 'agent', 'broker'):
                    try: registry.stop(names[role])
                    except (ValueError, OSError): pass
            self.addCleanup(cleanup)
            target_port = target.start()
            output = directory / 'configs'
            # C++'s native --init-demo requires a fresh directory and owns its
            # creation. Other realization helpers write into a private parent.
            if profile['core'] != 'cpp': output.mkdir(mode=0o700)
            engine = 'shadow6-' + profile['benchmarkAlias']
            if profile['realization']['launcher'] == 'native-files':
                documents = {}
                generate_commands(engine, binary, output, target_port,
                                  normalized_documents=documents)
                configs = {}
                for role, document in documents.items():
                    configs[role] = output / (role + '.json')
                    atomic_write(configs[role], json.dumps(document).encode())
            else:
                asyncio.run(generate_configs(engine, output, target_port, free_port()))
                configs = {role: output / (role + '.json' if profile['core'] == 'cpp'
                    else 'it-' + engine + '-' + role + '.json') for role in profile['roles']}
            environment = {**os.environ, 'SHADOW6_ROOT': str(ROOT), 'SHADOW6_SERVICE_REGISTRY': str(registry.path)}
            def cli(*arguments):
                result = subprocess.run([sys.executable, str(ENTRY_ROOT / 'CLI/shadow6.py'), *arguments],
                    capture_output=True, env=environment, timeout=45)
                self.assertEqual(result.returncode, 0, repr(arguments) + ': ' + result.stderr.decode(errors='replace') + result.stdout.decode(errors='replace'))
                return strict_json(result.stdout)
            for role in ('broker', 'agent', 'client'):
                context = minimal_context(profile['core']); context['role'] = role
                context_path = directory / (role + '.s6p1.json')
                atomic_write(context_path, pack_protocol(context).encode())
                binding = directory / (role + '.binding.json')
                atomic_write(binding, json.dumps({'config_path': str(configs[role])}).encode())
                # Use public setup, then inspect the persisted authority.
                args = ('setup', names[role], '--core', profile['core'], '--profile', profile['id'],
                        '--config', str(binding), '--protocol-file', str(context_path))
                cli(*args)
                registry._load()
                lock = registry.inspect(names[role])['deploymentLock']
                cli(*args)  # setup is idempotent before startup as well.
                registry._load()
                self.assertEqual(registry.inspect(names[role])['deploymentLock'], lock)
            # A small executable wrapper makes libshadow6 call the public CLI
            # under this test's interpreter and private registry, without mocks.
            facade_cli = directory / 'shadow6'
            facade_cli.write_text('#!' + sys.executable + '\nimport os,sys\n'
                + 'os.environ["SHADOW6_SERVICE_REGISTRY"]=' + repr(str(registry.path)) + '\n'
                + 'os.environ["SHADOW6_ROOT"]=' + repr(str(ROOT)) + '\n'
                + 'os.execv(sys.executable,[sys.executable,' + repr(str(ENTRY_ROOT / 'CLI/shadow6.py')) + ',*sys.argv[1:]])\n')
            facade_cli.chmod(0o700)
            with Shadow6(cli=facade_cli) as facade:
                for cycle in range(2):
                    for role in ('broker', 'agent', 'client'):
                        cli('run' if cycle == 0 else 'restart', names[role])
                    # Readiness must be owned and observed, never process-only.
                    deadline = time.monotonic() + 30
                    while True:
                        current = {role: cli('status', names[role]) for role in names}
                        if all(item['state'] == 'running' for item in current.values()) and current['client']['runtime']['readiness'] == 'application-ready':
                            break
                        self.assertFalse(any(item['state'] in ('failed', 'stale', 'exited') for item in current.values()), current)
                        self.assertLess(time.monotonic(), deadline, current)
                        time.sleep(.1)
                    for role, item in current.items():
                        self.assertEqual(item['profileBinding']['profile'], profile['id'])
                        self.assertEqual(cli('run', names[role])['runtime']['pid'], item['runtime']['pid'])
                        doctor = cli('doctor', names[role])
                        self.assertEqual(doctor['findings'], [], doctor)
                    with facade.connect(names['client']) as session:
                        payload = b'named-profile:' + profile['id'].encode()
                        if message:
                            session.send_record(payload)
                            received = session.receive_record()
                            if received != payload:
                                self.fail('message reply differs: ' + repr(received) + '; states=' + repr({role:cli('status',names[role])['state'] for role in names}))
                            with self.assertRaisesRegex(ValueError, 'UnsupportedApplicationHalfClose'):
                                session.half_close()
                        else:
                            session.send(payload)
                            received = bytearray()
                            while len(received) < len(payload):
                                data = session.receive(len(payload) - len(received))
                                self.assertTrue(data, 'unexpected stream EOF')
                                received.extend(data)
                            self.assertEqual(bytes(received), payload)
                    for role in ('client', 'agent', 'broker'):
                        stopped = cli('stop', names[role])
                        self.assertFalse(service_runtime.alive(stopped.get('runtime', {})))
                # Config drift invalidates the old lock; ordinary run cannot
                # relock or rebuild. Failed reconfiguration preserves that lock.
                registry._load()
                before = registry.inspect(names['client'])['deploymentLock']
                original = configs['client'].read_bytes()
                atomic_write(configs['client'], original + b'\n')
                failed = subprocess.run([sys.executable, str(ENTRY_ROOT / 'CLI/shadow6.py'),
                    'run', names['client']], capture_output=True, env=environment, timeout=15)
                self.assertNotEqual(failed.returncode, 0)
                registry._load()
                self.assertEqual(registry.inspect(names['client'])['deploymentLock'], before)
                atomic_write(configs['client'], original)
                for role in ('client', 'agent', 'broker'):
                    cli('remove', names[role])
                registry._load(); self.assertEqual(registry.list(), [])
            cleanup()


def _case(profile):
    def test(self): self.check_profile(profile)
    return test


for _profile in profiles():
    setattr(NamedProfileTests, 'test_' + _profile['id'].replace('-', '_'), _case(_profile))


if __name__ == '__main__':
    unittest.main()
