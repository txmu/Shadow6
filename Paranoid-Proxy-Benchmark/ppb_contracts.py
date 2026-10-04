"""Fixed, exportable Shadow6 contracts. No native build or arbitrary commands."""
import argparse
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

SUITES = {
    'adapter': ('Network-Adapter', 'test_network.py'),
    'interop': ('Network-Adapter', 'test_conformance.py'),
    'application': ('Application-Layer', 'test_protocols.py'),
    'public6': ('Public6', 'test_public6.py'),
    'features': ('Crosed', 'test_feature_contract.py'),
    'native-security': ('Crosed', 'test_security_capabilities.py'),
    'slots': ('Slot-System', 'test_slots.py'),
    'extensions': ('Extension-System', 'test_extensions.py'),
    'plugins': ('Plugin-System', 'test_plugins.py'),
    'adversarial': ('Paranoid-Proxy-Benchmark', 'ppb_vectors.py'),
}
FILES = [f'{directory}/{name}' for directory, name in SUITES.values()] + [
    'Network-Adapter/shadow6_network.py', 'Network-Adapter/shadow6_network.mjs',
    'Application-Layer/shadow_protocols.py', 'Public6/shadow6_public.py',
    'Crosed/feature_contract.py', 'Crosed/native_profiles.py', 'Crosed/limits.py', 'Crosed/install_layout.py',
    'CLI/native_config.py', 'Tools/python_runtime.py',
    'Plugin-System/shadow6_plugins.py', 'Plugin-System/trusted_signers.json',
    'Slot-System/shadow6_slots.py', 'Extension-System/shadow6_extensions.py',
    'Crosed/crosedctl.py',
    'Paranoid-Proxy-Benchmark/ppb_contracts.py',
    'Paranoid-Proxy-Benchmark/paranoid_proxy_benchmark.py',
]
# Source assertions are part of the exported contract; include their inputs.
FILES += [
    'Core-Go/data.go', 'Core-Rust/src/main.rs', 'Core-Gleam/src/shadow6_role.erl',
    'Core-Zig/src/runtime.zig', 'Core-Ada/src/runtime.adb', 'Core-D/src/runtime.d',
    'Core-Nim/src/runtime.nim', 'Core-Cpp/src/runtime.hpp', 'Core-Pony/runtime.pony',
    'Core-Hare/src/runtime.ha', 'Core-Carp/src/runtime.h', 'Core-Idris/ffi/sodium_ffi.c',
    'CLI/shadow6_vcore.py', 'CLI/shadow6.py', 'shadow6_audit.py',
    'Security-Assistants/shadow6_security.py',
]
FILES += [f'plugins/{plugin}/{name}' for plugin in ('maze-runner','number-guess','rock-paper-scissors') for name in ('main.py','plugin.json')]
# The native security inventory is a source contract, including its evidence.
# Export the evidence itself so validation remains independent of the checkout.
FILES += [
    'Crosed/security_capabilities.py', 'Crosed/security_capabilities.json',
    'docs/native-security-capabilities.md', 'Core-Go/control.go',
    'Core-Gleam/src/shadow6_forward.erl', 'Core-Gleam/README.md',
    'Core-Cpp/src/net.hpp', 'Core-Cpp/README.md',
    'Core-Zig/src/crypto.zig', 'Core-Zig/README.md',
    'Core-Ada/src/platform.c', 'Core-Ada/src/relay.adb',
    'Core-D/README.md', 'Core-Nim/src/rtc_bridge.c', 'Core-Nim/src/frames.nim',
    'Core-Pony/crypto/session.c', 'Core-Pony/README.md',
    'Core-Hare/README.md', 'Core-Carp/README.md',
    'Core-Idris/ffi/native_chain.h', 'Core-Idris/README.md',
]
PLUGIN_CASES = ('test_bundled_plugins_are_signed_and_discoverable',
    'test_modified_code_and_manifest_are_rejected',
    'test_capabilities_are_deny_by_default_at_policy_boundary',
    'test_plugin_symlink_and_oversized_request_are_rejected',
    'test_plugin_rpc_frames_and_ocap_replay_boundary')

def root():
    here = Path(__file__).resolve().parent
    for candidate in (here.parent, here.parent / 'share/shadow6/tree'):
        if (candidate / 'Network-Adapter/test_network.py').is_file():
            return candidate
    raise ValueError('contract bundle missing; export it from a Shadow6 installation first')


def export(destination):
    source = root()
    destination.mkdir(mode=0o700)  # Never merge or overwrite an existing tree.
    for name in FILES:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    manifest = {name: hashlib.sha256((destination / name).read_bytes()).hexdigest() for name in FILES}
    (destination / 'manifest.json').write_text(json.dumps({'schema':'ppb.bundle.v1','sha256':manifest}, indent=2) + '\n')
    (destination / 'README.txt').write_text(
        'Run: python3 Paranoid-Proxy-Benchmark/paranoid_proxy_benchmark.py contracts\n'
        'Requires Python cryptography; interop also requires Node.js. No native builds.\n'
        'These are local implementation contracts, not a remote-node security verdict.\n')


class Result(unittest.TestResult):
    def __init__(self):
        super().__init__(); self.rows = []
    def addSuccess(self, test):
        super().addSuccess(test); self.rows.append({'id': test.id(), 'status': 'pass'})
    def addFailure(self, test, err):
        super().addFailure(test, err); self.rows.append({'id': test.id(), 'status': 'fail', 'reason': str(err[1])[:512]})
    def addError(self, test, err):
        super().addError(test, err); self.rows.append({'id': test.id(), 'status': 'error', 'reason': str(err[1])[:512]})
    def addSkip(self, test, reason):
        super().addSkip(test, reason); self.rows.append({'id': test.id(), 'status': 'unsupported', 'reason': reason[:512]})
    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err: self.rows.append({'id': str(subtest), 'status': 'fail', 'reason': str(err[1])[:512]})


def worker(name):
    base = root()
    if os.name == 'nt' and name in ('slots','extensions','plugins'):
        print(json.dumps([{'status':'unsupported','reason':'POSIX resource/permission contracts require a POSIX host'}])); return 0
    for directory in ('Network-Adapter', 'Application-Layer', 'Public6', 'Crosed', 'CLI', 'Plugin-System', 'Slot-System', 'Extension-System'):
        sys.path.insert(0, str(base / directory))
    directory, filename = SUITES[name]
    spec = importlib.util.spec_from_file_location('ppb_' + name, base / directory / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    result = Result()
    suite = unittest.TestSuite(module.PluginSystemTests(case) for case in PLUGIN_CASES) if name == 'plugins' else unittest.defaultTestLoader.loadTestsFromModule(module)
    suite.run(result)
    print(json.dumps(result.rows))
    return 0 if result.wasSuccessful() and result.testsRun else 1


def run(selected, budget):
    import time
    end = time.monotonic() + budget
    rows = []
    for name in selected or SUITES:
        remaining = end - time.monotonic()
        if remaining <= 0:
            rows.append({'suite': name, 'status': 'not-run'}); continue
        try:
            completed = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), name],
                capture_output=True, text=True, timeout=min(60, remaining), env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            try: results = json.loads(completed.stdout)
            except ValueError: results = [{'status': 'error', 'reason': completed.stderr[-2048:]}]
            status = 'fail' if completed.returncode else 'unsupported' if any(row['status'] == 'unsupported' for row in results) else 'pass'
            rows.append({'suite': name, 'status': status, 'results': results})
        except subprocess.TimeoutExpired:
            rows.append({'suite': name, 'status': 'timeout'})
    return {'schema': 'ppb.contracts.v1', 'scope': 'local production implementations; no remote-node verdict', 'results': rows}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('suite', choices=SUITES)
    raise SystemExit(worker(parser.parse_args().suite))
