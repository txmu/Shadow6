#!/usr/bin/env python3
"""Stage and admit a complete installation before replacing locked material.

Both source and binary installs use this transaction. No native build or
dependency installation occurs here. Failed admission never touches the prefix.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


def owned_directory(path):
    entry = path.lstat()
    if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid() or entry.st_mode & 0o022:
        raise ValueError('installation directory must be owner-controlled and non-symlink: ' + str(path))


def ensure_directory(path, created):
    if path.exists() or path.is_symlink():
        owned_directory(path)
        return
    ensure_directory(path.parent, created)
    path.mkdir(mode=0o755)
    created.append(path)


def reject_live_services(destination, registry_path=None):
    """Use the existing identity authority; do not signal or replace live jobs."""
    from Deployment.service_storage import private_read, strict_json
    from Deployment.service_runtime import alive
    path = Path(registry_path or os.environ.get('SHADOW6_SERVICE_REGISTRY',
        Path.home() / '.config/shadow6/services.json'))
    try:
        data = strict_json(private_read(path))
    except FileNotFoundError:
        return
    if not isinstance(data, dict) or not isinstance(data.get('services'), dict):
        raise ValueError('invalid existing Service Registry; repair it before installation')
    tree = destination / 'share/shadow6/tree'
    # Any update to an existing installation can change supervisor/adapter
    # material, even if a Core binary remains identical.
    if not tree.is_dir():
        return
    for name, item in data['services'].items():
        if not isinstance(item, dict):
            raise ValueError('invalid existing service record')
        if alive(item.get('runtime', {})):
            raise ValueError('ServiceRunning: stop ' + name
                + ' before upgrade; then explicitly reconfigure, lock/apply and run. The current lock is preserved.')


def admit_stage(prefix):
    """Probe the staged entrypoint's own module paths, never ambient imports."""
    cli = prefix / 'bin/shadow6'
    environment = {k: v for k, v in os.environ.items()
                   if k not in ('PYTHONPATH', 'SHADOW6_ROOT', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES')}
    result = subprocess.run([sys.executable, str(cli), 'core', 'profiles', '--installed'],
        cwd=prefix, env=environment, capture_output=True, timeout=60, check=False)
    if result.returncode:
        raise ValueError('staged Profile doctor failed; install matching binaries and modules before retrying')
    from Deployment.service_storage import strict_json
    report = strict_json(result.stdout)
    if not isinstance(report, dict) or not isinstance(report.get('profiles'), list):
        raise ValueError('invalid staged Profile doctor report')
    # A zero-Core installation is legal. A selected binary whose own contract
    # or runtime cannot be probed is an installation failure, not a silent skip.
    invalid = [p for p in report['profiles'] if any(
        d['code'] == 'NativeFeatureContractUnavailable' for d in p['diagnostics'])]
    if invalid:
        raise ValueError('ArtifactContractMismatch: ' + json.dumps(invalid, sort_keys=True))
    code = '''import sys,json
sys.path.insert(0,sys.argv[1])
sys.path.insert(0,sys.argv[2])
from feature_contract import validate_feature_report
from Deployment.service_runtime import feature_report
from pathlib import Path
root=Path(sys.argv[2])
for path in sorted(root.glob('Core-*/shadow6-*')):
 if not path.is_file() or path.suffix: continue
 report=feature_report(str(path));validate_feature_report(report)
 variant=path.name.endswith(('-crosed','-public6'))
 if report['crosed_max_level'] != (5 if variant else 0): raise ValueError('invalid build level: '+path.name)
 if not variant and any(report[k] for k in ('crosed_compiled','app_transport','qubes_isolation','gate_enabled_by_default')): raise ValueError('invalid default privilege: '+path.name)
 if variant and not report['app_transport']: raise ValueError('invalid variant contract: '+path.name)
print('admitted')
'''
    environment['PYTHONPATH'] = str(prefix / 'share/shadow6')
    # Deployment uses its installed bridge and adjacent generated runtime trees.
    result = subprocess.run([sys.executable, '-c', code,
        str(prefix / 'share/shadow6/modules'), str(prefix / 'share/shadow6/tree')],
        cwd=prefix, env=environment, capture_output=True, timeout=120, check=False)
    if result.returncode:
        raise ValueError('ArtifactContractMismatch: default/variant validation failed; installation unchanged')
    return report


def publish(staged, destination, backup, *, replace=os.replace):
    """Atomically replace individual files, and roll back all on any failure."""
    files = sorted(p for p in staged.rglob('*') if p.is_symlink() or not p.is_dir())
    if len(files) > 30000:
        raise ValueError('installation file limit')
    replacements, created = [], []
    try:
        for source in files:
            if source.is_symlink() or not source.is_file():
                raise ValueError('unsupported installation file: ' + str(source))
            relative = source.relative_to(staged)
            target = destination / relative
            ensure_directory(target.parent, created)
            old = backup / relative
            if target.exists() or target.is_symlink():
                entry = target.lstat()
                if not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.geteuid() or entry.st_nlink != 1:
                    raise ValueError('refusing unsafe installation destination: ' + str(target))
                old.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, old)
            else:
                old = None
            # The temporary is adjacent, so rename is atomic across filesystems.
            fd, temporary = tempfile.mkstemp(prefix='.shadow6-install-', dir=target.parent)
            try:
                with os.fdopen(fd, 'wb') as output, source.open('rb') as incoming:
                    shutil.copyfileobj(incoming, output)
                    output.flush(); os.fsync(output.fileno())
                    os.fchmod(output.fileno(), stat.S_IMODE(source.stat().st_mode) & ~0o022)
                replace(temporary, target)
                replacements.append((target, old))
            finally:
                Path(temporary).unlink(missing_ok=True)
    except BaseException:
        for target, old in reversed(replacements):
            if old is None:
                target.unlink()
            else:
                # Keep rollback on the destination filesystem as well.
                fd, temporary = tempfile.mkstemp(prefix='.shadow6-rollback-', dir=target.parent)
                os.close(fd)
                try:
                    shutil.copy2(old, temporary); os.replace(temporary, target)
                finally:
                    Path(temporary).unlink(missing_ok=True)
        for directory in reversed(created):
            try: directory.rmdir()
            except OSError: pass
        raise


def install(source, prefix, destdir=None, core_selections=()):
    source = source.resolve()
    if not prefix.is_absolute() or '..' in prefix.parts or (destdir and (not destdir.is_absolute() or '..' in destdir.parts)):
        raise ValueError('installation paths must be absolute without parent traversal')
    destination = (destdir / prefix.relative_to('/')) if destdir else prefix
    sys.path[:0] = [str(source), str(source / 'Crosed')]
    from native_profiles import profiles
    artifacts = {p['core'].upper(): p['artifact'] for p in profiles() if p['primary']}
    selections = {}
    for selection in core_selections:
        name, separator, value = selection.partition(':')
        if not separator or name not in artifacts or value not in ('0', '1', 'auto') or name in selections:
            raise ValueError('invalid installation Core selection')
        selections[name] = value
    core_flags = ['BUILD_' + name + '=' + (value if value != 'auto' else
        str(int((source / artifact).is_file())))
        for name, artifact in artifacts.items() for value in [selections.get(name, 'auto')]]
    destination.mkdir(mode=0o755, parents=True, exist_ok=True)
    owned_directory(destination)
    lock = destination / '.shadow6-install.lock'
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        from Deployment.service_storage import private_read
        private_read(lock)
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise ValueError('another Shadow6 install is running')
        reject_live_services(destination)
        tree = destination / 'share/shadow6/tree'
        if tree.exists() and (not (tree / '.shadow6-tree').is_file()
            or (tree / '.shadow6-tree').is_symlink()
            or (tree / '.shadow6-tree').read_bytes() != b'shadow6-installed-tree\n'):
            raise ValueError('refusing to replace an unrecognized installation tree')
        # Keep the transaction on the destination filesystem: /tmp may be a
        # small tmpfs even when the installation disk has ample capacity.
        with tempfile.TemporaryDirectory(prefix='shadow6-install-', dir=destination.parent) as temporary:
            staging = Path(temporary)
            staged = staging / 'payload' / prefix.relative_to('/')
            # The inner target copies existing artifacts only. Make forwards
            # command-line BUILD_* selections through its inherited MAKEFLAGS.
            command = ['make', 'install-prebuilt-files', 'PREFIX=' + str(prefix),
                       'DESTDIR=' + str(staging / 'payload'), *core_flags]
            subprocess.run(command, cwd=source, check=True)
            report = admit_stage(staged)
            # Serialize with service mutations across the final live check and
            # file transaction so setup/run cannot race an upgrade.
            from Deployment.service_registry import ServiceRegistry
            from Deployment.core_catalog import CoreCatalog
            from Deployment.service_registry import transaction
            registry = ServiceRegistry(path=staging / 'services.json' if destdir else None,
                catalog=CoreCatalog(tree if tree.is_dir() else source))
            @transaction
            def commit(manager):
                reject_live_services(destination, manager.path)
                publish(staged, destination, staging / 'backup')
            commit(registry)
            print(json.dumps({'schema': 'shadow6.installation.v1', 'prefix': str(destination),
                              'availableProfiles': report['availableProfiles'],
                              'profiles': report['profiles'], 'status': 'installed'}, sort_keys=True))
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--destdir', type=Path)
    parser.add_argument('--core-selection', action='append', default=[])
    args = parser.parse_args()
    try: install(args.source, args.prefix, args.destdir, args.core_selection)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({'schema': 'shadow6.installation-error.v1', 'error': str(error)}, sort_keys=True), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
