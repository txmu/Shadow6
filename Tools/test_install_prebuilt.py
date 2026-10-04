"""Install admission, active-lock protection and failure rollback contracts."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from Tools.install_prebuilt import publish, reject_live_services
from Deployment.service_runtime import identity
from Deployment.service_storage import atomic_write


class InstallTransactionTests(unittest.TestCase):
    def test_failed_publish_restores_all_original_material_and_unrelated_files(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-install-transaction-') as directory:
            root = Path(directory); staged = root / 'staged'; live = root / 'live'
            staged.mkdir(mode=0o755); live.mkdir(mode=0o755); backup = root / 'backup'
            for name in ('a', 'b', 'c'):
                (staged / name).write_text('new-' + name)
                (live / name).write_text('old-' + name)
            (live / 'unrelated').write_text('preserve')
            calls = 0
            def failure(source, target):
                nonlocal calls
                calls += 1
                if calls == 2: raise OSError('injected write failure')
                os.replace(source, target)
            with self.assertRaisesRegex(OSError, 'injected'):
                publish(staged, live, backup, replace=failure)
            self.assertEqual({p.name: p.read_text() for p in live.iterdir()},
                {'a':'old-a', 'b':'old-b', 'c':'old-c', 'unrelated':'preserve'})

    def test_symlink_destination_rolls_back_earlier_changes(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-install-transaction-') as directory:
            root = Path(directory); staged = root / 'staged'; live = root / 'live'
            staged.mkdir(mode=0o755); live.mkdir(mode=0o755)
            for name in ('a', 'b'): (staged / name).write_text('new')
            (live / 'a').write_text('old'); (root / 'external').write_text('untouched')
            (live / 'b').symlink_to(root / 'external')
            with self.assertRaisesRegex(ValueError, 'unsafe installation destination'):
                publish(staged, live, root / 'backup')
            self.assertEqual((live / 'a').read_text(), 'old')
            self.assertTrue((live / 'b').is_symlink())
            self.assertEqual((root / 'external').read_text(), 'untouched')

    @unittest.skipUnless(sys.platform == 'linux', 'Linux process identity backend unavailable')
    def test_running_service_blocks_upgrade_and_preserves_the_lock(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-install-active-') as directory:
            root = Path(directory); (root / 'share/shadow6/tree').mkdir(parents=True)
            child = subprocess.Popen([sys.executable, '-c', 'import sys;sys.stdin.read()'], stdin=subprocess.PIPE)
            try:
                item = {'runtime':{'pid':child.pid, 'processIdentity':identity(child.pid)},
                        'deploymentLock':{'digest':'unchanged'}}
                path = root / 'services.json'
                atomic_write(path, json.dumps({'services':{'home/nas':item}}).encode())
                before = path.read_bytes()
                with self.assertRaisesRegex(ValueError, 'ServiceRunning: stop home/nas'):
                    reject_live_services(root, path)
                self.assertEqual(path.read_bytes(), before)
                self.assertIsNone(child.poll())
                child.stdin.close(); child.wait(timeout=3)
                reject_live_services(root, path)
            finally:
                if child.poll() is None: child.terminate(); child.wait(timeout=3)
                if not child.stdin.closed: child.stdin.close()


if __name__ == '__main__': unittest.main()
