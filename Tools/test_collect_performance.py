import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from collect_performance import collect


class PerformanceBundleTests(unittest.TestCase):
    def test_same_names_keep_platform_sources_and_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'input'
            for platform in ('linux', 'windows'):
                directory = source / f'shadow6-iperf3-{platform}-test'
                directory.mkdir(parents=True)
                (directory / 'report.json').write_text(json.dumps({'platform': platform}))
            output = root / 'all.zip'
            needs = {'linux': {'result': 'failure'}, 'windows': {'result': 'success'}}
            manifest = collect(source, output, needs, root / 'summary.md')
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(json.loads(archive.read('manifest.json'))['jobs'], needs)
                for entry in manifest['artifacts']:
                    file = entry['files'][0]
                    data = archive.read('artifacts/' + file['path'])
                    self.assertEqual(hashlib.sha256(data).hexdigest(), file['sha256'])
            self.assertIn('failure', (root / 'summary.md').read_text())
            self.assertTrue(manifest['missing_artifacts'])

    def test_empty_input_still_reports_missing_data(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = collect(root / 'input', root / 'all.zip', {}, None)
            self.assertFalse(manifest['artifacts'])
            self.assertTrue(manifest['missing_artifacts'])
            with zipfile.ZipFile(root / 'all.zip') as archive:
                self.assertIn(b'No performance reports', archive.read('SUMMARY.md'))

    def test_symlink_is_not_packaged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory = root / 'input' / 'artifact'
            directory.mkdir(parents=True)
            (root / 'private').write_text('not a report')
            (directory / 'report.json').symlink_to(root / 'private')
            with self.assertRaises(ValueError):
                collect(root / 'input', root / 'all.zip', {}, None)
            self.assertFalse((root / 'all.zip').exists())


if __name__ == '__main__':
    unittest.main()
