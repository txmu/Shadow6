"""Installation replacement must never infer ownership from an arbitrary Makefile."""
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent/'install_tree.sh'

class InstallDestinationTests(unittest.TestCase):
    def test_unrelated_makefile_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-install-guard-') as directory:
            path = Path(directory); marker=path/'Makefile'; marker.write_text('unrelated data\n')
            result=subprocess.run(['bash',str(SCRIPT),str(path)],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,2)
            self.assertEqual(marker.read_text(),'unrelated data\n')

    def test_symlink_destination_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-install-guard-') as directory:
            path=Path(directory); target=path/'real'; target.mkdir(); link=path/'link'; link.symlink_to(target, target_is_directory=True)
            result=subprocess.run(['bash',str(SCRIPT),str(link)],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,2)
            self.assertTrue(link.is_symlink())

    def test_invalid_or_symlink_marker_cannot_authorize_replacement(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-install-guard-') as directory:
            path=Path(directory); marker=path/'.shadow6-tree'; marker.write_text('wrong-marker')
            result=subprocess.run(['bash',str(SCRIPT),str(path)],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,2)
            self.assertEqual(marker.read_text(),'wrong-marker')
            marker.unlink(); marker.symlink_to(path/'missing')
            result=subprocess.run(['bash',str(SCRIPT),str(path)],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,2)
            self.assertTrue(marker.is_symlink())

if __name__=='__main__': unittest.main()
