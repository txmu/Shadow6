"""Runtime fallback must reflect dependency imports, not interpreter filenames."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import python_runtime as runtime

class RuntimeTests(unittest.TestCase):
    def report(self, path, preferred=False, usable=True):
        return dict(executable=path, preferred=preferred, usable=usable, version=[3,14,0],
                    gil_enabled=not preferred, dependencies_ok=usable)

    def test_prefer_working_free_threaded_runtime(self):
        def probe(path, _): return self.report(path, preferred='.venv-ft' in path)
        with patch.dict(os.environ,{},clear=True), patch.object(runtime,'probe',side_effect=probe), patch.object(Path,'is_file',return_value=True), patch.object(os.path,'isfile',return_value=True):
            result=runtime.select_runtime('/fixture')
        self.assertFalse(result['fallback'])
        self.assertIn('.venv-ft',result['selected']['executable'])

    def test_incompatible_free_threaded_runtime_falls_back(self):
        def probe(path, _): return self.report(path, usable='.venv-ft' not in path)
        with patch.dict(os.environ,{},clear=True), patch.object(runtime,'probe',side_effect=probe), patch.object(os.path,'isfile',return_value=True):
            result=runtime.select_runtime('/fixture')
        self.assertTrue(result['fallback'])
        self.assertNotIn('.venv-ft',result['selected']['executable'])

    def test_explicit_runtime_preserves_gil_choice(self):
        with patch.dict(os.environ,{'SHADOW6_PYTHON':sys.executable}), patch.object(runtime,'probe',return_value=self.report(sys.executable)):
            result=runtime.select_runtime('/fixture')
        self.assertEqual(result['reason'],'explicit runtime')
        self.assertTrue(result['selected']['gil_enabled'])

    def test_probe_reports_actual_process(self):
        report=runtime.runtime_report()
        self.assertEqual(report['gil_enabled'],bool(getattr(sys,'_is_gil_enabled',lambda:True)()))
        self.assertTrue(report['dependencies_ok'])

if __name__=='__main__': unittest.main()
