"""Fast regression checks: missing products must never make the suite green."""
import contextlib
import io
from pathlib import Path
import unittest
from unittest.mock import patch
import stack_test


class CIContracts(unittest.TestCase):
    def test_all_requires_every_declared_core(self):
        with patch.object(Path,'is_file',return_value=False), \
             patch('sys.argv',['stack_test.py','--engine','all']), \
             contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(stack_test.main(),1)

    def test_an_explicit_missing_core_fails(self):
        with patch.object(Path,'is_file',return_value=False), \
             patch('sys.argv',['stack_test.py','--engine','shadow6-idris']), \
             contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(stack_test.main(),1)


if __name__=='__main__': unittest.main()
