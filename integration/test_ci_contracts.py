"""Fast regression checks: missing products must never make the suite green."""
import contextlib
import io
import threading
from pathlib import Path
import unittest
from unittest.mock import patch
import stack_test


class CIContracts(unittest.TestCase):
    def test_parallel_workload_waits_for_all_native_trios(self):
        entered = []
        lock = threading.Lock()
        def ready(engine, options, backend, barrier):
            with lock:
                entered.append(engine)
            barrier.wait(timeout=2)
            self.assertEqual(len(entered), 4)
            return dict(requests=1, bytes_sent=512, bytes_received=512,
                        latency_p95_seconds=0.01, latency_avg_seconds=0.01,
                        success_rate=1.0)
        with patch.object(stack_test, 'run_engine', side_effect=ready):
            result = stack_test.run_parallel('shadow6-carp', {'concurrency': 4}, 'node')
        self.assertEqual(result['bytes_received'], 2048)
        self.assertEqual(result['concurrency'], 4)

    def test_failed_native_trio_releases_waiting_peers(self):
        entered = []
        lock = threading.Lock()
        def ready(engine, options, backend, barrier):
            with lock:
                entered.append(engine)
                first = len(entered) == 1
            if first:
                raise RuntimeError('startup failed')
            barrier.wait(timeout=2)
        with patch.object(stack_test, 'run_engine', side_effect=ready):
            with self.assertRaisesRegex(RuntimeError, 'startup failed'):
                stack_test.run_parallel('shadow6-carp', {'concurrency': 4}, 'node')

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
