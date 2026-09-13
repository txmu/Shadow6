import errno, json, os, sys, tempfile, time, unittest
from unittest.mock import patch
from pathlib import Path
from benchmark import _load_config, execute, network_unavailable

class ConfigTests(unittest.TestCase):
    def test_rejects_unknown_and_unbounded(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"; p.write_text(json.dumps({"repeats": 1001}))
            with self.assertRaises(ValueError): _load_config(str(p))
    def test_defaults_are_bounded(self):
        c = _load_config(None); self.assertEqual(c["repeats"], 1); self.assertIn("go", c["cores"])

class ProcessTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "wait4"), "requires POSIX wait4")
    def test_child_counters_and_exit_status(self):
        code, out, err, usage = execute([sys.executable, "-c", "print('sample'); raise SystemExit(7)"], 5)
        self.assertEqual((code, out.strip(), err), (7, "sample", ""))
        self.assertTrue(all(metric["state"] == "valid" for metric in usage.values()))
        self.assertGreater(usage["peak_rss_kib"]["value"], 0)

    def test_timeout_remains_bounded(self):
        start = time.monotonic()
        code, _, _, usage = execute([sys.executable, "-c", "import time; time.sleep(20)"], 0.1)
        self.assertEqual(code, 124)
        self.assertLess(time.monotonic() - start, 5)
        self.assertEqual(usage["peak_rss_kib"]["reason"], "timed out")

    def test_protocol_absence_is_distinct_from_permission_failure(self):
        with patch("benchmark.socket.socket", side_effect=OSError(errno.EPROTONOSUPPORT, "unsupported")):
            self.assertIn("SCTP unavailable", network_unavailable("cpp"))
            self.assertIsNone(network_unavailable("go"))
        with patch("benchmark.socket.socket", side_effect=PermissionError(errno.EPERM, "denied")):
            with self.assertRaises(PermissionError): network_unavailable("cpp")

if __name__ == "__main__": unittest.main()
