import errno, json, os, sys, tempfile, time, unittest
from unittest.mock import patch
from pathlib import Path
from benchmark import _load_config, execute, network_unavailable, network_result, run, write, validate_config
from performance_matrix import ENGINES, cases

class ConfigTests(unittest.TestCase):
    def test_performance_matrix_is_bounded_and_complete(self):
        matrix = list(cases())
        self.assertEqual(len(matrix), 12)
        self.assertEqual({item["payload_bytes"] for item in matrix}, {4096, 65536, 1048576})
        self.assertTrue(all(item["stream_bytes"] == 16 * 1024 * 1024 for item in matrix))
        self.assertEqual(len(ENGINES), 12)
        with self.assertRaises(ValueError): list(cases(0))
    def test_rejects_unknown_and_unbounded(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"; p.write_text(json.dumps({"repeats": 1001}))
            with self.assertRaises(ValueError): _load_config(str(p))
    def test_defaults_are_bounded(self):
        c = _load_config(None); self.assertEqual(c["repeats"], 1); self.assertIn("go", c["cores"])

    def test_cli_overrides_and_network_fields_are_revalidated(self):
        for change in ({'repeats':True}, {'repeats':1001}, {'network':{'requests':2}},
                       {'args':{'go':['--config','sensitive.json']}}, {'cores':['go','go']}):
            config = _load_config(None); config.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): validate_config(config)

class ReportTests(unittest.TestCase):
    def test_wrapped_network_metrics_survive_all_three_formats(self):
        data = dict(throughput_bps=1234.5, duration_seconds=0.5,
                    latency_p95_seconds=0.001, success_rate=1.0)
        out = 'ready\n'+json.dumps({'schema':'shadow6.network-suite.v1','results':{'shadow6-go':data}})
        self.assertEqual(network_result(out,'go'),data)
        result = {'results':[dict(core='go',measurement='network-chain',status='ok',network=network_result(out,'go'))]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'report'
            write(result,path)
            for suffix in ('.json','.txt','.md'):
                self.assertIn('1234.5',path.with_suffix(suffix).read_text())

    def test_network_cannot_pass_with_missing_or_nonfinite_measurements(self):
        for data in ({}, {'throughput_bps':float('nan')}, {'throughput_bps':True}):
            with self.subTest(data=data), self.assertRaises((ValueError,KeyError)):
                network_result(json.dumps(data),'go')

    def test_missing_core_fails_instead_of_silently_skipping(self):
        with patch('benchmark.available',return_value=False):
            result=run({'cores':['pony'],'roles':['network-chain']})
        self.assertEqual(result['results'][0]['status'],'failed')

    def test_required_network_rejects_unsupported_kernel(self):
        with patch('benchmark.available',return_value=True), patch('benchmark.network_unavailable',return_value='SCTP unavailable'):
            result=run({'cores':['cpp'],'roles':['network-chain'],'require_network':True})
        self.assertEqual(result['results'][0]['status'],'failed')

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
