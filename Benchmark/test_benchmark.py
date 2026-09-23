import errno, json, os, sys, tempfile, time, unittest
from unittest.mock import patch
from pathlib import Path
from benchmark import _load_config, execute, network_unavailable, network_result, run, write, validate_config
from performance_matrix import ENGINES, cases

class ConfigTests(unittest.TestCase):
    def test_virtual_broker_datagram_benchmark_covers_all_modes(self):
        import asyncio
        from virtual_broker_datagram_benchmark import run as datagram_run
        report=asyncio.run(datagram_run(2,16))
        self.assertEqual(report['expected_rows'],16)
        self.assertEqual(len(report['results']),16)
        self.assertTrue(all(row['status']=='ok' and row['throughput_bps']>0 for row in report['results']))
    def test_component_matrix_has_identical_backend_workloads(self):
        from component_benchmark import run as component_run
        def success(spec):
            return dict(duration_seconds=1,throughput_bps=8*spec['useful_bytes'],bytes_received=spec['useful_bytes'])
        def node(command,timeout):
            return 0,json.dumps(success(json.loads(command[-1]))),'',{}
        with patch('component_benchmark.adapter_case',side_effect=success),patch('component_benchmark.execute',side_effect=node),patch('component_benchmark.shutil.which',return_value='node'):
            report=component_run(('adapter',),payloads=(4096,),concurrency=(1,4),flow_bytes=16384)
        self.assertEqual(report['expected_rows'],12*2*2*4)
        self.assertEqual(len(report['results']),report['expected_rows'])
        by_backend={backend:{(r['core'],r['payload_bytes'],r['concurrency'],r['requests'],r['loss_percent'],r['reorder']) for r in report['results'] if r['backend']==backend} for backend in ('python','node')}
        self.assertEqual(by_backend['python'],by_backend['node'])
        self.assertTrue(all(r['status']=='ok' for r in report['results']))
    def test_performance_matrix_is_bounded_and_complete(self):
        matrix = list(cases())
        self.assertEqual(len(matrix), 12)
        self.assertEqual({item["payload_bytes"] for item in matrix}, {4096, 65536, 1048576})
        self.assertTrue(all(0<item["stream_bytes"] <= 16 * 1024 * 1024 for item in matrix))
        self.assertTrue(all(item["stream_bytes"]==16*1024*1024 for item in matrix if not item["rtt_ms"]))
        self.assertTrue(all(item["requests"]*item["rtt_ms"]*(1+item["loss_percent"]/100)<=30000 for item in matrix))
        self.assertEqual(len(ENGINES), 12)
        with self.assertRaises(ValueError): list(cases(0))
    def test_rejects_unknown_and_unbounded(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"; p.write_text(json.dumps({"repeats": 1001}))
            with self.assertRaises(ValueError): _load_config(str(p))
    def test_defaults_are_bounded(self):
        c = _load_config(None); self.assertEqual(c["repeats"], 1); self.assertIn("go", c["cores"])
        self.assertEqual(len(c["cores"]), 12)
        self.assertEqual(c["backends"], ["native", "python", "node"])

    def test_cli_overrides_and_network_fields_are_revalidated(self):
        for change in ({'repeats':True}, {'repeats':1001}, {'network':{'requests':2}},
                       {'args':{'go':['--config','sensitive.json']}}, {'cores':['go','go']}):
            config = _load_config(None); config.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): validate_config(config)

class ReportTests(unittest.TestCase):
    def test_wrapped_network_metrics_survive_all_three_formats(self):
        data = dict(throughput_bps=1234.5, duration_seconds=0.5,
                    latency_p95_seconds=0.001, success_rate=1.0,backend='native',
                    payload_bytes=4,requests=2,concurrency=1,bytes_sent=8,bytes_received=8)
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
        self.assertEqual({r['backend'] for r in result['results']}, {'native','python','node'})

    def test_every_core_backend_uses_identical_stack_command(self):
        calls = []
        def execute_case(command, timeout):
            calls.append(command)
            engine = command[command.index('--engine')+1]
            backend = command[command.index('--backend')+1]
            key = engine + ('' if backend == 'native' else '@'+backend)
            result = dict(throughput_bps=1024, duration_seconds=1, latency_p95_seconds=.1, success_rate=1,
                          backend=backend,payload_bytes=4096,requests=32,concurrency=4,bytes_sent=131072,bytes_received=131072)
            return 0, json.dumps({'schema':'shadow6.network-suite.v1','results':{key:result}}), '', {}
        with patch('benchmark.available',return_value=True), patch('benchmark.network_unavailable',return_value=None), patch('benchmark.shutil.which',return_value='/usr/bin/node'), patch('benchmark.execute',side_effect=execute_case):
            result = run({'roles':['network-chain'],'network':{'payload_bytes':4096,'requests':8,'concurrency':4}})
        self.assertEqual(len(calls),36)
        self.assertEqual(len({(r['core'],r['backend']) for r in result['results']}),36)
        self.assertTrue(all(r['status']=='ok' for r in result['results']))
        for command in calls:
            self.assertTrue(command[1].endswith('integration/stack_test.py'))
            self.assertEqual(command[command.index('--payload-bytes')+1],'4096')
            self.assertEqual(command[command.index('--requests')+1],'8')
            self.assertEqual(command[command.index('--concurrency')+1],'4')
            self.assertNotIn('--benchmark-loopback',command)

    def test_stress_matrix_has_no_per_core_exemptions(self):
        from performance_matrix import run as matrix_run
        commands=[]
        def fail_case(command, timeout):
            commands.append(command)
            return 1, '', 'unavailable', {}
        with patch('performance_matrix.execute',side_effect=fail_case):
            result=matrix_run(list(ENGINES),1048576,concurrency=(1,4))
        self.assertEqual(len(result['results']),12*3*2*12)
        self.assertTrue(all(r['status']=='failed' for r in result['results']))
        workloads={}
        for row in result['results']:
            workloads.setdefault((row['engine'],row['backend']),set()).add((row['payload_bytes'],row['requests'],row['rtt_ms'],row['loss_percent'],row['concurrency']))
        self.assertEqual(len(workloads),36)
        self.assertTrue(all(v==next(iter(workloads.values())) for v in workloads.values()))

    def test_internal_benchmark_metrics_are_not_accepted(self):
        with self.assertRaises(ValueError):
            network_result(json.dumps(dict(schema='shadow6.network-chain.v1',throughput_bps=1,duration_seconds=1,latency_p95_seconds=1,success_rate=1)),'d')

    def test_zero_and_inconsistent_counts_fail(self):
        base=dict(throughput_bps=1,duration_seconds=1,latency_p95_seconds=0,success_rate=1,
                  backend='native',payload_bytes=512,requests=2,concurrency=1,bytes_sent=1024,bytes_received=1024)
        for change in ({'bytes_received':0},{'requests':0},{'bytes_received':512},{'backend':'node'}, {'concurrency':True}):
            value=base|change
            with self.subTest(change=change),self.assertRaises(ValueError):
                network_result(json.dumps({'schema':'shadow6.network-suite.v1','results':{'shadow6-go':value}}),'go')

    def test_required_network_rejects_unsupported_kernel(self):
        with patch('benchmark.available',return_value=True), patch('benchmark.network_unavailable',return_value='SCTP unavailable'):
            result=run({'cores':['cpp'],'roles':['network-chain'],'require_network':True})
        self.assertEqual(result['results'][0]['status'],'failed')

    def test_optional_network_records_unsupported_kernel(self):
        with patch('benchmark.available',return_value=True), patch('benchmark.network_unavailable',return_value='SCTP unavailable'):
            result=run({'cores':['cpp'],'roles':['network-chain'],'require_network':False})
        self.assertTrue(all(row['status']=='not_applicable' for row in result['results']))

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
