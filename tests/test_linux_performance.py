import importlib.util
import json
from pathlib import Path
import unittest
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('benchmark', ROOT / 'tools/benchmark_linux_console.py')
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


class PerformanceTests(unittest.TestCase):
    def probe(self, iterations=10):
        return json.dumps({'probe': 'compatforge-console-v1', 'iterations': iterations,
                           'checksum': benchmark.expected_checksum(iterations), 'workNanoseconds': 1000})

    def test_json_publication_never_leaves_success_file_on_write_failure(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'summary.json'
            def interrupted(value, stream, **kwargs):
                stream.write('{"partial":')
                raise OSError('disk full')
            with mock.patch.object(benchmark.json, 'dump', interrupted), self.assertRaises(OSError):
                benchmark.write_json(path, {'valid': True})
            self.assertFalse(path.exists())
            benchmark.write_json(path, {'valid': True})
            with self.assertRaises(FileExistsError):
                benchmark.write_json(path, {'valid': False})
            self.assertEqual(json.loads(path.read_text()), {'valid': True})

    def test_reference_checksum_matches_loop(self):
        for count in (0, 1, 10, 10000):
            value = 0x12345678
            for _ in range(count):
                value = (1664525 * value + 1013904223) & 0xffffffff
            self.assertEqual(benchmark.expected_checksum(count), f'{value:08x}')

    def test_probe_rejects_wrong_work_and_checksum(self):
        self.assertEqual(benchmark.validate_probe(self.probe(), 10)['iterations'], 10)
        for value in (self.probe().replace('checksum', 'bad'), self.probe(11),
                      self.probe().replace(benchmark.expected_checksum(10), '00000000'),
                      self.probe() + '\n' + self.probe(), self.probe().replace('1000', 'NaN')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                benchmark.validate_probe(value, 10)

    def events(self):
        return [dict(schemaVersion='1', requestId='request', sequence=i, elapsedMilliseconds=i, **event)
                for i, event in enumerate([
                    {'kind': 'started', 'processId': 100},
                    {'kind': 'output', 'output': {'stream': 'stdout', 'text': self.probe() + '\r\n'}},
                    {'kind': 'wine-server-stop-requested'},
                    {'kind': 'exited', 'exit': {'code': 0, 'success': True}}])]

    def test_events_require_successful_child_and_complete_lifecycle(self):
        events = self.events()
        self.assertEqual(benchmark.validate_events(events, 'request', 10)['iterations'], 10)
        for bad in (events[:-1], events + [events[-1]], events[1:]):
            with self.assertRaises(ValueError):
                benchmark.validate_events(bad, 'request', 10)
        for exit_value in ({'code': 1, 'success': False}, {'code': False, 'success': True}):
            bad = self.events()
            bad[-1]['exit'] = exit_value
            with self.assertRaises(ValueError):
                benchmark.validate_events(bad, 'request', 10)

    def test_summary_refuses_incomplete_nonfinite_setup_or_failed_samples(self):
        good = [{'phase': 'warm', 'valid': True, 'elapsedSeconds': v, 'returnCode': 0}
                for v in (1., 2., 3., 4., 5.)]
        self.assertEqual(benchmark.summarize(good)['medianSeconds'], 3.)
        for bad in (good[:4], good + [dict(good[0], phase='initialization')],
                    good + [dict(good[0], elapsedSeconds=float('nan'))],
                    good + [dict(good[0], elapsedSeconds=-1)],
                    good + [dict(good[0], returnCode=1)],
                    good + [dict(good[0], valid=False)]):
            with self.assertRaises(ValueError):
                benchmark.summarize(bad)

    def test_direct_spec_uses_exact_plan_environment_and_cwd(self):
        plan = {'runtime': {'provider': 'wine'}, 'translator': {'provider': 'native'},
                'graphics': {'backend': 'wined3d'},
                'guestArtifact': {'storedPath': '/store/object', 'digest': 'sha256:' + 'a'*64},
                'process': {'executable': '/runtime/wine', 'arguments': ['/store/object', '10'],
                            'environment': {'WINEPREFIX': '/private/prefix', 'WINEDEBUG': '-all'},
                            'workingDirectory': '/private'},
                'lifecycle': {'wineserver': {'executable': '/runtime/wineserver', 'prefix': '/private/prefix'}}}
        spec = benchmark.direct_spec(plan)
        self.assertEqual(spec['argv'], ['/runtime/wine', '/store/object.exe', '10'])
        self.assertEqual(spec['environment'], plan['process']['environment'])
        self.assertEqual(spec['cwd'], '/private')
        other = dict(spec, environment={'WINEPREFIX': '/another/prefix'})
        with self.assertRaises(ValueError):
            benchmark.validate_match(spec, other)
        plan['translator']['provider'] = 'fex'
        with self.assertRaises(ValueError):
            benchmark.direct_spec(plan)


@unittest.skipUnless(sys.platform == 'linux', 'Linux subprocess bounds')
class CommandTests(unittest.TestCase):
    def test_direct_capture_does_not_time_descendants_pipe_lifetime(self):
        import time
        with tempfile.TemporaryDirectory() as directory:
            journal = benchmark.Journal(Path(directory), 5)
            record, text = journal.run('root', [sys.executable, '-c',
                'import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time; time.sleep(0.6)"]); print("root done")'],
                root_exit=True)
            self.assertEqual(text.strip(), 'root done')
            self.assertLess(record['elapsedSeconds'], 0.5)
            time.sleep(0.7)  # Reap fixture pipe holders before deleting temporary output.

    def test_stop_allows_absent_server_only_with_wait_and_no_prefix_process(self):
        import os
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server = root / 'server'
            server.write_text('#!' + sys.executable + '\nimport sys\nsys.exit(1 if sys.argv[1] == "-k" else 0)\n')
            server.chmod(0o700)
            spec = {'environment': {'WINEPREFIX': str(root / 'prefix')}, 'cwd': str(root)}
            journal = benchmark.Journal(root, 5)
            self.assertGreaterEqual(benchmark.stop_server(journal, 'absent', str(server), spec), 0)
            self.assertEqual([r['returnCode'] for r in journal.commands], [1, 0])
            child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'], env=spec['environment'])
            try:
                with self.assertRaisesRegex(ValueError, 'prefix process remains'):
                    benchmark.stop_server(journal, 'remaining', str(server), spec)
            finally:
                child.terminate()
                child.wait()
            server.write_text('#!' + sys.executable + '\nimport sys\nsys.exit(2)\n')
            with self.assertRaises(ValueError):
                benchmark.stop_server(journal, 'bad', str(server), spec)

    def test_failure_timeout_and_output_limit_keep_exit_receipts(self):
        cases = [('exit', 'import sys; print("before failure"); sys.exit(7)', 5, 7),
                 ('timeout', 'import time; time.sleep(10)', 0.1, -9),
                 ('overflow', 'import sys; sys.stdout.write("x"*2000000); sys.stdout.flush()', 5, None)]
        for name, code, timeout, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                journal = benchmark.Journal(root, timeout)
                with self.assertRaises(ValueError):
                    journal.run(name, [sys.executable, '-I', '-S', '-c', code])
                record = json.loads((root / 'commands.jsonl').read_text())
                if expected is not None:
                    self.assertEqual(record['returnCode'], expected)
                self.assertLessEqual(record['stdout']['bytes'] + record['stderr']['bytes'], benchmark.LIMIT)
                for stream in ('stdout', 'stderr'):
                    self.assertEqual(benchmark.digest(root / record[stream]['file']), record[stream]['sha256'])
                self.assertFalse((root / 'summary.json').exists())

if __name__ == '__main__':
    unittest.main()
