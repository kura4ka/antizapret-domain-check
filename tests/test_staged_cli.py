"""Network-free integration tests for staged scans and durable resume."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from azcheck import cli
from azcheck.checkpoint import ScanCheckpoint
from azcheck.scanner import scan_inventory


class Clock:
    def __init__(self):
        self.now = 1000000.0
        self.sleeps = []

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def response(domain, status='ok', code=200, **extra):
    return {'domain': domain, 'status': status, 'http_status': code,
            'curl_code': 0, 'address': '93.184.215.14',
            'detail': 'Isolated synthetic response; no network request.', **extra}


class StagedCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.az = self.root / 'native'
        (self.az / 'config').mkdir(parents=True)
        (self.az / 'config/include-hosts.txt').write_text(''.join(f'site{i}.example\n' for i in range(5)))
        self.reports = self.root / 'reports'
        self.clock = Clock()
        self.seen = []
        self.probe = lambda domain: response(domain)

    def synthetic_scan(self, inventory, **options):
        def probe(domain, **unused):
            self.seen.append((domain, self.clock.now))
            return self.probe(domain)

        return scan_inventory(inventory, probe_fn=probe, workers=1, interval_seconds=0,
                              retry_delay_seconds=0, attempts=options['attempts'],
                              completed=options['completed'], event=options.get('event'),
                              progress=options.get('progress'))

    def run_scan(self, *extra, scanner=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), \
             patch('azcheck.cli.shutil.which', return_value='curl'), \
             patch('azcheck.cli.scan_inventory', side_effect=scanner or self.synthetic_scan), \
             patch('azcheck.checkpoint.time.time', side_effect=lambda: self.clock.now), \
             patch('azcheck.cli.time.sleep', side_effect=self.clock.sleep):
            code = cli.main(['scan', '--az-dir', str(self.az), '--report-dir', str(self.reports),
                             '--batch-size', '2', '--batch-pause', '60', *extra])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_one_stage_resumes_without_duplicate_checks_and_saves_partial_then_full_reports(self):
        code, _, error = self.run_scan('--one-batch')
        self.assertEqual(code, 0, error)
        partial = json.loads((self.reports / 'latest.json').read_text())
        self.assertEqual(partial['progress']['completed'], 2)
        self.assertEqual(partial['progress']['total'], 5)
        self.assertEqual(partial['progress']['scope'], 'latest_batch')
        self.assertEqual(len(partial['results']), 2)
        self.assertFalse(self.clock.sleeps)

        code, _, error = self.run_scan('--one-batch')
        self.assertEqual(code, 0, error)
        self.assertGreaterEqual(sum(self.clock.sleeps), 60)
        self.assertIn('Resuming run', error)
        code, output, error = self.run_scan()
        self.assertEqual(code, 0, error)
        final = json.loads((self.reports / 'latest.json').read_text())
        self.assertEqual(final['progress']['completed'], 5)
        self.assertEqual(final['progress']['scope'], 'full_run')
        self.assertEqual(len(final['results']), 5)
        self.assertTrue(all('checked_at' in item for item in final['results']))
        self.assertEqual([domain for domain, _ in self.seen], [f'site{i}.example' for i in range(5)])
        self.assertIn('Checked 5 domains', output)
        self.assertEqual(len(list((self.reports / 'runs').glob('*/batch-*/latest.json'))), 3)

    def test_interruption_saves_completed_domain_and_next_command_resumes(self):
        def interrupt_after_result(inventory, **options):
            entry = inventory.entries[0]
            options['completed']({'domain': entry.domain, 'sources': entry.sources,
                                  'decision': 'reachable', 'reason': 'Synthetic check.',
                                  'warp_included': False, 'warp_excluded': False,
                                  'checks': [response(entry.domain)]})
            raise KeyboardInterrupt()

        code, _, error = self.run_scan(scanner=interrupt_after_result)
        self.assertEqual(code, 130, error)
        self.assertIn('completed checks are saved', error)
        self.assertEqual(json.loads((self.reports / 'latest.json').read_text())['progress']['completed'], 1)
        code, _, error = self.run_scan()
        self.assertEqual(code, 0, error)
        self.assertNotIn('site0.example', [domain for domain, _ in self.seen])
        self.assertEqual(len(json.loads((self.reports / 'latest.json').read_text())['results']), 5)

    def test_rate_limit_stops_stage_and_restart_honors_saved_retry_after(self):
        self.probe = lambda domain: response(domain, 'rate_limited', 429, retry_after_seconds=7200)
        code, _, error = self.run_scan()
        self.assertEqual(code, 0, error)
        self.assertEqual(len(self.seen), 1)
        self.assertIn('Rate limit received; scan stopped', error)
        with ScanCheckpoint(self.reports) as state:
            self.assertEqual(state.info()['pause_until'], self.clock.now + 7200)
            self.assertEqual(state.completed_count(), 1)
        self.assertFalse(self.clock.sleeps)

        self.probe = lambda domain: response(domain)
        before = self.clock.now
        code, _, error = self.run_scan('--restart', '--one-batch')
        self.assertEqual(code, 0, error)
        self.assertGreaterEqual(self.seen[1][1] - before, 7200)
        self.assertIn('Saved cooldown', error)

    def test_partial_candidate_file_is_cumulative_and_current_exclusions_apply_on_resume(self):
        self.probe = lambda domain: response(domain, 'blocked', 403) if domain == 'site0.example' else response(domain)
        code, _, error = self.run_scan('--one-batch', '--batch-size', '1')
        self.assertEqual(code, 0, error)
        candidates = self.reports / 'suggested-include-warp-hosts.txt'
        self.assertIn('site0.example\n', candidates.read_text())
        code, _, error = self.run_scan('--one-batch', '--batch-size', '1')
        self.assertEqual(code, 0, error)
        self.assertIn('site0.example\n', candidates.read_text())
        (self.az / 'config/exclude-warp-hosts.txt').write_text('site0.example\n')
        code, _, error = self.run_scan('--one-batch', '--batch-size', '1')
        self.assertEqual(code, 0, error)
        self.assertNotIn('site0.example\n', candidates.read_text())
        partial = json.loads((self.reports / 'latest.json').read_text())
        self.assertEqual(partial['progress']['counts']['excluded'], 1)

    def test_interrupt_during_rate_limit_callback_does_not_count_a_saved_domain_twice(self):
        original_pause = ScanCheckpoint.pause
        interrupted = False

        def pause_once(state, seconds, reason):
            nonlocal interrupted
            if reason == 'HTTP 429 rate limit' and not interrupted:
                interrupted = True
                raise KeyboardInterrupt()
            return original_pause(state, seconds, reason)

        self.probe = lambda domain: response(domain, 'rate_limited', 429)
        with patch.object(ScanCheckpoint, 'pause', new=pause_once):
            code, _, error = self.run_scan()
        self.assertEqual(code, 130, error)
        saved = json.loads((self.reports / 'latest.json').read_text())
        self.assertEqual(saved['progress']['scope'], 'latest_batch')
        self.assertEqual(saved['progress']['completed'], 1)
        self.assertEqual(saved['progress']['total'], 5)
        self.assertEqual(len(saved['results']), 1)
        with ScanCheckpoint(self.reports) as state:
            self.assertFalse(state.info()['completed'])
            self.assertEqual(state.info()['pause_reason'], 'HTTP 429 rate limit')


if __name__ == '__main__':
    unittest.main()
