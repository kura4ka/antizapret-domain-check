"""Decisions must be cautious and reports must never change native lists."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from azcheck import cli
from azcheck.domains import Inventory, InventoryEntry
from azcheck.scanner import classify, report_lock, scan_inventory, write_reports


def outcome(status='ok', code=200, curl_code=0, domain='example.org'):
    return {'domain': domain, 'status': status, 'http_status': code, 'curl_code': curl_code,
            'address': '93.184.215.14', 'detail': 'Synthetic test result; no request sent.'}


class DecisionTests(unittest.TestCase):
    def test_repeated_failures_are_only_tentative_candidates(self):
        entry = InventoryEntry('example.org')
        for failure in (outcome('blocked', 403), outcome('blocked', 451),
                        outcome('transport_error', None, 28), outcome('transport_error', None, 56)):
            with self.subTest(failure=failure):
                self.assertEqual(classify(entry, [failure, failure])[0], 'candidate')
                self.assertEqual(classify(entry, [failure])[0], 'inconclusive')

    def test_server_dns_rate_limit_cert_and_missing_curl_do_not_suggest_routing(self):
        entry = InventoryEntry('example.org')
        for failure in (outcome('server_error', 503), outcome('dns_error', None, None),
                        outcome('rate_limited', 429), outcome('transport_error', None, 60),
                        outcome('transport_error', None, 127)):
            with self.subTest(failure=failure):
                self.assertEqual(classify(entry, [failure, failure])[0], 'inconclusive')

    def test_transient_failure_does_not_become_a_candidate(self):
        self.assertEqual(classify(InventoryEntry('example.org'),
                                  [outcome('blocked', 403), outcome()])[0], 'reachable')

    def test_exclusions_override_includes_and_existing_rules_are_not_resuggested(self):
        failures = [outcome('blocked', 451)] * 2
        self.assertEqual(classify(InventoryEntry('example.org', included=True, excluded=True), failures)[0], 'excluded')
        self.assertEqual(classify(InventoryEntry('example.org', included=True), failures)[0], 'already_warp')


class ScannerTests(unittest.TestCase):
    def test_all_domains_are_checked_with_bounded_concurrency_and_retries(self):
        entries = [InventoryEntry(f'site{i}.example.org', [f'list.txt:{i + 1}']) for i in range(31)]
        lock = threading.Lock()
        active = maximum = 0
        seen = []

        def probe(domain, **options):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
                seen.append(domain)
            time.sleep(0.002)
            with lock:
                active -= 1
            return outcome('blocked', 403, domain=domain)

        progress = []
        results = scan_inventory(Inventory(entries, []), probe_fn=probe, workers=3,
                                 interval_seconds=0, retry_delay_seconds=0,
                                 progress=lambda done, total: progress.append((done, total)))
        self.assertLessEqual(maximum, 3)
        self.assertEqual(len(results), len(entries))
        self.assertEqual(len(seen), 2 * len(entries))
        self.assertEqual(set(seen), {entry.domain for entry in entries})
        self.assertEqual(progress[-1], (31, 31))
        self.assertEqual([result['domain'] for result in results], sorted(entry.domain for entry in entries))
        self.assertTrue(all(result['decision'] == 'candidate' for result in results))

    def test_success_and_infrastructure_failure_are_not_retried(self):
        seen = []

        def probe(domain, **options):
            seen.append(domain)
            return outcome(domain=domain) if domain.startswith('ok') else outcome('transport_error', None, 127, domain)

        entries = [InventoryEntry('ok.example.org'), InventoryEntry('error.example.org')]
        results = scan_inventory(Inventory(entries, []), probe_fn=probe, interval_seconds=0, retry_delay_seconds=0)
        self.assertCountEqual(seen, [entry.domain for entry in entries])
        self.assertEqual({result['decision'] for result in results}, {'reachable', 'inconclusive'})

    def test_reports_only_list_candidates_and_preserve_sources_and_warnings(self):
        entries = [InventoryEntry('blocked.example.org', ['include-hosts.txt:4']),
                   InventoryEntry('excluded.example.org', ['include-hosts.txt:5'], excluded=True)]
        inventory = Inventory(entries, ['Native catch-all cannot be probed.'])
        results = scan_inventory(inventory, probe_fn=lambda domain, **kw: outcome('blocked', 403, domain=domain),
                                 interval_seconds=0, retry_delay_seconds=0)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = root / 'include-warp-hosts.txt'
            native.write_bytes(b'# preserved\ncustom.example.org\n')
            reports = root / 'reports'
            with report_lock(reports):
                report = write_reports(reports, inventory, results)
            self.assertFalse(report['donor_tested'])
            self.assertEqual(report['counts'], {'candidate': 1, 'excluded': 1})
            self.assertEqual(json.loads((reports / 'latest.json').read_text()), report)
            suggestions = (reports / 'suggested-include-warp-hosts.txt').read_text()
            self.assertIn('blocked.example.org\n', suggestions)
            self.assertNotIn('excluded.example.org', suggestions)
            self.assertIn('include-hosts.txt:4', (reports / 'latest.txt').read_text())
            self.assertEqual(native.read_bytes(), b'# preserved\ncustom.example.org\n')

    def test_overlapping_scans_in_same_report_directory_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with report_lock(directory):
                with self.assertRaises(RuntimeError):
                    with report_lock(directory):
                        self.fail('Second scan acquired the lock')
            with report_lock(directory):
                pass


class CLITests(unittest.TestCase):
    def run_cli(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_configuration_errors_are_clear_and_cannot_start_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'config.json'
            documents = ['{"workers":true}', '{"interval_seconds":NaN}',
                         '{"attempts":1}', '{"include_download":"yes"}',
                         '{"unknown":1}', '{"workers":1,"workers":2}']
            for document in documents:
                with self.subTest(document=document):
                    config.write_text(document)
                    with patch('azcheck.cli.scan_inventory') as scan:
                        code, _, error = self.run_cli(['scan', '--config', str(config)])
                    self.assertEqual(code, 1)
                    self.assertIn('ERROR:', error)
                    scan.assert_not_called()

    def test_old_configuration_uses_full_inventory_and_new_report_default(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'config.json'
            original = {'report_dir': cli.LEGACY_REPORT_DIR, 'include_download': False,
                        'timeout_seconds': 12, 'workers': 3}
            config.write_text(json.dumps(original))
            args = cli.parser().parse_args(['scan', '--config', str(config)])
            settings = cli.load_settings(args)
            self.assertEqual(settings['report_dir'], '/root/antizapret-domain-check/reports')
            self.assertTrue(settings['include_download'])
            self.assertEqual(settings['timeout_seconds'], 12)
            self.assertEqual(settings['workers'], 3)
            self.assertEqual(json.loads(config.read_text()), original, 'Runtime migration must be read-only')
            config.write_text(json.dumps({'config_version': 2, 'include_download': False, 'report_dir': directory}))
            args = cli.parser().parse_args(['scan', '--config', str(config), '--az-dir', str(Path(directory) / 'native')])
            settings = cli.load_settings(args)
            self.assertFalse(settings['include_download'])
            self.assertEqual(settings['report_dir'], directory)

    def test_full_inventory_and_live_query_response_are_default_with_quiet_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            az = root / 'antizapret'
            (az / 'config').mkdir(parents=True)
            (az / 'download').mkdir()
            (az / 'result').mkdir()
            (az / 'config/include-hosts.txt').write_text('user.example\n')
            (az / 'result/include-hosts.txt').write_text('upstream.example\n')
            (az / 'result/include-warp-hosts.txt').write_text('')
            (az / 'download/bol-van-domain.txt').write_text('child.upstream.example\n')
            calls = []

            def synthetic_scan(inventory, **options):
                calls.append(inventory)
                return scan_inventory(inventory, probe_fn=lambda domain, **kw: outcome(domain=domain),
                                      interval_seconds=0, retry_delay_seconds=0,
                                      event=options.get('event'), progress=options.get('progress'))

            arguments = ['scan', '--az-dir', str(az), '--report-dir', str(root / 'reports')]
            with patch('azcheck.cli.scan_inventory', side_effect=synthetic_scan), patch('azcheck.cli.shutil.which', return_value='curl'):
                code, output, error = self.run_cli(arguments)
                self.assertEqual(code, 0, error)
                self.assertEqual([entry.domain for entry in calls[-1].entries],
                                 ['child.upstream.example', 'upstream.example', 'user.example'])
                self.assertIn('child.upstream.example attempt 1/2 QUERY', error)
                self.assertIn('child.upstream.example attempt 1/2 RESPONSE ok | HTTP 200 | curl 0 | IP', error)
                self.assertIn('Synthetic test result', error)
                self.assertIn('Checked 3 domains', output)
                code, output, error = self.run_cli(arguments + ['--quiet'])
                self.assertEqual(code, 0, error)
                self.assertEqual(output + error, '')
            saved = json.loads((root / 'reports/latest.json').read_text())
            self.assertTrue(saved['inventory']['include_download'])
            self.assertEqual(len(saved['inventory']['registry_files']), 1)

    def test_empty_or_missing_inventory_does_not_produce_successful_empty_report(self):
        with tempfile.TemporaryDirectory() as directory:
            code, _, error = self.run_cli(['scan', '--az-dir', str(Path(directory) / 'antizapret'),
                                           '--report-dir', str(Path(directory) / 'reports')])
            self.assertEqual(code, 1)
            self.assertIn('No domains found', error)
            self.assertFalse((Path(directory) / 'reports/latest.json').exists())

    def test_report_directory_cannot_become_an_antizapret_include_list(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'config'
            config.mkdir()
            native = config / 'include-hosts.txt'
            native.write_bytes(b'example.org\n')
            for report_dir in (config, root / 'download', root / 'nested/reports'):
                with self.subTest(report_dir=report_dir), patch('azcheck.cli.scan_inventory') as scan:
                    code, _, error = self.run_cli(['scan', '--az-dir', directory, '--report-dir', str(report_dir)])
                    self.assertEqual(code, 1)
                    self.assertIn('outside the AntiZapret', error)
                    scan.assert_not_called()
                    self.assertFalse((report_dir / 'suggested-include-warp-hosts.txt').exists())
            self.assertEqual(native.read_bytes(), b'example.org\n')

    def test_each_scan_rereads_user_include_hosts_and_does_not_change_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            az = root / 'antizapret'
            (az / 'config').mkdir(parents=True)
            native = az / 'config/include-hosts.txt'
            reports = root / 'reports'
            observed = []

            def synthetic_scan(inventory, **options):
                observed.append([entry.domain for entry in inventory.entries])
                return scan_inventory(inventory, probe_fn=lambda domain, **kw: outcome(domain=domain),
                                      interval_seconds=0, retry_delay_seconds=0)

            with patch('azcheck.cli.scan_inventory', side_effect=synthetic_scan), patch('azcheck.cli.shutil.which', return_value='curl'):
                for text in ('first.example.org\n', 'first.example.org\nsecond.example.org\n'):
                    native.write_text(text, encoding='utf-8', newline='\n')
                    code, _, error = self.run_cli(['scan', '--az-dir', str(az), '--report-dir', str(reports), '--quiet'])
                    self.assertEqual(code, 0, error)
                    self.assertEqual(native.read_text(), text)
            self.assertEqual(observed, [['first.example.org'], ['first.example.org', 'second.example.org']])
            self.assertEqual(len(json.loads((reports / 'latest.json').read_text())['results']), 2)


if __name__ == '__main__':
    unittest.main()
