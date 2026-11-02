"""Network-free coverage of fast-profile settings, DNS scope and checkpoints."""

from collections import Counter
from contextlib import nullcontext, redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from azcheck import cli
from azcheck.checkpoint import ScanCheckpoint
from azcheck.resolvers import parse_resolver


def native_plan():
    reference = parse_resolver('udp://127.3.3.3:53', allow_loopback=True)
    reference['role'] = 'reference'
    upstreams = [parse_resolver(value) for value in (
        'udp://1.1.1.1:53', 'udp://1.0.0.1:53', 'udp://9.9.9.10:53',
        'udp://149.112.112.10:53', 'udp://9.9.9.10:9953',
        'udp://149.112.112.10:9953', 'udp://76.76.2.0:53', 'udp://76.76.10.0:53',
        'udp://64.6.64.6:53', 'udp://64.6.65.6:53', 'udp://208.67.222.222:443',
        'udp://86.54.11.100:53')]
    return {'reference': reference, 'upstreams': upstreams, 'warnings': [], 'sources': [],
            'fingerprint': 'synthetic-native-plan', 'context': {
                'primary_resolver_ids': [endpoint['id'] for endpoint in upstreams],
                'primary_method': 'FORWARD', 'fallback_resolver_ids': [], 'custom_rules': []}}


def dns_response(domain, endpoint, timeout):
    return {'resolver': endpoint['id'], 'transport': endpoint['transport'],
            'status': 'ok', 'rcode': 'NOERROR', 'addresses': ['93.184.215.14'],
            'detail': 'Synthetic native DNS response; no network request.', 'elapsed_seconds': 0.001}


def https_response(domain, address, timeout):
    return {'domain': domain, 'status': 'ok', 'http_status': 200, 'curl_code': 0,
            'address': address, 'detail': 'Synthetic HTTPS response; no network request.'}


class FastSettingsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = self.root / 'config.json'

    def settings(self, document=None, *flags):
        self.config.write_text(json.dumps({'config_version': 4, **(document or {})}), encoding='utf-8')
        return cli.load_settings(cli.parser().parse_args(['scan', '--config', str(self.config), *flags]))

    def test_fast_profile_changes_only_scheduling_and_diagnostic_scope(self):
        document = {'antizapret_dir': str(self.root / 'native'),
                    'report_dir': str(self.root / 'custom-reports'),
                    'dns_config_dir': str(self.root / 'custom-knot'),
                    'attempts': 3, 'timeout_seconds': 12,
                    'include_download': True, 'workers': 3, 'interval_seconds': 1.0,
                    'dns_interval_seconds': 0.8, 'batch_size': 100, 'batch_pause_seconds': 600}
        for dns in ({'resolvers': ['udp://1.1.1.1:53'], 'resolver_url': ''},
                    {'resolvers': [], 'resolver_url': 'https://8.8.8.8/resolve'}):
            with self.subTest(dns=dns):
                settings = self.settings({**document, **dns}, '--fast')
                self.assertEqual(settings['workers'], 128)
                self.assertEqual(settings['interval_seconds'], 0)
                self.assertEqual(settings['dns_interval_seconds'], 0)
                self.assertEqual(settings['batch_size'], 5000)
                self.assertEqual(settings['batch_pause_seconds'], 0)
                self.assertEqual(settings['dns_checks'], 'reference')
                for key in ('antizapret_dir', 'report_dir', 'dns_config_dir', 'attempts',
                            'timeout_seconds', 'include_download'):
                    self.assertEqual(settings[key], document[key], key)
                self.assertEqual(settings['resolvers'], dns['resolvers'])
                self.assertEqual(settings['resolver_url'], dns['resolver_url'])

    def test_explicit_flags_override_fast_profile(self):
        settings = self.settings(None, '--fast', '--workers', '6', '--interval', '0.12',
                                 '--dns-interval', '0.09', '--batch-size', '80',
                                 '--batch-pause', '120', '--dns-checks', 'all')
        self.assertEqual(settings['workers'], 6)
        self.assertEqual(settings['interval_seconds'], 0.12)
        self.assertEqual(settings['dns_interval_seconds'], 0.09)
        self.assertEqual(settings['batch_size'], 80)
        self.assertEqual(settings['batch_pause_seconds'], 120)
        self.assertEqual(settings['dns_checks'], 'all')

    def test_plain_scan_retains_existing_conservative_defaults(self):
        settings = self.settings()
        self.assertEqual(settings['workers'], 2)
        self.assertEqual(settings['interval_seconds'], 0.5)
        self.assertEqual(settings['dns_interval_seconds'], 0.25)
        self.assertEqual(settings['batch_size'], 500)
        self.assertEqual(settings['batch_pause_seconds'], 300)
        self.assertEqual(settings['dns_checks'], 'all')
        self.assertFalse(settings['include_download'])

    def test_plain_scan_preserves_custom_scheduling_and_reference_scope(self):
        saved = {'workers': 7, 'interval_seconds': 0.1, 'dns_interval_seconds': 0.15,
                 'batch_size': 250, 'batch_pause_seconds': 240, 'dns_checks': 'reference'}
        settings = self.settings(saved)
        for key, value in saved.items():
            self.assertEqual(settings[key], value, key)

    def test_invalid_config_dns_scope_is_rejected(self):
        for value in ('invalid', None, False, 1, []):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'dns_checks must be'):
                self.settings({'dns_checks': value})

    def test_workers_and_both_pacers_reject_values_beyond_supported_limits(self):
        for flags, error in ((('--workers', '129'), 'workers must be'),
                             (('--interval', '-0.01'), 'interval_seconds must be'),
                             (('--dns-interval', '-0.01'), 'dns_interval_seconds must be')):
            with self.subTest(flags=flags), self.assertRaisesRegex(ValueError, error):
                self.settings(None, '--fast', *flags)


class FastNativeScanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.az = self.root / 'native'
        (self.az / 'config').mkdir(parents=True)
        (self.az / 'result').mkdir()
        (self.az / 'result/include-hosts.txt').write_text('a.example\nb.example\nc.example\n')
        self.reports = self.root / 'reports'
        self.config = self.root / 'config.json'
        self.config.write_text(json.dumps({'config_version': 4, 'antizapret_dir': str(self.az),
                                          'report_dir': str(self.reports)}))
        self.plan = native_plan()

    def invoke(self, *flags, query_fn=dns_response, https_fn=https_response, clock=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), \
             patch('azcheck.cli.discover_resolvers', side_effect=lambda *a, **k: deepcopy(self.plan)), \
             patch('azcheck.cli.shutil.which', return_value='curl'), \
             patch('azcheck.scanner._Pacer.wait', return_value=True), \
             (patch.object(ScanCheckpoint, 'pause_remaining', return_value=0) if clock is None else nullcontext()), \
             (patch('azcheck.checkpoint.time.time', side_effect=lambda: clock.now) if clock is not None else nullcontext()), \
             (patch('azcheck.cli.time.sleep', side_effect=clock.sleep) if clock is not None else nullcontext()), \
             patch('azcheck.probe.query_resolver', side_effect=query_fn) as query, \
             patch('azcheck.probe._https_head', side_effect=https_fn) as https, \
             patch('azcheck.probe._public_address') as doh, \
             patch('socket.getaddrinfo') as system_dns:
            code = cli.main(['scan', '--config', str(self.config), '--one-batch', *flags])
        doh.assert_not_called()
        system_dns.assert_not_called()
        return code, stdout.getvalue(), stderr.getvalue(), query, https

    def test_fast_native_scan_sends_one_dns_query_per_domain_and_reports_its_scope(self):
        code, _, error, query, https = self.invoke('--fast')
        self.assertEqual(code, 0, error)
        self.assertEqual(Counter(call.args[0] for call in query.call_args_list),
                         {'a.example': 1, 'b.example': 1, 'c.example': 1})
        self.assertTrue(all(call.args[1]['id'] == 'udp://127.3.3.3:53'
                            for call in query.call_args_list))
        self.assertEqual(https.call_count, 3)
        self.assertIn('DNS checks: reference; direct upstream diagnostics are skipped.', error)
        self.assertIn('Fresh-run DNS matrix: 3 queries before retries', error)
        report = json.loads((self.reports / 'latest.json').read_text())
        self.assertEqual(report['progress']['completed'], 3)
        self.assertEqual(report['progress']['scope'], 'full_run')
        self.assertEqual(report['inventory']['dns_plan']['dns_checks'], 'reference')
        self.assertEqual(len(report['inventory']['dns_plan']['upstreams']), 12)
        for result in report['results']:
            check = result['checks'][0]
            self.assertEqual(check['dns_mode'], 'antizapret')
            self.assertEqual(check['dns_checks_mode'], 'reference')
            self.assertEqual(check['dns_diagnostics_skipped'], 12)
            self.assertEqual(len(check['dns_checks']), 1)
        with ScanCheckpoint(self.reports) as checkpoint:
            self.assertEqual(checkpoint.info()['probe_context']['dns']['dns_checks'], 'reference')

    def test_switching_reference_to_all_changes_context_and_rechecks_completed_domain(self):
        code, _, error, first_query, _ = self.invoke('--fast', '--batch-size', '1')
        self.assertEqual(code, 0, error)
        self.assertEqual(first_query.call_count, 1)
        with ScanCheckpoint(self.reports) as checkpoint:
            first = checkpoint.info()
            self.assertEqual(checkpoint.completed_count(), 1)
        code, _, error, second_query, _ = self.invoke('--fast', '--dns-checks', 'all', '--batch-size', '1')
        self.assertEqual(code, 0, error)
        self.assertIn('cached checks were invalidated', error)
        self.assertEqual(second_query.call_count, 13)
        self.assertTrue(all(call.args[0] == 'a.example' for call in second_query.call_args_list))
        with ScanCheckpoint(self.reports) as checkpoint:
            second = checkpoint.info()
            self.assertEqual(checkpoint.completed_count(), 1)
            self.assertEqual(second['probe_context']['dns']['dns_checks'], 'all')
        self.assertNotEqual(first['run_id'], second['run_id'])
        self.assertNotEqual(first['probe_context_sha256'], second['probe_context_sha256'])

    def test_retry_failed_preserves_success_and_rechecks_only_candidate_and_inconclusive(self):
        def first_dns(domain, endpoint, timeout):
            answer = dns_response(domain, endpoint, timeout)
            if domain == 'c.example':
                answer.update(status='dns_error', rcode='NXDOMAIN', addresses=[])
            return answer

        def first_https(domain, address, timeout):
            result = https_response(domain, address, timeout)
            if domain == 'b.example':
                result.update(status='blocked', http_status=403)
            return result

        code, _, error, first_queries, _ = self.invoke('--fast', query_fn=first_dns, https_fn=first_https)
        self.assertEqual(code, 0, error)
        self.assertEqual(Counter(call.args[0] for call in first_queries.call_args_list),
                         {'a.example': 1, 'b.example': 2, 'c.example': 1})
        with ScanCheckpoint(self.reports) as checkpoint:
            initial = checkpoint.info()
            initial_results = {item['domain']: item for item in checkpoint.iter_results()}
        self.assertEqual(initial_results['a.example']['decision'], 'reachable')
        self.assertEqual(initial_results['b.example']['decision'], 'candidate')
        self.assertEqual(initial_results['c.example']['decision'], 'inconclusive')

        code, _, error, retried, _ = self.invoke('--fast', '--retry-failed')
        self.assertEqual(code, 0, error)
        self.assertEqual(Counter(call.args[0] for call in retried.call_args_list),
                         {'b.example': 1, 'c.example': 1})
        with ScanCheckpoint(self.reports) as checkpoint:
            current = checkpoint.info()
            current_results = {item['domain']: item for item in checkpoint.iter_results()}
            self.assertEqual(checkpoint.completed_count(), 3)
        self.assertEqual(current['probe_context_sha256'], initial['probe_context_sha256'])
        self.assertEqual(current_results['a.example'], initial_results['a.example'])
        self.assertTrue(all(item['decision'] == 'reachable' for item in current_results.values()))
        report = json.loads((self.reports / 'latest.json').read_text())
        self.assertEqual(report['progress']['completed'], 3)
        self.assertEqual(report['progress']['scope'], 'full_run')

        code, _, error, no_failures, _ = self.invoke('--fast', '--retry-failed')
        self.assertEqual(code, 0, error)
        no_failures.assert_not_called()

    def test_retry_failed_fast_mode_keeps_saved_http429_cooldown(self):
        class Clock:
            now = 1000000.0

            def __init__(self):
                self.sleeps = []

            def sleep(self, seconds):
                self.sleeps.append(seconds)
                self.now += seconds

        clock = Clock()

        def limited(domain, address, timeout):
            result = https_response(domain, address, timeout)
            result.update(status='rate_limited', http_status=429, retry_after_seconds=7200)
            return result

        code, _, error, first_query, _ = self.invoke('--fast', '--workers', '1',
                                                    https_fn=limited, clock=clock)
        self.assertEqual(code, 0, error)
        self.assertIn('Rate limit received; scan stopped', error)
        first_query.assert_called_once()
        with ScanCheckpoint(self.reports) as checkpoint:
            deadline = checkpoint.info()['pause_until']
        self.assertEqual(deadline, 1007200.0)
        self.assertFalse(clock.sleeps)

        query_times = []

        def after_cooldown(domain, endpoint, timeout):
            query_times.append(clock.now)
            return dns_response(domain, endpoint, timeout)

        code, _, error, _, _ = self.invoke('--fast', '--retry-failed', '--workers', '1',
                                          query_fn=after_cooldown, clock=clock)
        self.assertEqual(code, 0, error)
        self.assertIn('Saved cooldown:', error)
        self.assertTrue(query_times)
        self.assertGreaterEqual(min(query_times), deadline)
        self.assertGreaterEqual(sum(clock.sleeps), 7200)


if __name__ == '__main__':
    unittest.main()
