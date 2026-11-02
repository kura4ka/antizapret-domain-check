"""Per-origin throttling must not stop unrelated destinations or erase work."""

from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from azcheck import cli, scanner
from azcheck.checkpoint import ScanCheckpoint
from azcheck.domains import Inventory, InventoryEntry
from azcheck.resolvers import parse_resolver


ADDRESS = '93.184.215.14'


def answer(domain, status='ok', code=200, **extra):
    return {'domain': domain, 'status': status, 'http_status': code, 'curl_code': 0,
            'address': ADDRESS, 'detail': 'Synthetic response; no network request.', **extra}


class ScannerRateScopeTests(unittest.TestCase):
    def test_only_origin_scoped_rate_limits_allow_other_domains_to_continue(self):
        inventory = Inventory([InventoryEntry('a.example'), InventoryEntry('b.example')], [])
        for scope, expected in (('origin', ['a.example', 'b.example']),
                                ('resolver', ['a.example']), (None, ['a.example']),
                                ('unknown', ['a.example'])):
            with self.subTest(scope=scope):
                calls = []

                def probe(domain, **unused):
                    calls.append(domain)
                    if domain == 'a.example':
                        fields = {} if scope is None else {'rate_limit_scope': scope}
                        return answer(domain, 'rate_limited', 429, retry_after_seconds=60, **fields)
                    return answer(domain)

                saved = []
                results = scanner.scan_inventory(inventory, probe_fn=probe, workers=1,
                                                 interval_seconds=0, retry_delay_seconds=0,
                                                 completed=saved.append)
                self.assertEqual(calls, expected)
                self.assertEqual([item['domain'] for item in results], expected)
                self.assertEqual(len(saved), len(expected))

    def test_global_predicate_keeps_ambiguous_and_resolver_limits_conservative(self):
        for value, expected in (
            (answer('a.example'), False),
            (answer('a.example', rate_limit_scope='resolver'), False),
            (answer('a.example', 'rate_limited', 429, rate_limit_scope='origin'), False),
            (answer('a.example', 'rate_limited', 429, rate_limit_scope='resolver'), True),
            (answer('a.example', 'rate_limited', 429), True),
            (answer('a.example', 'transport_error', 429), True),
            (answer('a.example', 'rate_limited', None, rate_limit_scope='unknown'), True),
        ):
            with self.subTest(probe=value):
                self.assertEqual(scanner.is_global_rate_limit(value), expected)


class Clock:
    def __init__(self):
        self.now = 1000000.0
        self.sleeps = []

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class OriginRateLimitCLITests(unittest.TestCase):
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
        reference = parse_resolver('udp://127.3.3.3:53', allow_loopback=True)
        reference['role'] = 'reference'
        upstream = parse_resolver('udp://1.1.1.1:53')
        self.plan = {'reference': reference, 'upstreams': [upstream], 'warnings': [],
                     'sources': [], 'fingerprint': 'synthetic-scoped-plan',
                     'context': {'primary_resolver_ids': [upstream['id']],
                                 'primary_method': 'FORWARD', 'fallback_resolver_ids': [],
                                 'custom_rules': []}}
        self.clock = Clock()

    def invoke(self, *flags, https_fn=None):
        stdout, stderr = io.StringIO(), io.StringIO()

        def dns_response(domain, endpoint, timeout):
            return {'resolver': endpoint['id'], 'status': 'ok', 'rcode': 'NOERROR',
                    'transport': endpoint['transport'], 'addresses': [ADDRESS],
                    'detail': 'Synthetic DNS response; no network request.'}

        def https_response(domain, address, timeout):
            return answer(domain)

        with redirect_stdout(stdout), redirect_stderr(stderr), \
             patch('azcheck.cli.discover_resolvers', side_effect=lambda *a, **k: deepcopy(self.plan)), \
             patch('azcheck.cli.shutil.which', return_value='curl'), \
             patch('azcheck.scanner._Pacer.wait', return_value=True), \
             patch('azcheck.checkpoint.time.time', side_effect=lambda: self.clock.now), \
             patch('azcheck.cli.time.sleep', side_effect=self.clock.sleep), \
             patch('azcheck.probe.query_resolver', side_effect=dns_response) as query, \
             patch('azcheck.probe._https_head', side_effect=https_fn or https_response) as https, \
             patch('azcheck.probe._public_address') as doh, \
             patch('socket.getaddrinfo') as system_dns:
            code = cli.main(['scan', '--config', str(self.config), '--fast', '--workers', '1',
                             '--one-batch', *flags])
        doh.assert_not_called()
        system_dns.assert_not_called()
        return code, stdout.getvalue(), stderr.getvalue(), query, https

    def one_origin_limited(self, domain, address, timeout):
        return (answer(domain, 'rate_limited', 429, rate_limit_scope='origin', retry_after_seconds=7200)
                if domain == 'a.example' else answer(domain))

    def saved(self):
        with patch('azcheck.checkpoint.time.time', side_effect=lambda: self.clock.now), \
             ScanCheckpoint(self.reports) as checkpoint:
            return (checkpoint.info(), {item['domain']: item for item in checkpoint.iter_results()},
                    checkpoint.origin_cooldowns())

    def test_origin429_completes_other_domains_without_a_global_pause(self):
        code, _, error, query, https = self.invoke(https_fn=self.one_origin_limited)
        self.assertEqual(code, 0, error)
        self.assertEqual([call.args[0] for call in query.call_args_list],
                         ['a.example', 'b.example', 'c.example'])
        self.assertEqual(https.call_count, 3)
        self.assertFalse(self.clock.sleeps)
        self.assertNotIn('scan stopped', error)
        info, results, cooldowns = self.saved()
        self.assertEqual(len(results), 3)
        self.assertEqual(info['pause_until'], 0)
        self.assertEqual(cooldowns, {'a.example': 1007200.0})
        self.assertEqual(results['a.example']['decision'], 'inconclusive')
        self.assertEqual(results['b.example']['decision'], 'reachable')
        self.assertEqual(results['c.example']['decision'], 'reachable')
        report = json.loads((self.reports / 'latest.json').read_text())
        self.assertEqual(report['progress']['completed'], 3)
        self.assertEqual(report['progress']['scope'], 'full_run')

    def test_retry_failed_skips_cooling_origin_and_preserves_successful_results(self):
        code, _, error, _, _ = self.invoke(https_fn=self.one_origin_limited)
        self.assertEqual(code, 0, error)
        before, results_before, cooldowns_before = self.saved()
        code, _, error, query, https = self.invoke('--retry-failed')
        self.assertEqual(code, 0, error)
        query.assert_not_called()
        https.assert_not_called()
        self.assertFalse(self.clock.sleeps)
        after, results_after, cooldowns_after = self.saved()
        self.assertEqual(results_after, results_before)
        self.assertEqual(cooldowns_after, cooldowns_before)
        self.assertEqual(after['probe_context_sha256'], before['probe_context_sha256'])
        self.assertEqual(after['run_id'], before['run_id'])

    def test_restart_defers_cooling_origin_without_dns_or_extending_its_deadline(self):
        code, _, error, _, _ = self.invoke(https_fn=self.one_origin_limited)
        self.assertEqual(code, 0, error)
        _, _, before = self.saved()
        code, _, error, query, https = self.invoke('--restart')
        self.assertEqual(code, 0, error)
        self.assertEqual(Counter(call.args[0] for call in query.call_args_list),
                         {'b.example': 1, 'c.example': 1})
        self.assertEqual(Counter(call.args[0] for call in https.call_args_list),
                         {'b.example': 1, 'c.example': 1})
        self.assertFalse(self.clock.sleeps)
        _, results, after = self.saved()
        self.assertEqual(after, before)
        self.assertEqual(len(results), 3)
        self.assertEqual(results['a.example']['checks'][0]['status'], 'rate_limited')
        self.assertEqual(results['a.example']['checks'][0]['rate_limit_scope'], 'origin')

    def test_retry_failed_after_origin_expiry_rechecks_only_that_domain(self):
        code, _, error, _, _ = self.invoke(https_fn=self.one_origin_limited)
        self.assertEqual(code, 0, error)
        _, before, _ = self.saved()
        self.clock.now += 7201
        code, _, error, query, https = self.invoke('--retry-failed')
        self.assertEqual(code, 0, error)
        self.assertEqual([call.args[0] for call in query.call_args_list], ['a.example'])
        https.assert_called_once()
        _, after, _ = self.saved()
        self.assertEqual(after['b.example'], before['b.example'])
        self.assertEqual(after['c.example'], before['c.example'])
        self.assertEqual(after['a.example']['decision'], 'reachable')

    def test_legacy_native_origin_pause_converts_without_resetting_saved_work(self):
        code, _, error, _, _ = self.invoke('--batch-size', '1')
        self.assertEqual(code, 0, error)
        before, before_results, _ = self.saved()
        old_probe = answer('b.example', 'rate_limited', 429, retry_after_seconds=3600)
        old_probe.update(dns_mode='antizapret', dns_reference='udp://127.3.3.3:53')
        with patch('azcheck.checkpoint.time.time', side_effect=lambda: self.clock.now), \
             ScanCheckpoint(self.reports) as checkpoint:
            checkpoint.save_result({'domain': 'b.example', 'decision': 'inconclusive',
                                    'reason': 'Saved old result.', 'sources': [], 'checks': [old_probe]})
            checkpoint.pause(3600, 'HTTP 429 rate limit')
            self.assertEqual(checkpoint.completed_count(), 2)
        code, _, error, query, _ = self.invoke()
        self.assertEqual(code, 0, error)
        self.assertEqual([call.args[0] for call in query.call_args_list], ['c.example'])
        self.assertFalse(self.clock.sleeps)
        after, results, cooldowns = self.saved()
        self.assertEqual(after['run_id'], before['run_id'])
        self.assertEqual(after['probe_context_sha256'], before['probe_context_sha256'])
        self.assertEqual(results['a.example'], before_results['a.example'])
        self.assertEqual(len(results), 3)
        self.assertEqual(after['pause_until'], 0)
        self.assertEqual(cooldowns, {'b.example': 1003600.0})

    def test_ambiguous_legacy_doh_pause_remains_global(self):
        inventory = Inventory([InventoryEntry('a.example')], [])
        context = {'probe_version': 2, 'dns': {'mode': 'explicit-doh',
                    'resolver_url': 'https://1.1.1.1/dns-query', 'dns_checks': 'reference'}}
        old_probe = answer('a.example', 'rate_limited', 429, retry_after_seconds=3600)
        old_probe['dns_mode'] = 'explicit-doh'
        with patch('azcheck.checkpoint.time.time', side_effect=lambda: self.clock.now), \
             ScanCheckpoint(self.reports) as checkpoint:
            checkpoint.prepare(inventory, probe_context=context)
            checkpoint.save_result({'domain': 'a.example', 'decision': 'inconclusive',
                                    'reason': 'Ambiguous legacy result.', 'sources': [], 'checks': [old_probe]})
            checkpoint.pause(3600, 'HTTP 429 rate limit')
            before = checkpoint.info()
            self.assertFalse(checkpoint.release_legacy_origin_pause())
            after = checkpoint.info()
            self.assertEqual(after['pause_until'], 1003600.0)
            self.assertEqual(after['pause_reason'], 'HTTP 429 rate limit')
            self.assertEqual(after['run_id'], before['run_id'])
            self.assertEqual(checkpoint.completed_count(), 1)
            self.assertEqual(checkpoint.origin_cooldowns(), {})


if __name__ == '__main__':
    unittest.main()
