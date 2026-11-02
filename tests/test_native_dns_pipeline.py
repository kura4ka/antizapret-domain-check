"""Network-free coverage of native DNS plans, probes, resume, and audit output."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from azcheck import cli
from azcheck.checkpoint import ScanCheckpoint
from azcheck.domains import Inventory, InventoryEntry
from azcheck.probe import check_domain
from azcheck.resolvers import ResolverError, parse_resolver
from azcheck.scanner import scan_inventory, write_reports


DOMAIN = 'www.example.com'
REFERENCE_IP = '93.184.215.14'


def native_plan():
    reference = parse_resolver('udp://127.3.3.3:53', allow_loopback=True)
    reference['role'] = 'reference'
    cloudflare = parse_resolver('udp://1.1.1.1:53')
    quad9 = parse_resolver('udp://9.9.9.9:53')
    custom = parse_resolver('udp://8.8.8.8:53')
    return {
        'mode': 'antizapret', 'reference': reference,
        'upstreams': [cloudflare, quad9, custom], 'warnings': [], 'sources': [],
        'fingerprint': 'fixture-a',
        'context': {
            'primary_resolver_ids': [cloudflare['id'], cloudflare['id']],
            'primary_method': 'FORWARD',
            'fallback_resolver_ids': [quad9['id'], cloudflare['id']],
            'custom_rules': [{'suffixes': ['custom.example'], 'method': 'STUB',
                              'resolver_ids': [custom['id'], custom['id']]}],
        },
    }


def dns_response(domain, endpoint, timeout):
    address = REFERENCE_IP if endpoint.get('role') == 'reference' else '8.8.4.4'
    return {'resolver': endpoint['id'], 'transport': endpoint['transport'],
            'status': 'ok', 'rcode': 'NOERROR', 'addresses': [address],
            'detail': 'Synthetic DNS answer; no network request.', 'elapsed_seconds': 0.001}


def https_response(domain, address, timeout):
    return {'domain': domain, 'status': 'ok', 'http_status': 200, 'curl_code': 0,
            'address': address, 'detail': 'Synthetic HTTPS response; no network request.'}


class NativeDNSProbeTests(unittest.TestCase):
    def setUp(self):
        self.plan = native_plan()

    def test_native_matrix_queries_every_applicable_unique_endpoint_and_paces_each(self):
        events = []
        with patch('azcheck.probe.query_resolver', side_effect=dns_response) as query, \
             patch('azcheck.probe._https_head', side_effect=https_response) as https, \
             patch('azcheck.probe._public_address') as doh, \
             patch('socket.getaddrinfo') as system_dns:
            pacer = Mock(return_value=True)
            result = check_domain(DOMAIN, timeout=3, resolver_plan=self.plan,
                                  dns_pacer=pacer, dns_event=events.append)
        expected = ['udp://127.3.3.3:53', 'udp://1.1.1.1:53', 'udp://9.9.9.9:53']
        self.assertEqual([call.args[1]['id'] for call in query.call_args_list], expected)
        self.assertEqual(pacer.call_count, len(expected))
        self.assertEqual([(event['type'], event['resolver']) for event in events],
                         [(kind, resolver) for resolver in expected
                          for kind in ('dns_start', 'dns_result')])
        self.assertTrue(all(event['domain'] == DOMAIN for event in events))
        self.assertEqual([answer['resolver'] for answer in result['dns_checks']], expected)
        self.assertEqual(result['dns_mode'], 'antizapret')
        self.assertEqual(result['dns_reference'], expected[0])
        https.assert_called_once_with(DOMAIN, REFERENCE_IP, 3.0)
        doh.assert_not_called()
        system_dns.assert_not_called()

    def test_custom_stub_selects_only_its_endpoints_without_primary_or_fallback(self):
        with patch('azcheck.probe.query_resolver', side_effect=dns_response) as query, \
             patch('azcheck.probe._https_head', side_effect=https_response):
            check_domain('child.custom.example', resolver_plan=self.plan)
        self.assertEqual([call.args[1]['id'] for call in query.call_args_list],
                         ['udp://127.3.3.3:53', 'udp://8.8.8.8:53'])

    def test_reference_failure_never_uses_diagnostic_public_answer_for_https(self):
        for status, rcode in [('dns_error', 'NXDOMAIN'), ('skipped', 'NOERROR')]:
            with self.subTest(status=status):
                def answer(domain, endpoint, timeout):
                    result = dns_response(domain, endpoint, timeout)
                    if endpoint.get('role') == 'reference':
                        result.update(status=status, rcode=rcode, addresses=[])
                    return result
                with patch('azcheck.probe.query_resolver', side_effect=answer) as query, \
                     patch('azcheck.probe._https_head') as https:
                    result = check_domain(DOMAIN, resolver_plan=self.plan)
                self.assertEqual(query.call_count, 3)
                https.assert_not_called()
                self.assertEqual(result['status'], 'dns_error')
                self.assertNotIn('incomplete', result)
                self.assertEqual(len(result['dns_checks']), 3)

    def test_pacer_cancellation_leaves_matrix_incomplete_and_skips_https(self):
        with patch('azcheck.probe.query_resolver', side_effect=dns_response) as query, \
             patch('azcheck.probe._https_head') as https:
            pacer = iter((True, False))
            result = check_domain(DOMAIN, resolver_plan=self.plan,
                                  dns_pacer=lambda: next(pacer))
        query.assert_called_once()
        https.assert_not_called()
        self.assertTrue(result['incomplete'])
        self.assertEqual(result['status'], 'dns_error')
        self.assertEqual(len(result['dns_checks']), 1)

    def test_preexisting_cancellation_sends_no_dns_or_https(self):
        with patch('azcheck.probe.query_resolver') as query, \
             patch('azcheck.probe._https_head') as https:
            result = check_domain(DOMAIN, resolver_plan=self.plan,
                                  cancelled=lambda: True)
        query.assert_not_called()
        https.assert_not_called()
        self.assertTrue(result['incomplete'])
        self.assertEqual(result['dns_checks'], [])

    def test_cancelled_after_matrix_prevents_https_and_retains_resolver_diagnostics(self):
        with patch('azcheck.probe.query_resolver', side_effect=dns_response), \
             patch('azcheck.probe._https_head') as https:
            result = check_domain(DOMAIN, resolver_plan=self.plan,
                                  cancelled=Mock(side_effect=[False, False, False, True]))
        https.assert_not_called()
        self.assertTrue(result['incomplete'])
        self.assertEqual(len(result['dns_checks']), 3)

    def test_scanner_does_not_checkpoint_an_incomplete_dns_matrix(self):
        inventory = Inventory([InventoryEntry(DOMAIN)], [])
        completed, progress, events = [], [], []

        def probe(domain, **options):
            pacer = iter((True, False))
            return check_domain(domain, **options, resolver_plan=self.plan,
                                dns_pacer=lambda: next(pacer))

        with patch('azcheck.probe.query_resolver', side_effect=dns_response), \
             patch('azcheck.probe._https_head') as https:
            results = scan_inventory(inventory, probe_fn=probe, workers=1,
                                     interval_seconds=0, retry_delay_seconds=0,
                                     completed=completed.append, event=events.append,
                                     progress=lambda done, total: progress.append((done, total)))
        self.assertEqual(results, [])
        self.assertEqual(completed, [])
        self.assertEqual(progress, [])
        self.assertTrue(events[-1]['result']['incomplete'])
        https.assert_not_called()

    def test_reports_preserve_native_reference_and_all_resolver_answers(self):
        inventory = Inventory([InventoryEntry(DOMAIN, ['fixture:1'])], [])

        def probe(domain, **options):
            return check_domain(domain, **options, resolver_plan=self.plan)

        with patch('azcheck.probe.query_resolver', side_effect=dns_response), \
             patch('azcheck.probe._https_head', side_effect=https_response):
            results = scan_inventory(inventory, probe_fn=probe, interval_seconds=0)
        with tempfile.TemporaryDirectory() as directory:
            write_reports(directory, inventory, results)
            report = json.loads((Path(directory) / 'latest.json').read_text(encoding='utf-8'))
            text = (Path(directory) / 'latest.txt').read_text(encoding='utf-8')
        check = report['results'][0]['checks'][0]
        self.assertEqual(check['dns_reference'], self.plan['reference']['id'])
        self.assertEqual(check['dns_mode'], 'antizapret')
        self.assertEqual(len(check['dns_checks']), 3)
        for answer in check['dns_checks']:
            self.assertIn('DNS ' + answer['resolver'] + ': ok | NOERROR', text)
            self.assertIn(answer['addresses'][0], text)


class NativeDNSCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.az = self.root / 'antizapret'
        self.reports = self.root / 'reports'
        for directory in ('config', 'result', 'download'):
            (self.az / directory).mkdir(parents=True)
        self.write('result/include-hosts.txt', 'example.com\n')
        self.write('config/include-hosts.txt', 'user.example\n')
        self.write('download/bol-van-domain.txt', 'child.example.com\nunrouted.example\n')
        self.write('download/antifilter-download-domain.txt', 'child.example.com\n')

    def write(self, path, value):
        (self.az / path).write_text(value, encoding='utf-8')

    def invoke(self, command, *options):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main([command, '--az-dir', str(self.az),
                             '--report-dir', str(self.reports), *options])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_audit_compares_effective_and_raw_sources_without_any_network_requests(self):
        original = {path: path.read_bytes() for path in self.az.rglob('*') if path.is_file()}
        with patch('azcheck.cli.dns_plan', return_value=native_plan()), \
             patch('azcheck.probe.query_resolver') as query, \
             patch('azcheck.probe._https_head') as https, \
             patch('azcheck.probe._public_address') as doh, \
             patch('azcheck.cli.scan_inventory') as scan:
            code, output, error = self.invoke('audit', '--compare-download')
        self.assertEqual(code, 0, error)
        query.assert_not_called()
        https.assert_not_called()
        doh.assert_not_called()
        scan.assert_not_called()
        audit = json.loads((self.reports / 'inventory-audit.json').read_text())
        self.assertEqual(audit['unique_count'], 2)
        self.assertEqual(audit['comparison']['unique_count'], 3)
        self.assertEqual(audit['dns']['status'], 'discovered')
        self.assertIn('no DNS or HTTPS checks were sent', output)
        self.assertEqual(original, {path: path.read_bytes() for path in self.az.rglob('*') if path.is_file()})

    def test_unknown_native_configuration_fails_before_probing_without_silent_fallback(self):
        with patch('azcheck.cli.discover_resolvers',
                   side_effect=ResolverError('Unsupported active Lua in custom3.lua')), \
             patch('azcheck.cli.shutil.which', return_value='curl'), \
             patch('azcheck.probe.query_resolver') as query, \
             patch('azcheck.probe._https_head') as https, \
             patch('azcheck.probe._public_address') as doh, \
             patch('azcheck.cli.scan_inventory') as scan:
            code, _, error = self.invoke('scan', '--one-batch')
        self.assertEqual(code, 1)
        self.assertIn('Unsupported active Lua in custom3.lua', error)
        for operation in (query, https, doh, scan):
            operation.assert_not_called()
        self.assertFalse((self.reports / 'latest.json').exists())

    def test_audit_records_dns_discovery_failure_and_keeps_inventory_available(self):
        with patch('azcheck.cli.discover_resolvers',
                   side_effect=ResolverError('Unknown native policy')), \
             patch('azcheck.probe.query_resolver') as query:
            code, _, error = self.invoke('audit')
        self.assertEqual(code, 0, error)
        query.assert_not_called()
        audit = json.loads((self.reports / 'inventory-audit.json').read_text())
        self.assertEqual(audit['dns']['status'], 'error')
        self.assertEqual(audit['dns']['error'], 'Unknown native policy')
        self.assertEqual(audit['unique_count'], 2)
        self.assertTrue((self.reports / 'inventory.tsv').is_file())

    def test_changed_dns_plan_invalidates_saved_checks_before_resuming(self):
        plan = native_plan()
        self.write('result/include-hosts.txt', 'a.example\nb.example\nc.example\nexample.com\n')
        with patch('azcheck.cli.dns_plan', side_effect=lambda settings: deepcopy(plan)), \
             patch('azcheck.cli.shutil.which', return_value='curl'), \
             patch('azcheck.scanner._Pacer.wait', return_value=True), \
             patch.object(ScanCheckpoint, 'pause_remaining', return_value=0), \
             patch('azcheck.probe.query_resolver', side_effect=dns_response) as query, \
             patch('azcheck.probe._https_head', side_effect=https_response):
            code, _, error = self.invoke('scan', '--one-batch', '--batch-size', '1')
            self.assertEqual(code, 0, error)
            self.assertIn('Fresh-run DNS matrix: 15 queries before retries', error)
            self.assertIn('DNS pacing floor 4s', error)
            with ScanCheckpoint(self.reports) as state:
                first_run = state.info()['run_id']
                self.assertEqual(state.completed_count(), 1)
            first_queries = query.call_count
            code, _, error = self.invoke('scan', '--one-batch', '--batch-size', '1')
            self.assertEqual(code, 0, error)
            self.assertEqual(query.call_count, first_queries * 2)
            with ScanCheckpoint(self.reports) as state:
                self.assertEqual(state.info()['run_id'], first_run)
                self.assertEqual(state.completed_count(), 2)
            plan['fingerprint'] = 'fixture-b'
            code, _, error = self.invoke('scan', '--one-batch', '--batch-size', '1')
            self.assertEqual(code, 0, error)
            self.assertEqual(query.call_count, first_queries * 3)
            self.assertEqual([query.call_args_list[i].args[0] for i in (0, 3, 6)],
                             ['a.example', 'b.example', 'a.example'])
            with ScanCheckpoint(self.reports) as state:
                self.assertNotEqual(state.info()['run_id'], first_run)
                self.assertEqual(state.completed_count(), 1)
                self.assertEqual(state.info()['probe_context']['dns']['fingerprint'], 'fixture-b')


if __name__ == '__main__':
    unittest.main()
