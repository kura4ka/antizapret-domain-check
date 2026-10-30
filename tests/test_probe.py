"""Network-free checks for public DNS and bounded HTTPS probes."""

import json
import subprocess
import unittest
from unittest.mock import patch

from azcheck import probe


def dns_answer(*addresses):
    return {'Status': 0, 'Answer': [{'type': 1, 'data': address} for address in addresses]}


def dns_result(document=None, raw=None, code=200, curl_code=0):
    payload = raw if raw is not None else json.dumps(document if document is not None else dns_answer('93.184.215.14')).encode()
    return subprocess.CompletedProcess([], curl_code, payload + b'\n' + str(code).encode(), b'')


class ProbeTests(unittest.TestCase):
    def run_probe(self, *, document=None, raw=None, code=200, curl_code=0, output=None):
        completed = subprocess.CompletedProcess([], curl_code,
                                                output if output is not None else str(code) + '\n93.184.215.14\n', '')
        with patch.object(probe.subprocess, 'run', side_effect=[dns_result(document, raw), completed]) as run:
            result = probe.check_domain('Example.COM')
        return result, run

    def test_dns_and_https_have_total_deadlines_and_proxies_are_disabled(self):
        result, run = self.run_probe()
        self.assertEqual(result['domain'], 'example.com')
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(run.call_count, 2)
        dns_call, https_call = run.call_args_list
        dns_command, https_command = dns_call.args[0], https_call.args[0]
        self.assertEqual(dns_command[-1], 'https://1.1.1.1/dns-query?name=example.com&type=A')
        self.assertIn('Accept: application/dns-json', dns_command)
        self.assertEqual(dns_command[dns_command.index('--max-filesize') + 1], str(probe.MAX_DNS_BYTES))
        for call in (dns_call, https_call):
            command = call.args[0]
            self.assertEqual(command[:2], ['curl', '--disable'])
            self.assertEqual(command[command.index('--proxy') + 1], '')
            self.assertEqual(command[command.index('--proto') + 1], '=https')
            self.assertEqual(command[command.index('--max-time') + 1], '8.0')
            self.assertNotIn('--location', command)
            self.assertNotIn('-L', command)
            self.assertNotIn('--insecure', command)
            self.assertFalse(call.kwargs['shell'])
            self.assertEqual(call.kwargs['timeout'], 9.0)
        self.assertIn('--head', https_command)
        self.assertIn('example.com:443:93.184.215.14', https_command)

    def test_http_status_classes_do_not_claim_every_error_is_a_block(self):
        for code, expected in ((200, 'ok'), (302, 'ok'), (401, 'reachable'), (403, 'blocked'),
                               (404, 'reachable'), (405, 'reachable'), (429, 'rate_limited'),
                               (451, 'blocked'), (500, 'server_error'), (503, 'server_error')):
            with self.subTest(code=code):
                result, _ = self.run_probe(code=code)
                self.assertEqual(result['status'], expected)
                self.assertEqual(result['http_status'], code)

    def test_private_reserved_multicast_and_mixed_answers_are_skipped(self):
        for address in ('127.0.0.1', '10.0.0.1', '169.254.169.254', '192.0.2.1', '224.0.0.1', '100.64.0.1'):
            with self.subTest(address=address):
                result, run = self.run_probe(document=dns_answer('93.184.215.14', address))
                self.assertEqual(result['status'], 'skipped')
                self.assertEqual(run.call_count, 1)

    def test_unresolvable_or_malformed_dns_is_reported_without_https_request(self):
        for document in ({'Status': 3}, {'Status': 0}, {'Status': True},
                         {'Status': 0, 'Answer': [{'type': 1, 'data': 'invalid'}]},
                         {'Status': 0, 'Answer': [None]}, {'Status': 0, 'Answer': {}},
                         {'Status': 0, 'Answer': [{'type': True, 'data': '93.184.215.14'}]},
                         {'Status': 0, 'Answer': [{'type': 1, 'data': 1572399382}]},
                         {'Status': 0, 'TC': True},
                         {'Status': 0, 'Answer': [{'type': 1, 'data': '93.184.215.14'}] * 129}):
            with self.subTest(document=str(document)[:80]):
                result, run = self.run_probe(document=document)
                self.assertEqual(result['status'], 'dns_error')
                self.assertEqual(run.call_count, 1)

    def test_large_or_invalid_dns_documents_are_bounded(self):
        for raw in (b'not JSON', b'x' * (probe.MAX_DNS_BYTES + 1)):
            with self.subTest(size=len(raw)):
                result, run = self.run_probe(raw=raw)
                self.assertEqual(result['status'], 'dns_error')
                self.assertEqual(run.call_count, 1)

    def test_dns_timeout_missing_curl_or_failure_does_not_run_https(self):
        failures = (subprocess.TimeoutExpired('curl', 9), FileNotFoundError('curl'),
                    dns_result(curl_code=28), dns_result(curl_code=63))
        for failure in failures:
            with self.subTest(failure=str(failure)[:60]), patch.object(probe.subprocess, 'run') as run:
                if isinstance(failure, BaseException):
                    run.side_effect = failure
                else:
                    run.return_value = failure
                result = probe.check_domain('example.com')
                self.assertEqual(result['status'], 'dns_error')
                self.assertEqual(run.call_count, 1)

    def test_dns_http_redirect_or_error_is_not_accepted_as_a_dns_result(self):
        for code in (302, 403, 500):
            with self.subTest(code=code), patch.object(probe.subprocess, 'run', return_value=dns_result(code=code)) as run:
                result = probe.check_domain('example.com')
                self.assertEqual(result['status'], 'dns_error')
                self.assertEqual(run.call_count, 1)

    def test_curl_transport_failures_keep_exit_code(self):
        result, _ = self.run_probe(curl_code=28, output='000\n\n')
        self.assertEqual(result['status'], 'transport_error')
        self.assertEqual(result['curl_code'], 28)
        self.assertIsNone(result['http_status'])

    def test_unconfirmed_or_wrong_remote_address_is_not_success(self):
        for output in ('200\n10.0.0.1\n', '200\n', '000\n93.184.215.14\n', 'x' * 1025):
            with self.subTest(output=output[:30]):
                result, _ = self.run_probe(output=output)
                self.assertEqual(result['status'], 'transport_error')

    def test_curl_timeout_and_missing_binary_have_distinct_exit_codes(self):
        for failure, expected in ((subprocess.TimeoutExpired('curl', 9), 28), (FileNotFoundError('curl'), 127)):
            with self.subTest(failure=type(failure).__name__), \
                 patch.object(probe, '_public_address', return_value='93.184.215.14'), \
                 patch.object(probe.subprocess, 'run', side_effect=failure):
                result = probe.check_domain('example.com')
                self.assertEqual(result['status'], 'transport_error')
                self.assertEqual(result['curl_code'], expected)

    def test_invalid_domains_never_resolve_or_execute(self):
        with patch.object(probe, '_public_address') as resolve, patch.object(probe.subprocess, 'run') as run:
            for domain in ('localhost', '127.0.0.1', 'https://example.com', '*.example.com',
                           'example.com;id', '-option.example', 'example.com\nnext.example',
                           'example.com..', '0127.0.0.1', 'example.123'):
                with self.subTest(domain=domain):
                    self.assertEqual(probe.check_domain(domain)['status'], 'skipped')
            resolve.assert_not_called()
            run.assert_not_called()

    def test_invalid_resolver_configuration_fails_before_network(self):
        for url in ('http://1.1.1.1/dns-query', 'https://127.0.0.1/dns-query',
                    'https://user:secret@example.com/query', 'https://example.com:444/query',
                    'https://example.com/query#fragment', 'https://localhost/query'):
            with self.subTest(url=url), patch.object(probe.subprocess, 'run') as run:
                with self.assertRaises(probe.ProbeError):
                    probe.check_domain('example.com', resolver_url=url)
                run.assert_not_called()

    def test_timeout_configuration_rejects_nonfinite_and_unbounded_values(self):
        for timeout in (0, 61, float('nan'), float('inf'), True, 'invalid'):
            with self.subTest(timeout=timeout), self.assertRaises(probe.ProbeError):
                probe.check_domain('example.com', timeout=timeout)

    def test_existing_resolver_query_is_preserved_without_overriding_domain(self):
        with patch.object(probe.subprocess, 'run', return_value=dns_result()) as run:
            address = probe._public_address('example.com', 8, 'https://1.1.1.1/dns-query?name=other.example&foo=bar&type=AAAA')
        self.assertEqual(address, '93.184.215.14')
        self.assertEqual(run.call_args.args[0][-1],
                         'https://1.1.1.1/dns-query?foo=bar&name=example.com&type=A')


if __name__ == '__main__':
    unittest.main()
