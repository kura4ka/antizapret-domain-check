"""Network-free checks for public DNS and bounded HTTPS probes."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from azcheck import probe


def dns_answer(*addresses):
    return {'Status': 0, 'Answer': [{'type': 1, 'data': address} for address in addresses]}


def dns_result(document=None, raw=None, code=200, curl_code=0):
    payload = raw if raw is not None else json.dumps(document if document is not None else dns_answer('93.184.215.14')).encode()
    return subprocess.CompletedProcess([], curl_code, payload + b'\n' + str(code).encode(), b'')


def header_response(completed, headers):
    def respond(command, **options):
        Path(command[command.index('--dump-header') + 1]).write_bytes(headers)
        return completed
    return respond


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

    def test_dns_http429_stops_before_https_and_retains_retry_after(self):
        responder = header_response(dns_result(code=429, curl_code=22),
                                    b'HTTP/2 429\r\nRetry-After: 120\r\n\r\n')
        with patch.object(probe.subprocess, 'run', side_effect=responder) as run:
            result = probe.check_domain('example.com')
        self.assertEqual(run.call_count, 1)
        self.assertEqual(result['status'], 'rate_limited')
        self.assertEqual(result['http_status'], 429)
        self.assertEqual(result['curl_code'], 22)
        self.assertEqual(result['retry_after_seconds'], 120)
        self.assertIn('DNS resolver', result['detail'])
        command = run.call_args.args[0]
        self.assertFalse(Path(command[command.index('--dump-header') + 1]).exists())

    def test_https429_and_http11_fallback_retain_retry_after_without_another_request(self):
        for initial_error in (False, True):
            with self.subTest(http11_fallback=initial_error):
                results = [dns_result()]
                if initial_error:
                    results.append(subprocess.CompletedProcess([], 92, '000\n93.184.215.14\n', ''))
                limited = subprocess.CompletedProcess([], 0, '429\n93.184.215.14\n', '')
                responder = header_response(limited, b'HTTP/1.1 429 Too Many Requests\r\nretry-after: 3600\r\n\r\n')

                def respond(command, **options):
                    if results:
                        return results.pop(0)
                    return responder(command, **options)

                with patch.object(probe.subprocess, 'run', side_effect=respond) as run:
                    result = probe.check_domain('example.com')
                self.assertEqual(run.call_count, 3 if initial_error else 2)
                self.assertEqual(result['status'], 'rate_limited')
                self.assertEqual(result['retry_after_seconds'], 3600)
                self.assertIn('HTTP 429', result['detail'])
                if initial_error:
                    self.assertIn('HTTP/1.1', result['detail'])

    def test_known_http429_is_not_retried_even_when_curl_reports_http2_stream_error(self):
        responses = [dns_result(), subprocess.CompletedProcess([], 92, '429\n93.184.215.14\n', '')]
        with patch.object(probe.subprocess, 'run', side_effect=responses) as run:
            result = probe.check_domain('example.com')
        self.assertEqual(run.call_count, 2)
        self.assertEqual(result['status'], 'rate_limited')
        self.assertEqual(result['curl_code'], 92)

    def test_retry_after_http_dates_final_response_and_invalid_headers(self):
        cases = (
            (b'HTTP/2 429\r\nRetry-After: Thu, 01 Jan 1970 01:00:00 GMT\r\n', 3600),
            (b'HTTP/2 429\r\nRetry-After: Wed, 31 Dec 1969 23:00:00 GMT\r\n', 0),
            (b'HTTP/1.1 100 Continue\r\nRetry-After: 9000\r\n\r\nHTTP/2 429\r\nRetry-After: 30\r\n', 30),
            (b'HTTP/1.1 100 Continue\r\nRetry-After: 9000\r\n\r\nHTTP/2 429\r\n', None),
            (b'HTTP/2 429\r\nRetry-After: -1\r\nRetry-After: not-a-date\r\n', None),
            (b'HTTP/2 429\r\nRetry-After:\r\n', None),
            (b'HTTP/2 429\r\nRetry-After: 90\r\n' + b'x' * probe.MAX_HEADER_BYTES, None),
        )
        with tempfile.TemporaryDirectory() as directory:
            header_path = Path(directory) / 'headers'
            for headers, expected in cases:
                with self.subTest(headers=headers[:100]), patch.object(probe.time, 'time', return_value=0):
                    header_path.write_bytes(headers)
                    self.assertEqual(probe._read_retry_after(header_path), expected)

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

    def test_http2_stream_error_retries_once_with_http11_and_keeps_https_constraints(self):
        http2_error = subprocess.CompletedProcess([], 92, '000\n93.184.215.14\n', '')
        success = subprocess.CompletedProcess([], 0, '200\n93.184.215.14\n', '')
        with patch.object(probe.subprocess, 'run', side_effect=[dns_result(), http2_error, success]) as run:
            result = probe.check_domain('example.com')
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['http_status'], 200)
        self.assertEqual(result['curl_code'], 0)
        self.assertIn('curl 92', result['detail'])
        self.assertIn('retried HTTPS HEAD once with HTTP/1.1', result['detail'])
        self.assertEqual(run.call_count, 3)
        initial_call, fallback_call = run.call_args_list[1:]
        self.assertNotIn('--http1.1', initial_call.args[0])
        self.assertEqual(fallback_call.args[0], initial_call.args[0][:2] + ['--http1.1'] + initial_call.args[0][2:])
        command = fallback_call.args[0]
        self.assertIn('--head', command)
        self.assertEqual(command[command.index('--resolve') + 1], 'example.com:443:93.184.215.14')
        self.assertEqual(command[command.index('--proxy') + 1], '')
        self.assertEqual(command[command.index('--noproxy') + 1], '*')
        self.assertEqual(command[command.index('--max-time') + 1], '8.0')
        self.assertEqual(fallback_call.kwargs['timeout'], 9.0)
        self.assertFalse(fallback_call.kwargs['shell'])
        self.assertNotIn('--location', command)
        self.assertNotIn('--insecure', command)

    def test_failed_http11_fallback_keeps_final_exit_code_without_further_retries(self):
        for curl_code in (92, 60, 28):
            with self.subTest(curl_code=curl_code):
                failed = subprocess.CompletedProcess([], curl_code, '000\n93.184.215.14\n', '')
                with patch.object(probe.subprocess, 'run', side_effect=[
                    dns_result(), subprocess.CompletedProcess([], 92, '000\n\n', ''), failed,
                ]) as run:
                    result = probe.check_domain('example.com')
                self.assertEqual(run.call_count, 3)
                self.assertEqual(result['status'], 'transport_error')
                self.assertEqual(result['curl_code'], curl_code)
                self.assertIn('HTTP/1.1', result['detail'])
                self.assertIn('failed (curl ' + str(curl_code) + ')', result['detail'])

    def test_http11_fallback_timeout_remains_bounded_and_identifiable(self):
        with patch.object(probe.subprocess, 'run', side_effect=[
            dns_result(), subprocess.CompletedProcess([], 92, '000\n\n', ''),
            subprocess.TimeoutExpired('curl', 9),
        ]) as run:
            result = probe.check_domain('example.com')
        self.assertEqual(run.call_count, 3)
        self.assertEqual(result['status'], 'transport_error')
        self.assertEqual(result['curl_code'], 28)
        self.assertIn('HTTP/1.1', result['detail'])
        self.assertIn('timed out', result['detail'])

    def test_certificate_and_other_transport_errors_do_not_use_http11_fallback(self):
        for curl_code in (60, 7, 28, 35, 56):
            with self.subTest(curl_code=curl_code):
                result, run = self.run_probe(curl_code=curl_code, output='000\n\n')
                self.assertEqual(run.call_count, 2)
                self.assertEqual(result['curl_code'], curl_code)
                self.assertNotIn('HTTP/1.1', result['detail'])
                self.assertNotIn('--http1.1', run.call_args.args[0])

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
