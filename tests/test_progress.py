"""Live scan events must identify every actual request and its response."""

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import threading
import time
import unittest

from azcheck.domains import Inventory, InventoryEntry
from azcheck.scanner import scan_inventory, write_reports


def response(domain, *, blocked=False):
    return {'domain': domain, 'status': 'blocked' if blocked else 'ok',
            'http_status': 403 if blocked else 200, 'curl_code': 0,
            'address': '93.184.215.14', 'detail': 'Synthetic HTTPS header response.'}


class ProgressEventsTests(unittest.TestCase):
    def test_each_retry_emits_domain_attempt_and_corresponding_response(self):
        inventory = Inventory([InventoryEntry('blocked.example.org')], [])
        events, counts = [], []
        original = response('blocked.example.org', blocked=True)
        results = scan_inventory(inventory, probe_fn=lambda *args, **kwargs: original,
                                 workers=1, attempts=3, interval_seconds=0,
                                 retry_delay_seconds=0, event=events.append,
                                 progress=lambda done, total: counts.append((done, total)))
        self.assertEqual([event['type'] for event in events], ['start', 'result'] * 3)
        self.assertEqual([event['attempt'] for event in events], [1, 1, 2, 2, 3, 3])
        for event in events:
            self.assertEqual((event['domain'], event['index'], event['total'], event['attempts']),
                             ('blocked.example.org', 1, 1, 3))
            if event['type'] == 'result':
                self.assertEqual(event['result']['http_status'], 403)
                self.assertGreaterEqual(event['elapsed_seconds'], 0)
                self.assertEqual(event['elapsed_seconds'], event['result']['elapsed_seconds'])
        self.assertEqual(counts, [(1, 1)])
        self.assertEqual(results[0]['decision'], 'candidate')
        self.assertEqual(len(results[0]['checks']), 3)
        self.assertNotIn('elapsed_seconds', original, 'Timing must not modify reusable probe results')

    def test_concurrent_callbacks_are_serialized_and_requests_have_valid_event_pairs(self):
        inventory = Inventory([InventoryEntry(f'site{index}.example.org') for index in range(8)], [])
        events = []
        callback_active = maximum_callbacks = 0
        guard = threading.Lock()

        def event_callback(event):
            nonlocal callback_active, maximum_callbacks
            with guard:
                callback_active += 1
                maximum_callbacks = max(maximum_callbacks, callback_active)
            time.sleep(0.001)
            events.append(event)
            with guard:
                callback_active -= 1

        def probe(domain, **options):
            time.sleep(0.002)
            return response(domain)

        results = scan_inventory(inventory, probe_fn=probe, workers=4,
                                 interval_seconds=0, retry_delay_seconds=0,
                                 event=event_callback)
        self.assertEqual(maximum_callbacks, 1)
        self.assertEqual(len(events), 2 * len(inventory.entries))
        expected_indices = {entry.domain: index for index, entry in enumerate(inventory.entries, 1)}
        active = set()
        for event in events:
            domain = event['domain']
            self.assertEqual(event['index'], expected_indices[domain])
            self.assertEqual(event['total'], len(inventory.entries))
            if event['type'] == 'start':
                self.assertNotIn(domain, active)
                active.add(domain)
            else:
                self.assertIn(domain, active)
                self.assertEqual(event['result']['domain'], domain)
                active.remove(domain)
        self.assertEqual(active, set())
        self.assertTrue(all(result['decision'] == 'reachable' for result in results))

    def test_result_callback_cannot_change_the_recorded_response(self):
        def callback(event):
            if event['type'] == 'result':
                event['result']['status'] = 'blocked'

        results = scan_inventory(Inventory([InventoryEntry('example.org')], []),
                                 probe_fn=lambda domain, **options: response(domain),
                                 interval_seconds=0, event=callback)
        self.assertEqual(results[0]['decision'], 'reachable')
        self.assertEqual(results[0]['checks'][0]['status'], 'ok')

    def test_no_event_callback_leaves_terminal_silent_and_keeps_completion_counter(self):
        stdout, stderr, counts = io.StringIO(), io.StringIO(), []
        inventory = Inventory([InventoryEntry('example.org')], [])
        with redirect_stdout(stdout), redirect_stderr(stderr):
            results = scan_inventory(inventory, probe_fn=lambda domain, **options: response(domain),
                                     interval_seconds=0, event=None,
                                     progress=lambda done, total: counts.append((done, total)))
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), '')
        self.assertEqual(counts, [(1, 1)])
        self.assertEqual(len(results), 1)

    def test_report_explains_each_attempt_with_response_ip_timing_and_detail(self):
        inventory = Inventory([InventoryEntry('example.org', ['include-hosts.txt:3'])], [])
        results = scan_inventory(inventory, probe_fn=lambda domain, **options: response(domain),
                                 interval_seconds=0)
        with tempfile.TemporaryDirectory() as directory:
            report = write_reports(directory, inventory, results)
            text = (Path(directory) / 'latest.txt').read_text(encoding='utf-8')
        self.assertIn('Attempt 1: ok | HTTP 200 | curl 0 | IP 93.184.215.14 | ', text)
        self.assertIn('Synthetic HTTPS header response.', text)
        self.assertGreaterEqual(report['results'][0]['checks'][0]['elapsed_seconds'], 0)


if __name__ == '__main__':
    unittest.main()
