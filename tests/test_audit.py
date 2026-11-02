"""Inventory audit files describe selected targets without issuing probes."""

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from azcheck.audit import refresh_suggestions, write_inventory_audit
from azcheck.checkpoint import ScanCheckpoint
from azcheck.domains import Inventory, InventoryEntry


def probe_result(domain):
    return {'domain': domain, 'decision': 'candidate',
            'checks': [{'status': 'blocked', 'http_status': 403}] * 2,
            'sources': ['Synthetic test; no requests sent.']}


class AuditTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.reports = self.root / 'reports'
        self.inventory = Inventory([
            InventoryEntry('z.example', ['config/include-hosts.txt:2']),
            InventoryEntry('a.example', ['config/include-warp-hosts.txt:1'], included=True),
            InventoryEntry('b.example', ['user\tfile\n.txt:3'], included=True, excluded=True),
        ], ['A synthetic parsing warning.'], {
            'include_download': False, 'coverage': 'parsed-and-source',
            'unique_contributions': {'generated_host_lists': 2, 'config_additions': 1},
            'source_stats': [{'path': '/root/native/result/include-hosts.txt', 'valid_entries': 2,
                              'added_unique': 2, 'duplicate_targets': 1, 'filtered_entries': 0}],
            'active_routed_domains': 2, 'pending_config_count': 1,
            'pending_config_domains': ['z.example'], 'invalid_source_entries': 2,
            'valid_suffix_policy_occurrences': 3, 'notices': ['Source counts are occurrences.']})

    def test_audit_preserves_selected_inventory_dns_provenance_and_comparison(self):
        plan = {'reference': {'id': 'udp://127.3.3.3:53'},
                'context': {'selected_groups': {'proxy_dns': 'world_dns'}},
                'upstreams': [{'id': 'udp://1.1.1.1:53', 'address': '1.1.1.1', 'transport': 'udp'}],
                'warnings': []}
        comparison = {'effective_count': 3, 'expanded_count': 7, 'additional_unique': 4}
        report = write_inventory_audit(self.reports, self.inventory, dns_plan=plan, comparison=comparison)
        saved = json.loads((self.reports / 'inventory-audit.json').read_text())
        self.assertEqual(saved, report)
        self.assertEqual(saved['unique_count'], 3)
        self.assertEqual(saved['states'], {'normal': 1, 'already_warp': 1, 'excluded': 1})
        self.assertEqual(sum(saved['unique_contributions'].values()), 3)
        self.assertEqual(saved['pending_config_domains'], ['z.example'])
        self.assertEqual(saved['active_routed_domains'], 2)
        self.assertEqual(saved['dns']['plan'], plan)
        self.assertEqual(saved['dns']['status'], 'discovered')
        self.assertEqual(saved['comparison'], comparison)
        self.assertEqual(saved['warnings'], self.inventory.warnings)
        self.assertEqual(self.inventory.entries[0].domain, 'z.example', 'Writing must not reorder the inventory')
        rows = (self.reports / 'inventory.tsv').read_text().splitlines()
        self.assertEqual(rows[0], 'domain\tstate\tsources')
        self.assertEqual([row.split('\t')[0] for row in rows[1:]], ['a.example', 'b.example', 'z.example'])
        self.assertEqual(len(rows), 4)
        self.assertIn('user\\tfile\\n.txt:3', rows[2])
        self.assertTrue(all(len(row.split('\t')) == 3 for row in rows[1:]))
        text = (self.reports / 'inventory-audit.txt').read_text()
        self.assertIn('Unique domains selected: 3', text)
        self.assertIn('Reference DNS endpoint: udp://127.3.3.3:53', text)
        self.assertIn('Selected native DNS groups:', text)
        self.assertIn('Configured DNS endpoint: udp://1.1.1.1:53', text)
        self.assertIn('No DNS or HTTPS requests', text)

    def test_dns_discovery_failure_is_a_reported_audit_result(self):
        report = write_inventory_audit(self.reports, self.inventory,
                                       dns_error=ValueError('Unsupported native DNS configuration.'))
        self.assertEqual(report['dns']['status'], 'error')
        self.assertIsNone(report['dns']['plan'])
        self.assertIn('Unsupported native DNS', report['dns']['error'])
        self.assertEqual(report['unique_count'], 3)
        self.assertIn('DNS discovery error:', (self.reports / 'inventory-audit.txt').read_text())

    def test_failure_during_audit_stream_keeps_previous_files_and_removes_temporary_files(self):
        write_inventory_audit(self.reports, self.inventory)
        before = {path.name: path.read_bytes() for path in self.reports.iterdir()}
        malformed = Inventory([InventoryEntry('duplicate.example'), InventoryEntry('duplicate.example')], [])
        with self.assertRaisesRegex(ValueError, 'deduplicated'):
            write_inventory_audit(self.reports, malformed)
        self.assertEqual({path.name: path.read_bytes() for path in self.reports.iterdir()}, before)
        with self.assertRaises(ValueError):
            write_inventory_audit(self.reports, self.inventory, comparison={'invalid': float('nan')})
        self.assertEqual({path.name: path.read_bytes() for path in self.reports.iterdir()}, before)

    def test_refresh_suggestions_removes_cached_candidates_covered_by_current_rules(self):
        targets = Inventory([InventoryEntry('candidate.example')], [])
        with ScanCheckpoint(self.reports) as checkpoint:
            checkpoint.prepare(targets, probe_context={'dns': ['1.1.1.1']})
            checkpoint.save_result(probe_result('candidate.example'))
            path = refresh_suggestions(self.reports, checkpoint)
            self.assertIn('candidate.example\n', path.read_text())
            self.assertIn(checkpoint.info()['run_id'], path.read_text())
            self.assertIn(checkpoint.info()['probe_context_sha256'], path.read_text())
            targets.entries[0].excluded = True
            checkpoint.prepare(targets, probe_context={'dns': ['1.1.1.1']})
            refresh_suggestions(self.reports, checkpoint)
            self.assertNotIn('candidate.example\n', path.read_text())
            self.assertIn('Completed checks in current inventory: 1', path.read_text())
            checkpoint.prepare(targets, probe_context={'dns': ['9.9.9.9']})
            refresh_suggestions(self.reports, checkpoint)
            self.assertNotIn('candidate.example\n', path.read_text())
            self.assertIn('Completed checks in current inventory: 0', path.read_text())

    def test_failed_candidate_stream_keeps_previous_suggestions(self):
        self.reports.mkdir()
        path = self.reports / 'suggested-include-warp-hosts.txt'
        path.write_bytes(b'# Previously published report\nold.example\n')

        class BrokenCheckpoint:
            def info(self):
                return {'run_id': 'synthetic-run', 'probe_context_sha256': 'test-hash', 'completed_count': 2}

            def candidate_domains(self):
                yield 'new.example'
                raise RuntimeError('Synthetic failed result stream.')

        with self.assertRaisesRegex(RuntimeError, 'failed result stream'):
            refresh_suggestions(self.reports, BrokenCheckpoint())
        self.assertEqual(path.read_bytes(), b'# Previously published report\nold.example\n')
        self.assertEqual([entry.name for entry in self.reports.iterdir()], [path.name])

    @unittest.skipIf(os.name == 'nt', 'POSIX permission bits are not available on Windows.')
    def test_all_created_audit_files_and_suggestions_are_private(self):
        write_inventory_audit(self.reports, self.inventory)
        with ScanCheckpoint(self.reports) as checkpoint:
            checkpoint.prepare(self.inventory)
            refresh_suggestions(self.reports, checkpoint)
        for name in ('inventory-audit.json', 'inventory-audit.txt', 'inventory.tsv',
                     'suggested-include-warp-hosts.txt'):
            self.assertEqual(stat.S_IMODE((self.reports / name).stat().st_mode), 0o600)


if __name__ == '__main__':
    unittest.main()
