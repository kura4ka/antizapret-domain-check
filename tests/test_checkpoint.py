"""Checkpoints retain completed work and enforced pauses without network IO."""

import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch

from azcheck.checkpoint import ScanCheckpoint
from azcheck.domains import Inventory, InventoryEntry


def inventory(*domains):
    return Inventory([InventoryEntry(domain) for domain in domains], [])


def result(domain, decision='reachable'):
    checks = ([{'status': 'blocked', 'http_status': 403}] * 2 if decision == 'candidate'
              else [{'status': 'ok', 'http_status': 200}])
    return {'domain': domain, 'decision': decision, 'checks': checks,
            'sources': ['Synthetic checkpoint test; no requests sent.']}


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.report_dir = Path(temporary.name) / 'reports'

    def test_results_commit_immediately_and_resume_in_input_order(self):
        targets = inventory('c.example', 'a.example', 'b.example')
        original = result('a.example')
        with ScanCheckpoint(self.report_dir) as store:
            self.assertTrue(store.prepare(targets))
            run_id = store.info()['run_id']
            saved = store.save_result(original)
            self.assertIn('checked_at', saved)
            self.assertNotIn('checked_at', original)
            # A separate connection sees the result before the writer closes.
            with sqlite3.connect(str(store.path)) as reader:
                self.assertEqual(reader.execute('SELECT COUNT(*) FROM results').fetchone()[0], 1)
            self.assertEqual(store.finish_batch(), 1)
        with ScanCheckpoint(self.report_dir) as store:
            self.assertFalse(store.prepare(targets))
            self.assertEqual(store.info()['run_id'], run_id)
            self.assertEqual(store.info()['batch_index'], 1)
            self.assertEqual([entry.domain for entry in store.pending_entries(targets)],
                             ['c.example', 'b.example'])
            self.assertEqual(store.completed_count(), 1)
            self.assertEqual(store.counts(), {'reachable': 1})
            self.assertEqual(list(store.candidate_domains()), [])
            self.assertEqual(list(store.iter_results()), [saved])

    def test_current_targets_exclude_removed_domains_and_resume_readded_results(self):
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(inventory('removed.example', 'kept.example'))
            store.save_result(result('removed.example', 'candidate'))
            store.save_result(result('kept.example'))
            updated = inventory('new.example', 'kept.example')
            self.assertFalse(store.prepare(updated))
            self.assertEqual(store.info()['total'], 2)
            self.assertEqual(store.completed_count(), 1)
            self.assertEqual(store.counts(), {'reachable': 1})
            self.assertEqual([row['domain'] for row in store.iter_results()], ['kept.example'])
            self.assertEqual([entry.domain for entry in store.pending_entries(updated)], ['new.example'])
            readded = inventory('removed.example', 'new.example', 'kept.example')
            store.prepare(readded)
            self.assertEqual(store.completed_count(), 2)
            self.assertEqual(list(store.candidate_domains()), ['removed.example'])
            self.assertEqual([entry.domain for entry in store.pending_entries(readded)], ['new.example'])

    def test_explicit_restart_resets_results_and_batches_without_bypassing_pause(self):
        targets = inventory('one.example')
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(targets)
            previous = store.info()
            store.save_result(result('one.example'))
            store.finish_batch()
            with patch('azcheck.checkpoint.time.time', return_value=1000):
                store.pause(300, 'Wait between batches.')
            self.assertTrue(store.prepare(targets, restart=True))
            current = store.info()
            self.assertNotEqual(current['run_id'], previous['run_id'])
            self.assertFalse(current['completed'])
            self.assertEqual(current['batch_index'], 0)
            self.assertEqual(store.completed_count(), 0)
            with patch('azcheck.checkpoint.time.time', return_value=1100):
                self.assertEqual(store.pause_remaining(), 200)
                self.assertEqual(store.info()['pause_reason'], 'Wait between batches.')

    def test_completed_run_starts_fresh_next_time_and_preserves_pause(self):
        targets = inventory('one.example')
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(targets)
            store.save_result(result('one.example'))
            store.mark_complete()
            self.assertTrue(store.info()['completed'])
            previous = store.info()['run_id']
            with patch('azcheck.checkpoint.time.time', return_value=1000):
                store.pause(300, 'Provider cooldown.')
        with ScanCheckpoint(self.report_dir) as store:
            self.assertTrue(store.prepare(targets))
            self.assertNotEqual(store.info()['run_id'], previous)
            self.assertEqual(store.completed_count(), 0)
            with patch('azcheck.checkpoint.time.time', return_value=1100):
                self.assertEqual(store.pause_remaining(), 200)

    def test_pause_survives_reopen_and_never_shortens_existing_deadline(self):
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(inventory('one.example'))
            with patch('azcheck.checkpoint.time.time', return_value=1000):
                store.pause(500, 'Long provider pause.')
                store.pause(100, 'Short batch delay.')
                self.assertEqual(store.info()['pause_until'], 1500)
                self.assertEqual(store.info()['pause_reason'], 'Long provider pause.')
        with ScanCheckpoint(self.report_dir) as store:
            with patch('azcheck.checkpoint.time.time', return_value=1100):
                self.assertEqual(store.pause_remaining(), 400)
                store.pause(500, 'Extended provider pause.')
                self.assertEqual(store.info()['pause_until'], 1600)
                self.assertEqual(store.info()['pause_reason'], 'Extended provider pause.')
            with patch('azcheck.checkpoint.time.time', return_value=2000):
                self.assertEqual(store.pause_remaining(), 0)

    def test_duplicate_inventory_names_and_replaced_results_count_once(self):
        targets = inventory('b.example', 'a.example', 'b.example')
        targets.entries[1].excluded = True
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(targets)
            self.assertEqual(store.info()['total'], 2)
            self.assertEqual([entry.domain for entry in store.pending_entries(targets)], ['b.example', 'a.example'])
            saved = result('b.example', 'candidate')
            saved['checked_at'] = '2026-10-30T12:00:00+00:00'
            store.save_result(saved)
            store.save_result(result('b.example'))
            store.save_result(result('a.example', 'excluded'))
            self.assertEqual(store.completed_count(), 2)
            self.assertEqual(store.counts(), {'excluded': 1, 'reachable': 1})
            self.assertEqual([row['domain'] for row in store.iter_results()], ['a.example', 'b.example'])

    def test_resume_reclassifies_cached_probes_with_current_warp_rules_and_sources(self):
        original = inventory('candidate.example')
        original.entries[0].sources = ['config/include-hosts.txt:1']
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(original)
            first = store.save_result(result('candidate.example', 'candidate'))
            self.assertEqual(store.counts(), {'candidate': 1})
            self.assertEqual(list(store.candidate_domains()), ['candidate.example'])
            changed = inventory('candidate.example')
            changed.entries[0].sources = ['config/updated-include-hosts.txt:2']
            for included, excluded, expected in (
                (False, True, 'excluded'), (True, True, 'excluded'),
                (True, False, 'already_warp'), (False, False, 'candidate'),
            ):
                with self.subTest(included=included, excluded=excluded):
                    changed.entries[0].included = included
                    changed.entries[0].excluded = excluded
                    self.assertFalse(store.prepare(changed))
                    self.assertEqual(store.pending_entries(changed), [])
                    self.assertEqual(store.counts(), {expected: 1})
                    self.assertEqual(list(store.candidate_domains()),
                                     ['candidate.example'] if expected == 'candidate' else [])
                    current = list(store.iter_results())[0]
                    self.assertEqual(current['decision'], expected)
                    self.assertEqual(current['warp_included'], included)
                    self.assertEqual(current['warp_excluded'], excluded)
                    self.assertEqual(current['sources'], changed.entries[0].sources)
                    self.assertEqual(current['checks'], first['checks'])
                    self.assertEqual(current['checked_at'], first['checked_at'])
                    if expected == 'candidate':
                        self.assertEqual(current['reason'], first['reason'])

    def test_save_with_existing_warp_rule_still_preserves_unflagged_probe_decision(self):
        targets = inventory('candidate.example')
        targets.entries[0].excluded = True
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(targets)
            document = result('candidate.example', 'candidate')
            document['decision'] = 'excluded'
            saved = store.save_result(document)
            self.assertEqual(saved['decision'], 'excluded')
            self.assertTrue(saved['warp_excluded'])
            store.prepare(inventory('candidate.example'))
            self.assertEqual(store.counts(), {'candidate': 1})
            self.assertEqual(list(store.candidate_domains()), ['candidate.example'])
            self.assertEqual(list(store.iter_results())[0]['decision'], 'candidate')

    def test_checked_at_is_preserved_and_incomplete_run_cannot_be_marked_complete(self):
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(inventory('one.example', 'two.example'))
            saved = result('one.example')
            saved['checked_at'] = '2026-10-30T12:00:00+00:00'
            store.save_result(saved)
            self.assertEqual(list(store.iter_results())[0]['checked_at'], saved['checked_at'])
            with self.assertRaisesRegex(RuntimeError, 'remain unchecked'):
                store.mark_complete()
            self.assertFalse(store.info()['completed'])

    def test_invalid_inputs_do_not_change_saved_work(self):
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(inventory('one.example'))
            for document in (None, {}, result('other.example'), {'domain': 'one.example'}):
                with self.subTest(document=document), self.assertRaises(ValueError):
                    store.save_result(document)
            for seconds in (-1, float('nan'), float('inf'), True, '10'):
                with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                    store.pause(seconds, 'Invalid test pause.')
            self.assertEqual(store.completed_count(), 0)
            self.assertEqual(store.pause_remaining(), 0)

    def test_corrupt_database_is_reported_without_replacing_it(self):
        self.report_dir.mkdir()
        path = self.report_dir / 'checkpoint.sqlite3'
        contents = b'This is not a SQLite database.'
        path.write_bytes(contents)
        with self.assertRaisesRegex(RuntimeError, 'checkpoint'):
            ScanCheckpoint(self.report_dir)
        self.assertEqual(path.read_bytes(), contents)

    def test_unsupported_or_incomplete_schema_is_not_reinitialized(self):
        self.report_dir.mkdir()
        path = self.report_dir / 'checkpoint.sqlite3'
        with sqlite3.connect(str(path)) as connection:
            connection.execute('CREATE TABLE unrelated (value TEXT)')
            connection.execute("INSERT INTO unrelated VALUES ('preserve me')")
        with self.assertRaisesRegex(RuntimeError, 'unsupported or incomplete'):
            ScanCheckpoint(self.report_dir)
        with sqlite3.connect(str(path)) as connection:
            self.assertEqual(connection.execute('SELECT value FROM unrelated').fetchone()[0], 'preserve me')

    def test_invalid_saved_json_is_reported_instead_of_skipped(self):
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(inventory('one.example'))
            store.save_result(result('one.example'))
            with sqlite3.connect(str(store.path)) as connection:
                connection.execute('UPDATE results SET result_json = ?', ('{broken',))
            with self.assertRaisesRegex(RuntimeError, 'invalid saved result'):
                list(store.iter_results())

    def test_candidate_iteration_uses_current_targets_without_deserializing_json(self):
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(inventory('z.example', 'a.example', 'reachable.example', 'removed.example'))
            for domain in ('z.example', 'a.example', 'removed.example'):
                store.save_result(result(domain, 'candidate'))
            store.save_result(result('reachable.example'))
            store.prepare(inventory('z.example', 'a.example', 'reachable.example'))
            with sqlite3.connect(str(store.path)) as connection:
                connection.execute("UPDATE results SET result_json = '{broken'")
            self.assertEqual(list(store.candidate_domains()), ['a.example', 'z.example'])

    def test_sqlite_write_errors_and_closed_store_are_clear(self):
        store = ScanCheckpoint(self.report_dir)
        try:
            store.prepare(inventory('one.example'))
            with sqlite3.connect(str(store.path)) as connection:
                connection.execute('DROP TABLE results')
            with self.assertRaisesRegex(RuntimeError, 'scan checkpoint'):
                store.save_result(result('one.example'))
        finally:
            store.close()
        with self.assertRaisesRegex(RuntimeError, 'closed'):
            store.info()

    @unittest.skipIf(os.name == 'nt', 'POSIX permission bits are not available on Windows.')
    def test_database_has_private_permissions(self):
        with ScanCheckpoint(self.report_dir) as store:
            self.assertEqual(stat.S_IMODE(store.path.stat().st_mode), 0o600)


if __name__ == '__main__':
    unittest.main()
