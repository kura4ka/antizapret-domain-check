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

    def test_same_canonical_context_resumes_and_changed_dns_context_resets(self):
        targets = inventory('one.example', 'two.example')
        context = {'dns': [{'address': '1.1.1.1', 'transport': 'udp'}],
                   'probe_version': 2, 'criteria': {'attempts': 2, 'timeout': 8}}
        with ScanCheckpoint(self.report_dir) as store:
            self.assertTrue(store.prepare(targets, probe_context=context))
            self.assertFalse(store.info()['context_changed'])
            saved = store.save_result(result('one.example', 'candidate'))
            initial_id = store.info()['run_id']
            initial_sha = store.info()['probe_context_sha256']
            self.assertEqual(len(initial_sha), 64)
        with ScanCheckpoint(self.report_dir) as store:
            reordered = {'criteria': {'timeout': 8, 'attempts': 2},
                         'probe_version': 2, 'dns': context['dns']}
            self.assertFalse(store.prepare(targets, probe_context=reordered))
            self.assertEqual(store.info()['run_id'], initial_id)
            self.assertEqual(store.info()['probe_context_sha256'], initial_sha)
            self.assertEqual(store.info()['probe_context'], context)
            self.assertEqual(list(store.iter_results()), [saved])
            with patch('azcheck.checkpoint.time.time', return_value=1000):
                store.pause(7200, 'HTTP 429 rate limit')
            changed = {**context, 'dns': [{'address': '9.9.9.9', 'transport': 'tls'}]}
            self.assertTrue(store.prepare(targets, probe_context=changed))
            self.assertTrue(store.info()['context_changed'])
            self.assertIn('context changed', store.info()['reset_reason'])
            self.assertNotEqual(store.info()['run_id'], initial_id)
            self.assertNotEqual(store.info()['probe_context_sha256'], initial_sha)
            self.assertEqual(store.completed_count(), 0)
            self.assertEqual(store.counts(), {})
            self.assertEqual(list(store.candidate_domains()), [])
            with patch('azcheck.checkpoint.time.time', return_value=1100):
                self.assertEqual(store.pause_remaining(), 7100)

    def test_changed_probe_criteria_or_version_starts_fresh_run(self):
        targets = inventory('one.example')
        previous_id = None
        with ScanCheckpoint(self.report_dir) as store:
            for context in ({'attempts': 2, 'timeout': 8, 'version': 1},
                            {'attempts': 3, 'timeout': 8, 'version': 1},
                            {'attempts': 3, 'timeout': 10, 'version': 1},
                            {'attempts': 3, 'timeout': 10, 'version': 2}):
                self.assertTrue(store.prepare(targets, probe_context=context))
                self.assertNotEqual(store.info()['run_id'], previous_id)
                self.assertEqual(store.completed_count(), 0)
                previous_id = store.info()['run_id']
                store.save_result(result('one.example'))

    def test_first_supplied_context_invalidates_unrecorded_legacy_checks(self):
        targets = inventory('one.example')
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(targets)
            store.save_result(result('one.example'))
            self.assertIsNone(store.info()['probe_context'])
            self.assertTrue(store.prepare(targets, probe_context={'resolver': '1.1.1.1'}))
            self.assertEqual(store.completed_count(), 0)
            self.assertTrue(store.info()['context_changed'])
            self.assertIn('no recorded', store.info()['reset_reason'])

    def test_invalid_probe_context_does_not_reset_saved_work_or_echo_values(self):
        targets = inventory('one.example')
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(targets, probe_context={'valid': True})
            store.save_result(result('one.example'))
            before = store.info()
            for value in ([], 'sensitive-example', {1: 'sensitive-example'},
                          {'value': float('nan')}, {'value': float('inf')},
                          {'value': {'unsupported'}}):
                with self.subTest(context_type=type(value).__name__), self.assertRaises(ValueError) as error:
                    store.prepare(targets, probe_context=value)
                self.assertNotIn('sensitive-example', str(error.exception))
                self.assertEqual(store.info()['run_id'], before['run_id'])
                self.assertEqual(store.completed_count(), 1)

    def legacy_schema(self):
        """Write the published v0.3 state layout, retaining targets/results."""
        with sqlite3.connect(str(self.report_dir / 'checkpoint.sqlite3')) as connection:
            connection.executescript('''
                BEGIN;
                ALTER TABLE state RENAME TO oldstate;
                CREATE TABLE state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    run_id TEXT NOT NULL, started_at TEXT NOT NULL,
                    completed INTEGER NOT NULL CHECK (completed IN (0, 1)),
                    batch_index INTEGER NOT NULL CHECK (batch_index >= 0),
                    pause_until REAL NOT NULL, pause_reason TEXT NOT NULL
                );
                INSERT INTO state SELECT singleton, run_id, started_at, completed,
                                         batch_index, pause_until, pause_reason FROM oldstate;
                DROP TABLE oldstate;
                PRAGMA user_version = 1;
                COMMIT;
            ''')

    def test_schema_one_migration_retains_results_and_cooldown_until_context_supplied(self):
        targets = inventory('one.example', 'two.example')
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(targets)
            saved = store.save_result(result('one.example', 'candidate'))
            initial_id = store.info()['run_id']
            with patch('azcheck.checkpoint.time.time', return_value=1000):
                store.pause(4000, 'Provider pause')
        self.legacy_schema()
        with ScanCheckpoint(self.report_dir) as store:
            self.assertEqual(store.info()['run_id'], initial_id)
            self.assertEqual(list(store.iter_results()), [saved])
            self.assertIsNone(store.info()['probe_context'])
            self.assertFalse(store.prepare(targets))
            with sqlite3.connect(str(store.path)) as reader:
                self.assertEqual(reader.execute('PRAGMA user_version').fetchone()[0], 2)
            self.assertTrue(store.prepare(targets, probe_context={'dns': ['1.1.1.1']}))
            self.assertEqual(store.completed_count(), 0)
            with patch('azcheck.checkpoint.time.time', return_value=1100):
                self.assertEqual(store.pause_remaining(), 3900)

    def test_failed_schema_migration_rolls_back_added_column_and_version(self):
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(inventory('one.example'))
            store.save_result(result('one.example'))
        self.legacy_schema()
        path = self.report_dir / 'checkpoint.sqlite3'
        with sqlite3.connect(str(path)) as connection:
            connection.execute("ALTER TABLE state ADD COLUMN probe_context_sha256 TEXT NOT NULL DEFAULT ''")
        with self.assertRaisesRegex(RuntimeError, 'checkpoint'):
            ScanCheckpoint(self.report_dir)
        with sqlite3.connect(str(path)) as connection:
            columns = {row[1] for row in connection.execute('PRAGMA table_info(state)')}
            self.assertNotIn('probe_context_json', columns)
            self.assertEqual(connection.execute('PRAGMA user_version').fetchone()[0], 1)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM results').fetchone()[0], 1)

    def test_tampered_probe_context_is_reported_without_reinitialization(self):
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(inventory('one.example'), probe_context={'dns': ['1.1.1.1']})
            store.save_result(result('one.example'))
            with sqlite3.connect(str(store.path)) as connection:
                connection.execute("UPDATE state SET probe_context_sha256 = 'incorrect'")
            with self.assertRaisesRegex(RuntimeError, 'inconsistent probe context'):
                store.info()
        with self.assertRaisesRegex(RuntimeError, 'inconsistent probe context'):
            ScanCheckpoint(self.report_dir)
        with sqlite3.connect(str(self.report_dir / 'checkpoint.sqlite3')) as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM results').fetchone()[0], 1)

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

    def test_retry_failed_requeues_candidate_and_inconclusive_preserves_successes_and_run(self):
        targets = inventory('blocked.example', 'dns.example', 'timeout.example', 'ok.example', 'reachable.example')
        context = {'dns': ['1.1.1.1'], 'timeout': 8, 'attempts': 2}
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(targets, probe_context=context)
            store.save_result(result('blocked.example', 'candidate'))
            for domain, status, code in (('dns.example', 'dns_error', None),
                                         ('timeout.example', 'transport_error', None),
                                         ('reachable.example', 'reachable', 404)):
                document = result(domain)
                document['checks'] = [{'status': status, 'http_status': code}]
                store.save_result(document)
            success = store.save_result(result('ok.example'))
            store.finish_batch()
            store.mark_complete()
            with patch('azcheck.checkpoint.time.time', return_value=1000):
                store.pause(7200, 'HTTP 429 rate limit')
            previous = store.info()

        with ScanCheckpoint(self.report_dir) as store:
            self.assertFalse(store.prepare(targets, probe_context=context, retry_failed=True))
            current = store.info()
            self.assertEqual(current['run_id'], previous['run_id'])
            self.assertEqual(current['started_at'], previous['started_at'])
            self.assertEqual(current['probe_context_sha256'], previous['probe_context_sha256'])
            self.assertEqual(current['batch_index'], 1)
            self.assertEqual(current['requeued_count'], 3)
            self.assertFalse(current['completed'])
            self.assertEqual(current['pause_until'], previous['pause_until'])
            self.assertEqual(current['pause_reason'], previous['pause_reason'])
            self.assertEqual([entry.domain for entry in store.pending_entries(targets)],
                             ['blocked.example', 'dns.example', 'timeout.example'])
            self.assertEqual(store.counts(), {'reachable': 2})
            self.assertEqual(next(row for row in store.iter_results() if row['domain'] == 'ok.example'), success)
            with patch('azcheck.checkpoint.time.time', return_value=1100):
                self.assertEqual(store.pause_remaining(), 7100)

    def test_retry_failed_only_deletes_current_targets_and_uses_base_decision(self):
        original = inventory('removed.example', 'flagged.example', 'kept.example')
        original.entries[1].excluded = True
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(original)
            store.save_result(result('removed.example', 'candidate'))
            store.save_result(result('flagged.example', 'candidate'))
            store.save_result(result('kept.example'))
            removed_before = store._db().execute(
                'SELECT * FROM results WHERE domain = ?', ('removed.example',)).fetchone()
            updated = inventory('flagged.example', 'kept.example')
            updated.entries[0].included = True
            updated.entries[0].excluded = True
            updated.entries[1].sources = ['config/new-include-hosts.txt:7']
            self.assertFalse(store.prepare(updated, retry_failed=True))
            self.assertEqual(store.info()['requeued_count'], 1)
            self.assertEqual([entry.domain for entry in store.pending_entries(updated)], ['flagged.example'])
            self.assertEqual(store._db().execute(
                'SELECT * FROM results WHERE domain = ?', ('removed.example',)).fetchone(), removed_before)
            self.assertEqual(list(store.iter_results())[0]['sources'], ['config/new-include-hosts.txt:7'])
            self.assertFalse(store.prepare(original))
            self.assertEqual(store.info()['requeued_count'], 0)
            self.assertEqual(store.completed_count(), 2)

    def test_retry_failed_without_failures_preserves_completed_run_and_results(self):
        targets = inventory('ok.example')
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(targets)
            saved = store.save_result(result('ok.example'))
            store.mark_complete()
            run_id = store.info()['run_id']
            self.assertFalse(store.prepare(targets, retry_failed=True))
            self.assertEqual(store.info()['run_id'], run_id)
            self.assertEqual(store.info()['requeued_count'], 0)
            self.assertTrue(store.info()['completed'])
            self.assertEqual(store.pending_entries(targets), [])
            self.assertEqual(list(store.iter_results()), [saved])
            with ScanCheckpoint(self.report_dir) as reopened:
                self.assertEqual(reopened.info()['requeued_count'], 0)

    def test_retry_failed_reopens_completed_state_for_new_pending_targets(self):
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(inventory('ok.example'))
            store.save_result(result('ok.example'))
            store.mark_complete()
            run_id = store.info()['run_id']
            updated = inventory('ok.example', 'new.example')
            self.assertFalse(store.prepare(updated, retry_failed=True))
            self.assertEqual(store.info()['run_id'], run_id)
            self.assertEqual(store.info()['requeued_count'], 0)
            self.assertFalse(store.info()['completed'])
            self.assertEqual([entry.domain for entry in store.pending_entries(updated)], ['new.example'])
            self.assertEqual(store.completed_count(), 1)

    def test_retry_failed_requires_existing_run_and_rejects_restart_before_writes(self):
        with ScanCheckpoint(self.report_dir) as store:
            before = '\n'.join(store._db().iterdump())
            with self.assertRaisesRegex(ValueError, 'existing scan run'):
                store.prepare(inventory('new.example'), retry_failed=True)
            self.assertEqual('\n'.join(store._db().iterdump()), before)
            store.prepare(inventory('ok.example'))
            store.save_result(result('ok.example'))
            before = '\n'.join(store._db().iterdump())
            with self.assertRaisesRegex(ValueError, 'cannot be combined with restart'):
                store.prepare(inventory('different.example'), restart=True, retry_failed=True)
            self.assertEqual('\n'.join(store._db().iterdump()), before)

    def test_retry_failed_changed_probe_context_fails_before_replacing_targets_or_results(self):
        targets = inventory('failed.example', 'ok.example')
        context = {'dns': ['1.1.1.1'], 'timeout': 8, 'attempts': 2}
        with ScanCheckpoint(self.report_dir) as store:
            store.prepare(targets, probe_context=context)
            store.save_result(result('failed.example', 'candidate'))
            store.save_result(result('ok.example'))
            store.mark_complete()
            before = '\n'.join(store._db().iterdump())
            for changed in ({**context, 'dns': ['9.9.9.9']}, {**context, 'timeout': 4},
                            {**context, 'attempts': 3}, {**context, 'probe_version': 99}):
                with self.subTest(context=changed), self.assertRaisesRegex(
                        ValueError, 'Repeat the original DNS, timeout and attempts flags'):
                    store.prepare(inventory('different.example'), probe_context=changed, retry_failed=True)
                self.assertEqual('\n'.join(store._db().iterdump()), before)
            self.assertEqual(store.info()['requeued_count'], 0)
            self.assertTrue(store.info()['completed'])

    def test_retry_failed_cannot_adopt_context_for_unrecorded_checks(self):
        with ScanCheckpoint(self.report_dir) as store:
            targets = inventory('failed.example')
            store.prepare(targets)
            store.save_result(result('failed.example', 'candidate'))
            before = '\n'.join(store._db().iterdump())
            with self.assertRaisesRegex(ValueError, 'DNS/probe context changed'):
                store.prepare(targets, probe_context={'dns': ['1.1.1.1']}, retry_failed=True)
            self.assertEqual('\n'.join(store._db().iterdump()), before)

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
