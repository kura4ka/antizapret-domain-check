"""Durable scan batches and pauses; native AntiZapret files are never written."""

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import sqlite3
import time
import uuid

from .domains import InventoryEntry, normalize_domain
from .scanner import classify


SCHEMA_VERSION = 3
CURRENT_DECISION = ("CASE WHEN targets.excluded = 1 THEN 'excluded' "
                    "WHEN targets.included = 1 THEN 'already_warp' "
                    "ELSE results.base_decision END")


def _timestamp():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _encode_probe_context(context):
    """Return a stable finite JSON object and its hash without echoing values."""
    if not isinstance(context, dict):
        raise ValueError('Probe context must be a JSON object with string keys and finite values.')

    def validate(value):
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError('Probe context must use string object keys.')
            for child in value.values():
                validate(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                validate(child)

    try:
        validate(context)
        encoded = json.dumps(context, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError('Probe context must be a JSON object with string keys and finite values.') from exc
    return encoded, hashlib.sha256(encoded.encode('utf-8')).hexdigest()


def _decode_probe_context(encoded, fingerprint):
    if not encoded and not fingerprint:
        return None
    try:
        context = json.loads(encoded)
        canonical, expected = _encode_probe_context(context)
    except (TypeError, ValueError, RecursionError) as exc:
        raise RuntimeError('Scan checkpoint contains invalid probe context.') from exc
    if canonical != encoded or expected != fingerprint:
        raise RuntimeError('Scan checkpoint contains inconsistent probe context.')
    return context


class ScanCheckpoint:
    """Store one resumable run under the caller's existing report lock.

    Methods run in the calling thread. Each result and pause commits before
    returning, so a later process can resume after interruption or reboot.
    """

    def __init__(self, report_dir):
        self.path = Path(report_dir) / 'checkpoint.sqlite3'
        self._connection = None
        self._context_changed = False
        self._reset_reason = ''
        self._requeued_count = 0
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._connection = sqlite3.connect(str(self.path), timeout=5)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            self._connection.execute('PRAGMA synchronous = FULL')
            version = self._connection.execute('PRAGMA user_version').fetchone()[0]
            tables = {row[0] for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )}
            if version == 0 and not tables:
                with self._connection:
                    self._connection.executescript('''
                        CREATE TABLE state (
                            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                            run_id TEXT NOT NULL,
                            started_at TEXT NOT NULL,
                            completed INTEGER NOT NULL CHECK (completed IN (0, 1)),
                            batch_index INTEGER NOT NULL CHECK (batch_index >= 0),
                            pause_until REAL NOT NULL,
                            pause_reason TEXT NOT NULL,
                            probe_context_json TEXT NOT NULL DEFAULT '',
                            probe_context_sha256 TEXT NOT NULL DEFAULT ''
                        );
                        INSERT INTO state (singleton, run_id, started_at, completed,
                                           batch_index, pause_until, pause_reason)
                        VALUES (1, '', '', 0, 0, 0, '');
                        CREATE TABLE targets (
                            domain TEXT PRIMARY KEY,
                            sources_json TEXT NOT NULL,
                            included INTEGER NOT NULL CHECK (included IN (0, 1)),
                            excluded INTEGER NOT NULL CHECK (excluded IN (0, 1))
                        );
                        CREATE TABLE results (
                            domain TEXT PRIMARY KEY,
                            base_decision TEXT NOT NULL,
                            base_reason TEXT NOT NULL,
                            result_json TEXT NOT NULL
                        );
                        CREATE INDEX results_decision ON results (base_decision, domain);
                        CREATE TABLE origin_cooldowns (
                            domain TEXT PRIMARY KEY,
                            not_before REAL NOT NULL CHECK (not_before >= 0)
                        );
                        PRAGMA user_version = 3;
                    ''')
            elif version in (1, 2) and tables == {'state', 'targets', 'results'}:
                # Validate the published layouts before changing them. Schema
                # changes share one explicit transaction so failure rolls back.
                self._connection.execute('''
                    SELECT singleton, run_id, started_at, completed, batch_index,
                           pause_until, pause_reason FROM state LIMIT 0
                ''')
                self._connection.execute('SELECT domain, sources_json, included, excluded FROM targets LIMIT 0')
                self._connection.execute('SELECT domain, base_decision, base_reason, result_json FROM results LIMIT 0')
                if version == 2:
                    self._connection.execute('SELECT probe_context_json, probe_context_sha256 FROM state LIMIT 0')
                    self._state()
                self._connection.execute('BEGIN IMMEDIATE')
                try:
                    if version == 1:
                        self._connection.execute("ALTER TABLE state ADD COLUMN probe_context_json TEXT NOT NULL DEFAULT ''")
                        self._connection.execute("ALTER TABLE state ADD COLUMN probe_context_sha256 TEXT NOT NULL DEFAULT ''")
                    self._connection.execute('''
                        CREATE TABLE origin_cooldowns (
                            domain TEXT PRIMARY KEY,
                            not_before REAL NOT NULL CHECK (not_before >= 0)
                        )
                    ''')
                    self._connection.execute('PRAGMA user_version = 3')
                    self._connection.commit()
                except BaseException:
                    self._connection.rollback()
                    raise
            elif version != SCHEMA_VERSION or tables != {'state', 'targets', 'results', 'origin_cooldowns'}:
                raise RuntimeError('Checkpoint has an unsupported or incomplete database schema: ' + str(self.path))
            # Detect missing columns or state instead of recreating a broken store.
            self._connection.execute('SELECT domain, sources_json, included, excluded FROM targets LIMIT 0')
            self._connection.execute('SELECT domain, base_decision, base_reason, result_json FROM results LIMIT 0')
            self._connection.execute('SELECT domain, not_before FROM origin_cooldowns LIMIT 0')
            self._state()
        except (sqlite3.Error, OSError) as exc:
            self.close()
            raise RuntimeError('Cannot open scan checkpoint ' + str(self.path) + ': ' + str(exc)) from exc
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        self._db()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        connection, self._connection = self._connection, None
        if connection is not None:
            try:
                connection.close()
            except sqlite3.Error as exc:
                raise RuntimeError('Cannot close scan checkpoint ' + str(self.path) + ': ' + str(exc)) from exc

    def _db(self):
        if self._connection is None:
            raise RuntimeError('Scan checkpoint is closed: ' + str(self.path))
        return self._connection

    @contextmanager
    def _transaction(self, action):
        try:
            with self._db() as connection:
                yield connection
        except sqlite3.Error as exc:
            raise RuntimeError('Cannot ' + action + ' scan checkpoint ' + str(self.path) + ': ' + str(exc)) from exc

    def _state(self):
        with self._transaction('read') as connection:
            rows = connection.execute('''
                SELECT singleton, run_id, started_at, completed, batch_index,
                       pause_until, pause_reason, probe_context_json,
                       probe_context_sha256 FROM state
            ''').fetchall()
        if len(rows) != 1 or rows[0][0] != 1:
            raise RuntimeError('Scan checkpoint has invalid run state: ' + str(self.path))
        (_, run_id, started_at, completed, batch_index, pause_until, pause_reason,
         probe_context_json, probe_context_sha256) = rows[0]
        if (not isinstance(run_id, str) or not isinstance(started_at, str)
                or type(completed) is not int or completed not in (0, 1)
                or type(batch_index) is not int or batch_index < 0
                or not isinstance(pause_until, (int, float)) or not math.isfinite(pause_until)
                or pause_until < 0 or not isinstance(pause_reason, str)
                or not isinstance(probe_context_json, str) or not isinstance(probe_context_sha256, str)):
            raise RuntimeError('Scan checkpoint has invalid run state: ' + str(self.path))
        _decode_probe_context(probe_context_json, probe_context_sha256)
        return {'run_id': run_id, 'started_at': started_at, 'completed': bool(completed),
                'batch_index': batch_index, 'pause_until': float(pause_until),
                'pause_reason': pause_reason, 'probe_context_json': probe_context_json,
                'probe_context_sha256': probe_context_sha256}

    def _require_run(self):
        state = self._state()
        if not state['run_id']:
            raise RuntimeError('Prepare the scan checkpoint before saving or completing a batch.')
        return state

    def prepare(self, inventory, restart=False, probe_context=None, retry_failed=False):
        """Resume compatible outcomes or start fresh after probe/DNS changes.

        Omitting context preserves the legacy API. Production callers supply
        their complete semantic probe context so unrecorded legacy checks and
        incompatible results cannot silently count as completed work. Retrying
        failures preserves the existing run and requires a compatible context.
        """
        if retry_failed and restart:
            raise ValueError('retry_failed cannot be combined with restart; choose one scan action.')
        state = self._state()
        if retry_failed and not state['run_id']:
            raise ValueError('retry_failed requires an existing scan run; run a normal scan first.')
        encoded, fingerprint = state['probe_context_json'], state['probe_context_sha256']
        if probe_context is not None:
            encoded, fingerprint = _encode_probe_context(probe_context)
        context_changed = bool(state['run_id'] and probe_context is not None
                               and fingerprint != state['probe_context_sha256'])
        if retry_failed and context_changed:
            raise ValueError('Cannot retry failed checks after DNS/probe context changed. '
                             'Repeat the original DNS, timeout and attempts flags, or use restart for a fresh scan.')
        new_run = bool(not retry_failed and (restart or state['completed'] or not state['run_id'] or context_changed))
        reset_reason = ''
        if retry_failed:
            reset_reason = 'Retrying failed checks in the existing scan run.'
        elif restart:
            reset_reason = 'Explicit restart requested.'
        elif context_changed:
            reset_reason = ('DNS/probe context changed.' if state['probe_context_sha256']
                            else 'Previous checks have no recorded DNS/probe context.')
        elif state['completed']:
            reset_reason = 'The previous run completed; starting fresh checks.'
        elif not state['run_id']:
            reset_reason = 'Starting the first scan run.'
        requeued_count = 0
        with self._transaction('prepare') as connection:
            if new_run:
                connection.execute('DELETE FROM results')
                connection.execute('''
                    UPDATE state SET run_id = ?, started_at = ?, completed = 0,
                                     batch_index = 0, probe_context_json = ?,
                                     probe_context_sha256 = ? WHERE singleton = 1
                ''', (str(uuid.uuid4()), _timestamp(), encoded, fingerprint))
            connection.execute('DELETE FROM targets')
            connection.executemany('''
                INSERT OR IGNORE INTO targets (domain, sources_json, included, excluded)
                VALUES (?, ?, ?, ?)
            ''', ((entry.domain, json.dumps(entry.sources, ensure_ascii=True, allow_nan=False),
                   int(entry.included), int(entry.excluded)) for entry in inventory.entries))
            if retry_failed:
                requeued_count = connection.execute('''
                    DELETE FROM results
                    WHERE base_decision IN ('candidate', 'inconclusive')
                      AND EXISTS (SELECT 1 FROM targets WHERE targets.domain = results.domain)
                      AND NOT EXISTS (
                          SELECT 1 FROM origin_cooldowns
                          WHERE origin_cooldowns.domain = results.domain AND not_before > ?
                      )
                ''', (time.time(),)).rowcount
                missing = requeued_count or connection.execute('''
                    SELECT 1 FROM targets LEFT JOIN results USING (domain)
                    WHERE results.domain IS NULL LIMIT 1
                ''').fetchone()
                if missing:
                    connection.execute('UPDATE state SET completed = 0 WHERE singleton = 1')
        self._context_changed = context_changed
        self._reset_reason = reset_reason
        self._requeued_count = requeued_count
        return new_run

    def pending_entries(self, inventory):
        """Return unsaved entries in their supplied order, without duplicates."""
        self._require_run()
        with self._transaction('read') as connection:
            seen = {row[0] for row in connection.execute(
                'SELECT results.domain FROM results JOIN targets USING (domain)'
            )}
        pending = []
        for entry in inventory.entries:
            if entry.domain not in seen:
                pending.append(entry)
                seen.add(entry.domain)
        return pending

    def save_result(self, result):
        """Commit one completed domain immediately, adding its UTC timestamp."""
        self._require_run()
        if not isinstance(result, dict):
            raise ValueError('A checkpoint result must be an object.')
        saved = dict(result)
        domain, decision = saved.get('domain'), saved.get('decision')
        if not isinstance(domain, str) or not domain or not isinstance(decision, str) or not decision:
            raise ValueError('A checkpoint result requires a domain and decision.')
        probes = saved.get('checks')
        if not isinstance(probes, list) or any(
            not isinstance(probe, dict) or not isinstance(probe.get('status'), str) for probe in probes
        ):
            raise ValueError('A checkpoint result requires a list of probe checks with status values.')
        base_decision, base_reason = classify(InventoryEntry(domain), probes)
        saved.update(decision=base_decision, reason=base_reason,
                     warp_included=False, warp_excluded=False)
        saved.setdefault('checked_at', _timestamp())
        encoded = json.dumps(saved, ensure_ascii=True, allow_nan=False)
        with self._transaction('save a result to') as connection:
            target = connection.execute('''
                SELECT sources_json, included, excluded FROM targets WHERE domain = ?
            ''', (domain,)).fetchone()
            if target is None:
                raise ValueError('Cannot save a result outside the current checkpoint inventory: ' + domain)
            connection.execute('''
                INSERT INTO results (domain, base_decision, base_reason, result_json) VALUES (?, ?, ?, ?)
                ON CONFLICT (domain) DO UPDATE SET base_decision = excluded.base_decision,
                                                  base_reason = excluded.base_reason,
                                                  result_json = excluded.result_json
            ''', (domain, base_decision, base_reason, encoded))
        return self._current_result(saved, base_decision, base_reason, *target)

    def _current_result(self, result, base_decision, base_reason, sources_json, included, excluded):
        try:
            sources = json.loads(sources_json)
        except (TypeError, ValueError) as exc:
            raise RuntimeError('Scan checkpoint contains invalid target sources for ' + result['domain']) from exc
        if not isinstance(sources, list) or any(not isinstance(source, str) for source in sources):
            raise RuntimeError('Scan checkpoint contains invalid target sources for ' + result['domain'])
        decision, reason = base_decision, base_reason
        if included or excluded:
            decision, reason = classify(InventoryEntry(result['domain'], included=bool(included),
                                                       excluded=bool(excluded)), [])
        result.update(sources=sources, warp_included=bool(included), warp_excluded=bool(excluded),
                      decision=decision, reason=reason)
        return result

    def counts(self):
        with self._transaction('count') as connection:
            return dict(connection.execute('''
                SELECT ''' + CURRENT_DECISION + ''' AS decision, COUNT(*)
                FROM results JOIN targets USING (domain)
                GROUP BY decision ORDER BY decision
            '''))

    def completed_count(self):
        with self._transaction('count') as connection:
            return connection.execute(
                'SELECT COUNT(*) FROM results JOIN targets USING (domain)'
            ).fetchone()[0]

    def candidate_domains(self):
        """Stream only current candidate hostnames without loading result JSON."""
        try:
            cursor = self._db().execute('''
                SELECT results.domain FROM results JOIN targets USING (domain)
                WHERE base_decision = 'candidate' AND targets.included = 0 AND targets.excluded = 0
                ORDER BY results.domain
            ''')
            for domain, in cursor:
                yield domain
        except sqlite3.Error as exc:
            raise RuntimeError('Cannot read scan checkpoint ' + str(self.path) + ': ' + str(exc)) from exc

    def iter_results(self):
        """Stream saved current-target results in hostname order."""
        try:
            cursor = self._db().execute('''
                SELECT results.domain, base_decision, base_reason, result_json,
                       sources_json, included, excluded
                FROM results JOIN targets USING (domain) ORDER BY results.domain
            ''')
            for domain, decision, reason, encoded, sources_json, included, excluded in cursor:
                try:
                    result = json.loads(encoded)
                except (TypeError, ValueError) as exc:
                    raise RuntimeError('Scan checkpoint contains an invalid saved result for ' + domain) from exc
                if (not isinstance(result, dict) or result.get('domain') != domain
                        or result.get('decision') != decision or result.get('reason') != reason):
                    raise RuntimeError('Scan checkpoint contains an inconsistent saved result for ' + domain)
                yield self._current_result(result, decision, reason, sources_json, included, excluded)
        except sqlite3.Error as exc:
            raise RuntimeError('Cannot read scan checkpoint ' + str(self.path) + ': ' + str(exc)) from exc

    def finish_batch(self):
        self._require_run()
        with self._transaction('finish a batch in') as connection:
            connection.execute('UPDATE state SET batch_index = batch_index + 1 WHERE singleton = 1')
            return connection.execute('SELECT batch_index FROM state WHERE singleton = 1').fetchone()[0]

    def pause(self, seconds, reason):
        if (isinstance(seconds, bool) or not isinstance(seconds, (int, float))
                or not math.isfinite(seconds) or seconds < 0):
            raise ValueError('Checkpoint pause seconds must be a finite nonnegative number.')
        if not isinstance(reason, str) or not reason:
            raise ValueError('Checkpoint pause requires an explanation.')
        deadline = time.time() + seconds
        state = self._state()
        if deadline > state['pause_until']:
            with self._transaction('pause') as connection:
                connection.execute('UPDATE state SET pause_until = ?, pause_reason = ? WHERE singleton = 1',
                                   (deadline, reason))

    def pause_remaining(self):
        return max(0.0, self._state()['pause_until'] - time.time())

    def origin_cooldowns(self):
        """Return active per-domain deadlines, independent of the current run."""
        with self._transaction('read origin cooldowns from') as connection:
            rows = connection.execute('''
                SELECT domain, not_before FROM origin_cooldowns WHERE not_before > ?
            ''', (time.time(),))
            active = {}
            for domain, deadline in rows:
                if (not isinstance(domain, str) or normalize_domain(domain) != domain
                        or not isinstance(deadline, (int, float)) or not math.isfinite(deadline)):
                    raise RuntimeError('Scan checkpoint contains an invalid origin cooldown.')
                active[domain] = float(deadline)
        return active

    def defer_origin(self, domain, seconds):
        """Persist an origin's cooldown without shortening an existing deadline."""
        domain = normalize_domain(domain)
        try:
            valid = (not isinstance(seconds, bool) and isinstance(seconds, (int, float))
                     and math.isfinite(seconds) and seconds >= 0)
            deadline = time.time() + seconds if valid else float('nan')
        except (TypeError, OverflowError):
            valid, deadline = False, float('nan')
        if not valid or not math.isfinite(deadline) or deadline < 0:
            raise ValueError('Origin cooldown seconds must produce a finite nonnegative deadline.')
        with self._transaction('defer an origin in') as connection:
            connection.execute('''
                INSERT INTO origin_cooldowns (domain, not_before) VALUES (?, ?)
                ON CONFLICT (domain) DO UPDATE SET
                    not_before = MAX(origin_cooldowns.not_before, excluded.not_before)
            ''', (domain, deadline))
            return float(connection.execute(
                'SELECT not_before FROM origin_cooldowns WHERE domain = ?', (domain,)).fetchone()[0])

    def release_legacy_origin_pause(self):
        """Convert a proven old site HTTP-429 pause without changing saved work.

        Call before ``prepare`` can delete old results. A native/numeric DNS
        plan and a public pinned HTTPS address prove the HTTP-429 origin. DoH,
        missing or ambiguous evidence keeps the global resolver cooldown.
        """
        state = self._state()
        if state['pause_reason'] != 'HTTP 429 rate limit':
            return False
        context = _decode_probe_context(state['probe_context_json'], state['probe_context_sha256'])
        dns = context.get('dns') if isinstance(context, dict) else None
        if not isinstance(dns, dict) or dns.get('mode') not in ('antizapret', 'explicit'):
            return False
        origins = []
        with self._transaction('read legacy rate limits from') as connection:
            rows = connection.execute('''
                SELECT domain, result_json FROM results WHERE base_decision = 'inconclusive'
            ''')
            for domain, encoded in rows:
                try:
                    document = json.loads(encoded)
                    if (not isinstance(document, dict) or document.get('domain') != domain
                            or not isinstance(document.get('checks'), list)):
                        return False
                    matching = False
                    for probe in document['checks']:
                        if not isinstance(probe, dict):
                            return False
                        if probe.get('http_status') != 429 and probe.get('status') != 'rate_limited':
                            continue
                        address = ipaddress.IPv4Address(probe.get('address'))
                        if (not address.is_global or address.is_multicast
                                or probe.get('dns_mode') not in (None, 'antizapret', 'explicit')
                                or probe.get('rate_limit_scope') not in (None, 'origin')):
                            return False
                        matching = True
                    if matching:
                        if normalize_domain(domain) != domain:
                            return False
                        origins.append(domain)
                except (ValueError, TypeError, OverflowError):
                    return False
        if not origins:
            return False
        with self._transaction('convert a legacy origin pause in') as connection:
            connection.executemany('''
                INSERT INTO origin_cooldowns (domain, not_before) VALUES (?, ?)
                ON CONFLICT (domain) DO UPDATE SET
                    not_before = MAX(origin_cooldowns.not_before, excluded.not_before)
            ''', ((domain, state['pause_until']) for domain in origins))
            connection.execute("UPDATE state SET pause_until = 0, pause_reason = '' WHERE singleton = 1")
        return True

    def info(self):
        state = self._state()
        state['probe_context'] = _decode_probe_context(state.pop('probe_context_json'),
                                                      state['probe_context_sha256'])
        state['context_changed'] = self._context_changed
        state['reset_reason'] = self._reset_reason
        state['requeued_count'] = self._requeued_count
        with self._transaction('read') as connection:
            state['total'] = connection.execute('SELECT COUNT(*) FROM targets').fetchone()[0]
        state['completed_count'] = self.completed_count()
        state['pause_remaining'] = max(0.0, state['pause_until'] - time.time())
        return state

    def mark_complete(self):
        self._require_run()
        with self._transaction('complete') as connection:
            missing = connection.execute('''
                SELECT 1 FROM targets LEFT JOIN results USING (domain)
                WHERE results.domain IS NULL LIMIT 1
            ''').fetchone()
            if missing is not None:
                raise RuntimeError('Cannot complete a checkpoint while current domains remain unchecked.')
            connection.execute('UPDATE state SET completed = 1 WHERE singleton = 1')
