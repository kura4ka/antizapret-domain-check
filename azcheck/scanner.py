"""Paced checks and reviewable reports; native routing files are never written."""

from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
import time

from . import __version__
from .probe import check_domain


RETRYABLE_CURL = frozenset((7, 28, 35, 52, 55, 56))


def _possible_route_problem(probe):
    return probe['status'] == 'blocked' or (
        probe['status'] == 'transport_error' and probe.get('curl_code') in RETRYABLE_CURL
    )


def classify(entry, probes):
    """A client-only failure is a candidate, never proof that a donor fixes it."""
    if entry.excluded:
        return 'excluded', 'A native WARP exclusion applies; review it manually.'
    if entry.included:
        return 'already_warp', 'A native WARP include already covers this domain.'
    if len(probes) >= 2 and all(_possible_route_problem(probe) for probe in probes):
        return 'candidate', 'Repeated client-side failure; test through the donor before adding.'
    if any(probe['status'] == 'ok' for probe in probes):
        return 'reachable', 'An HTTPS header response was received; full application access is unverified.'
    if any(probe['status'] == 'reachable' for probe in probes):
        return 'reachable', 'The server answered HTTPS; this response does not establish a routing problem.'
    return 'inconclusive', 'No routing recommendation: DNS, site health, rate limits or TLS may be responsible.'


class _Pacer:
    def __init__(self, interval):
        self.interval = interval
        self.next_start = 0.0
        self.lock = threading.Lock()

    def wait(self, stop_event):
        if stop_event.is_set():
            return False
        with self.lock:
            now = time.monotonic()
            start = max(now, self.next_start)
            self.next_start = start + self.interval
        return not stop_event.wait(max(0.0, start - now))


def scan_inventory(inventory, *, attempts=2, workers=2, interval_seconds=0.5,
                   timeout_seconds=8.0, resolver_url='https://1.1.1.1/dns-query',
                   probe_fn=check_domain, progress=None, retry_delay_seconds=1.0,
                   event=None, completed=None, stop_event=None):
    """Bound pending tasks and emit serialized start/result events per attempt.

    ``progress`` remains a completed-domain counter. ``event`` receives the
    domain's input index and total, attempt number, and result with elapsed time.
    ``completed`` receives each result on the calling thread for checkpointing.
    Cancellation stops new attempts and drains in-flight results, including on
    KeyboardInterrupt. A rate-limit response requests cancellation as well.
    Callbacks are optional; the scanner itself does not write terminal output.
    """
    pacer = _Pacer(interval_seconds)
    event_lock = threading.Lock()
    stop_event = threading.Event() if stop_event is None else stop_event
    total = len(inventory.entries)

    def notify(payload):
        if event is not None:
            with event_lock:
                event(payload)

    def scan_one(index, entry):
        probes = []
        for attempt in range(attempts):
            if stop_event.is_set():
                break
            if attempt and stop_event.wait(retry_delay_seconds):
                break
            if not pacer.wait(stop_event):
                break
            context = {'domain': entry.domain, 'index': index, 'total': total,
                       'attempt': attempt + 1, 'attempts': attempts}
            notify({**context, 'type': 'start'})
            if stop_event.is_set():
                break
            started = time.monotonic()
            probe = dict(probe_fn(entry.domain, timeout=timeout_seconds, resolver_url=resolver_url))
            elapsed = round(max(0.0, time.monotonic() - started), 3)
            probe['elapsed_seconds'] = elapsed
            probes.append(probe)
            if probe['status'] == 'rate_limited' or probe.get('http_status') == 429:
                stop_event.set()
            notify({**context, 'type': 'result', 'result': dict(probe),
                    'elapsed_seconds': elapsed})
            if not _possible_route_problem(probe):
                break
        if not probes:
            return None
        decision, reason = classify(entry, probes)
        return {'domain': entry.domain, 'sources': list(entry.sources),
                'warp_included': entry.included, 'warp_excluded': entry.excluded,
                'decision': decision, 'reason': reason, 'checks': probes}

    entries = iter(enumerate(inventory.entries, 1))
    results = []
    delivered = set()
    pending = set()
    pool = ThreadPoolExecutor(max_workers=workers)

    def collect(future):
        if future in delivered:
            return
        result = future.result()
        if result is not None:
            if completed is not None:
                completed(result)
            results.append(result)
        delivered.add(future)
        if result is not None and progress is not None:
            progress(len(results), total)

    def submit_next():
        if stop_event.is_set():
            return
        entry = next(entries, None)
        if entry is not None:
            pending.add(pool.submit(scan_one, *entry))

    try:
        for _ in range(workers):
            submit_next()
        while pending:
            complete, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in complete:
                collect(future)
                pending.remove(future)
                delivered.discard(future)
                submit_next()
    except BaseException:
        stop_event.set()
        for future in pending:
            future.cancel()
        # Keep collecting on this thread so checkpoint stores need no threaded
        # connection. A second Ctrl+C still leaves bounded in-flight work to drain.
        while pending:
            try:
                complete, _ = wait(pending, return_when=FIRST_COMPLETED)
            except KeyboardInterrupt:
                continue
            for future in complete:
                if future.cancelled() or future.exception() is not None:
                    pending.remove(future)
                    delivered.discard(future)
                    continue
                try:
                    collect(future)
                except KeyboardInterrupt:
                    continue
                pending.remove(future)
                delivered.discard(future)
        raise
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    return sorted(results, key=lambda item: item['domain'])


@contextmanager
def report_lock(report_dir):
    """A process lock is released by the OS even after an interrupted scan."""
    report_dir = Path(report_dir)
    report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = report_dir / '.scan.lock'
    with lock_path.open('a+b') as handle:
        if os.name == 'nt':
            import msvcrt
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b'0')
                handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError('Another scan is using this report directory.') from exc
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise RuntimeError('Another scan is using this report directory.') from exc
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)


@contextmanager
def _temporary_text(path):
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=str(path.parent))
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as handle:
            os.chmod(temporary, 0o600)
            yield Path(temporary), handle
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_reports(report_dir, inventory, results, *, result_count=None, counts=None,
                  progress=None, suggestions=None):
    """Stream a single-pass result iterable without building report-sized strings.

    Optional totals are checked against the stream before replacing reports.
    List callers retain their full returned report; iterable callers receive the
    report header without materializing ``results``. ``suggestions`` can provide
    a separate cumulative candidate stream for a report of the latest batch.
    """
    report_dir = Path(report_dir)
    report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat(timespec='seconds')
    report = {'version': __version__, 'generated_at': stamp,
              'scope': 'Client VPS only; public IPv4 DNS and HTTPS HEAD on port 443.',
              'inventory': dict(inventory.metadata),
              'donor_tested': False, 'warnings': list(inventory.warnings)}
    if progress is not None:
        report['progress'] = dict(progress)
    names = ('latest.txt', 'suggested-include-warp-hosts.txt', 'latest.json')
    with ExitStack() as stack:
        staged = {name: stack.enter_context(_temporary_text(report_dir / name)) for name in names}
        text_file, suggestion_file, json_file = (staged[name][1] for name in names)
        body = stack.enter_context(tempfile.TemporaryFile(mode='w+', encoding='utf-8', newline='\n', dir=str(report_dir)))
        suggestion_file.write('# Tentative candidates from client-VPS checks only.\n'
                              '# Donor access is unverified. Review failures and test before adding.\n'
                              '# No AntiZapret file was changed. Generated: ' + stamp + '\n')
        json_file.write('{\n  "results": [')
        observed_counts, observed_count = Counter(), 0
        for result in results:
            if observed_count:
                json_file.write(',')
            json_file.write('\n    ')
            json.dump(result, json_file, ensure_ascii=True)
            observed_count += 1
            observed_counts[result['decision']] += 1
            if suggestions is None and result['decision'] == 'candidate':
                suggestion_file.write(result['domain'] + '\n')
            checks = '; '.join(str(check['status']) + (
                ' HTTP ' + str(check['http_status']) if check.get('http_status') else ''
            ) + (' curl ' + str(check['curl_code']) if check.get('curl_code') else '')
                for check in result['checks'])
            body.write(f"[{result['decision']}] {result['domain']}: {checks}\n" +
                       '  ' + result['reason'] + '\n  Source: ' + ', '.join(result['sources']) + '\n')
            for attempt, check in enumerate(result['checks'], 1):
                details = [f"Attempt {attempt}: {check['status']}"]
                if check.get('http_status'):
                    details.append('HTTP ' + str(check['http_status']))
                if check.get('curl_code') is not None:
                    details.append('curl ' + str(check['curl_code']))
                if check.get('address'):
                    details.append('IP ' + str(check['address']))
                if check.get('elapsed_seconds') is not None:
                    details.append(f"{check['elapsed_seconds']:.3f}s")
                body.write('  ' + ' | '.join(details) + '\n')
                if check.get('detail'):
                    body.write('    ' + str(check['detail']) + '\n')
        if result_count is not None and result_count != observed_count:
            raise ValueError('Report result_count does not match the result stream.')
        if counts is not None and dict(counts) != dict(observed_counts):
            raise ValueError('Report counts do not match the result stream.')
        report['counts'] = dict(sorted(observed_counts.items()))
        if suggestions is not None:
            for domain in suggestions:
                suggestion_file.write(domain + '\n')
        json_file.write('\n  ],' + json.dumps(report, ensure_ascii=True, indent=2)[1:] + '\n')
        lines = [f'AntiZapret Domain Check {__version__} — {stamp}', report['scope'],
                 'Candidates need review: donor accessibility was not tested.',
                 f'Domains checked: {observed_count}',
                 'Summary: ' + (', '.join(f'{key}={value}' for key, value in report['counts'].items()) or 'empty')]
        if progress is not None:
            lines.append('Progress: ' + ', '.join(f'{key}={value}' for key, value in progress.items()))
        lines.append('')
        lines.extend('WARNING: ' + warning for warning in inventory.warnings)
        if inventory.warnings:
            lines.append('')
        text_file.write('\n'.join(lines) + '\n')
        body.seek(0)
        shutil.copyfileobj(body, text_file)
        for temporary, handle in staged.values():
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
        for name, (temporary, _) in staged.items():
            os.replace(temporary, report_dir / name)
    if isinstance(results, (list, tuple)):
        report['results'] = results
    return report
