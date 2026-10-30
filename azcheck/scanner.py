"""Paced checks and reviewable reports; native routing files are never written."""

from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
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

    def wait(self):
        with self.lock:
            now = time.monotonic()
            start = max(now, self.next_start)
            self.next_start = start + self.interval
        if start > now:
            time.sleep(start - now)


def scan_inventory(inventory, *, attempts=2, workers=2, interval_seconds=0.5,
                   timeout_seconds=8.0, resolver_url='https://1.1.1.1/dns-query',
                   probe_fn=check_domain, progress=None, retry_delay_seconds=1.0,
                   event=None):
    """Bound pending tasks and emit serialized start/result events per attempt.

    ``progress`` remains a completed-domain counter. ``event`` receives the
    domain's input index and total, attempt number, and result with elapsed time.
    Callbacks are optional; the scanner itself does not write terminal output.
    """
    pacer = _Pacer(interval_seconds)
    event_lock = threading.Lock()
    total = len(inventory.entries)

    def notify(payload):
        if event is not None:
            with event_lock:
                event(payload)

    def scan_one(index, entry):
        probes = []
        for attempt in range(attempts):
            if attempt and retry_delay_seconds:
                time.sleep(retry_delay_seconds)
            pacer.wait()
            context = {'domain': entry.domain, 'index': index, 'total': total,
                       'attempt': attempt + 1, 'attempts': attempts}
            notify({**context, 'type': 'start'})
            started = time.monotonic()
            probe = dict(probe_fn(entry.domain, timeout=timeout_seconds, resolver_url=resolver_url))
            elapsed = round(max(0.0, time.monotonic() - started), 3)
            probe['elapsed_seconds'] = elapsed
            probes.append(probe)
            notify({**context, 'type': 'result', 'result': dict(probe),
                    'elapsed_seconds': elapsed})
            if not _possible_route_problem(probe):
                break
        decision, reason = classify(entry, probes)
        return {'domain': entry.domain, 'sources': list(entry.sources),
                'warp_included': entry.included, 'warp_excluded': entry.excluded,
                'decision': decision, 'reason': reason, 'checks': probes}

    entries = iter(enumerate(inventory.entries, 1))
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = set()
        for _ in range(workers):
            entry = next(entries, None)
            if entry is not None:
                pending.add(pool.submit(scan_one, *entry))
        while pending:
            complete, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in complete:
                results.append(future.result())
                if progress is not None:
                    progress(len(results), total)
                entry = next(entries, None)
                if entry is not None:
                    pending.add(pool.submit(scan_one, *entry))
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


def _atomic_text(path, text):
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=str(path.parent))
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as handle:
            os.chmod(temporary, 0o600)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_reports(report_dir, inventory, results):
    report_dir = Path(report_dir)
    report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    counts = dict(sorted(Counter(result['decision'] for result in results).items()))
    stamp = datetime.now(timezone.utc).isoformat(timespec='seconds')
    report = {'version': __version__, 'generated_at': stamp,
              'scope': 'Client VPS only; public IPv4 DNS and HTTPS HEAD on port 443.',
              'inventory': dict(inventory.metadata),
              'donor_tested': False, 'counts': counts, 'warnings': list(inventory.warnings),
              'results': results}
    lines = [f'AntiZapret Domain Check {__version__} — {stamp}', report['scope'],
             'Candidates need review: donor accessibility was not tested.',
             f'Domains checked: {len(results)}',
             'Summary: ' + (', '.join(f'{key}={value}' for key, value in counts.items()) or 'empty'), '']
    lines.extend('WARNING: ' + warning for warning in inventory.warnings)
    if inventory.warnings:
        lines.append('')
    for result in results:
        checks = '; '.join(str(check['status']) + (
            ' HTTP ' + str(check['http_status']) if check.get('http_status') else ''
        ) + (' curl ' + str(check['curl_code']) if check.get('curl_code') else '')
            for check in result['checks'])
        lines.extend([f"[{result['decision']}] {result['domain']}: {checks}",
                      '  ' + result['reason'], '  Source: ' + ', '.join(result['sources'])])
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
            lines.append('  ' + ' | '.join(details))
            if check.get('detail'):
                lines.append('    ' + str(check['detail']))
    suggestions = ['# Tentative candidates from client-VPS checks only.',
                   '# Donor access is unverified. Review failures and test before adding.',
                   '# No AntiZapret file was changed. Generated: ' + stamp]
    suggestions.extend(result['domain'] for result in results if result['decision'] == 'candidate')
    _atomic_text(report_dir / 'latest.txt', '\n'.join(lines) + '\n')
    _atomic_text(report_dir / 'suggested-include-warp-hosts.txt', '\n'.join(suggestions) + '\n')
    _atomic_text(report_dir / 'latest.json', json.dumps(report, ensure_ascii=True, indent=2) + '\n')
    return report
