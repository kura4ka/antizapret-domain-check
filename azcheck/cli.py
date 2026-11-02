"""Command-line interface for the standalone domain checker."""

import argparse
import json
import math
from pathlib import Path
import shutil
import sys
import threading
import time

from . import __version__
from .checkpoint import ScanCheckpoint
from .audit import refresh_suggestions, write_inventory_audit
from .domains import DomainError, Inventory, load_inventory
from .probe import ProbeError, check_domain, validate_resolver_url, validate_timeout
from .resolvers import applicable_resolvers, discover_resolvers, parse_resolver
from .scanner import _Pacer, report_lock, scan_inventory, write_reports


DEFAULT_CONFIG = '/etc/antizapret-domain-check/config.json'
LEGACY_REPORT_DIR = '/var/lib/antizapret-domain-check/reports'
DEFAULTS = {'config_version': 4, 'antizapret_dir': '/root/antizapret',
            'report_dir': '/root/antizapret-domain-check/reports',
            'timeout_seconds': 8, 'attempts': 2, 'workers': 2,
            'interval_seconds': 0.5, 'include_download': False,
            'batch_size': 500, 'batch_pause_seconds': 300,
            'resolver_url': '', 'resolvers': [], 'dns_config_dir': '/etc/knot-resolver',
            'dns_interval_seconds': 0.25}


def _duration(seconds):
    remaining = max(0, math.ceil(seconds))
    parts = []
    for size, unit in ((86400, 'd'), (3600, 'h'), (60, 'm'), (1, 's')):
        count, remaining = divmod(remaining, size)
        if count:
            parts.append(f'{count}{unit}')
    return ' '.join(parts) or '0s'


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate setting: {key}')
        result[key] = value
    return result


def migrate_config(document):
    """Upgrade old scope/path defaults while preserving unrelated settings."""
    if not isinstance(document, dict) or set(document) - set(DEFAULTS):
        raise ValueError('Configuration contains unknown settings or is not an object.')
    version = document.get('config_version', 1)
    if type(version) is not int or version not in (1, 2, 3, 4):
        raise ValueError('config_version must be 1, 2, 3 or 4.')
    upgraded = dict(document)
    if 'include_download' in document and type(document['include_download']) is not bool:
        raise ValueError('include_download must be true or false.')
    if version == 1:
        if upgraded.get('report_dir') == LEGACY_REPORT_DIR:
            upgraded['report_dir'] = DEFAULTS['report_dir']
        if 'include_download' in upgraded and type(upgraded['include_download']) is not bool:
            raise ValueError('include_download must be true or false.')
        upgraded['include_download'] = True
    if version < 3:
        for key in ('batch_size', 'batch_pause_seconds'):
            upgraded.setdefault(key, DEFAULTS[key])
    if version < 4:
        # Earlier releases enabled raw expansion and a fixed Cloudflare URL by
        # default. Migrate those defaults to effective lists and native DNS.
        upgraded['include_download'] = False
        if upgraded.get('resolver_url') == 'https://1.1.1.1/dns-query':
            upgraded['resolver_url'] = ''
        for key in ('resolvers', 'dns_config_dir', 'dns_interval_seconds'):
            upgraded.setdefault(key, DEFAULTS[key])
    upgraded['config_version'] = 4
    return upgraded


def load_settings(args):
    settings = dict(DEFAULTS)
    path = Path(args.config or DEFAULT_CONFIG)
    if path.exists():
        if not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise ValueError('Configuration must be a JSON file smaller than 1 MiB.')
        document = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_pairs)
        settings.update(migrate_config(document))
    elif args.config:
        raise ValueError(f'Configuration file not found: {path}')
    overrides = {'az_dir': 'antizapret_dir', 'report_dir': 'report_dir',
                 'timeout': 'timeout_seconds', 'attempts': 'attempts', 'workers': 'workers',
                 'interval': 'interval_seconds', 'resolver_url': 'resolver_url',
                 'batch_size': 'batch_size', 'batch_pause': 'batch_pause_seconds',
                 'resolver': 'resolvers', 'dns_config_dir': 'dns_config_dir',
                 'dns_interval': 'dns_interval_seconds',
                 'include_download': 'include_download'}
    for flag, key in overrides.items():
        value = getattr(args, flag, None)
        if value is not None:
            settings[key] = value
    if getattr(args, 'resolver', None) is not None:
        settings['resolver_url'] = ''
    elif getattr(args, 'resolver_url', None) is not None:
        settings['resolvers'] = []
    for key in ('antizapret_dir', 'report_dir', 'dns_config_dir'):
        if not isinstance(settings[key], str) or not settings[key] or '\x00' in settings[key]:
            raise ValueError(f'{key} must be a directory path.')
    if Path(settings['report_dir']).resolve().is_relative_to(Path(settings['antizapret_dir']).resolve()):
        raise ValueError('report_dir must be outside the AntiZapret directory; reports must not become native routing lists.')
    for key, minimum, maximum in (('attempts', 2, 3), ('workers', 1, 4),
                                  ('batch_size', 1, 5000), ('batch_pause_seconds', 60, 86400)):
        if type(settings[key]) is not int or not minimum <= settings[key] <= maximum:
            raise ValueError(f'{key} must be an integer from {minimum} to {maximum}.')
    interval = settings['interval_seconds']
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not math.isfinite(interval) or not 0.25 <= interval <= 60:
        raise ValueError('interval_seconds must be between 0.25 and 60.')
    if type(settings['include_download']) is not bool:
        raise ValueError('include_download must be true or false.')
    settings['timeout_seconds'] = validate_timeout(settings['timeout_seconds'])
    dns_interval = settings['dns_interval_seconds']
    if isinstance(dns_interval, bool) or not isinstance(dns_interval, (int, float)) or not math.isfinite(dns_interval) or not 0.25 <= dns_interval <= 60:
        raise ValueError('dns_interval_seconds must be between 0.25 and 60.')
    if settings['resolver_url']:
        settings['resolver_url'] = validate_resolver_url(settings['resolver_url'])
    elif not isinstance(settings['resolver_url'], str):
        raise ValueError('resolver_url must be an HTTPS URL or an empty string for native DNS discovery.')
    if not isinstance(settings['resolvers'], list) or any(not isinstance(value, str) for value in settings['resolvers']):
        raise ValueError('resolvers must be a list of explicit DNS endpoint strings.')
    if settings['resolvers'] and settings['resolver_url']:
        raise ValueError('Choose explicit resolvers or resolver_url, not both.')
    return settings


def dns_plan(settings):
    if settings['resolvers']:
        endpoints = {endpoint['id']: endpoint for endpoint in map(parse_resolver, settings['resolvers'])}
        values = list(endpoints.values())
        return {'mode': 'explicit', 'reference': values[0], 'upstreams': values[1:],
                'sources': [], 'warnings': ['Explicit DNS overrides are used; native path parity is unverified.']}
    if settings['resolver_url']:
        return {'mode': 'explicit-doh', 'resolver_url': settings['resolver_url'], 'upstreams': [],
                'sources': [], 'warnings': ['Explicit DoH override is used; native DNS discovery is disabled.']}
    plan = discover_resolvers(Path(settings['antizapret_dir']), knot_dir=Path(settings['dns_config_dir']))
    plan['mode'] = 'antizapret'
    return plan


def parser():
    result = argparse.ArgumentParser(description='Check AntiZapret domains from the client VPS and suggest WARP candidates.')
    result.add_argument('--version', action='version', version=__version__)
    commands = result.add_subparsers(dest='command', required=True)
    for command in ('inventory', 'audit', 'scan'):
        sub = commands.add_parser(command, help='List collected domains' if command == 'inventory' else 'Check domains and write reports')
        sub.add_argument('--config', help='JSON settings file (default: ' + DEFAULT_CONFIG + ')')
        sub.add_argument('--az-dir', help='AntiZapret root (default: /root/antizapret)')
        sub.add_argument('--file', action='append', default=[], help='Also check domains from this text file; repeatable')
        sub.add_argument('--domain', action='append', default=[], help='Also check this domain; repeatable')
        sub.add_argument('--include-download', action=argparse.BooleanOptionalAction, default=None,
                         help='Opt in to raw-registry subdomain expansion (default: disabled)')
        sub.add_argument('--dns-config-dir', help='Installed Knot configuration directory')
        if command in ('scan', 'audit'):
            sub.add_argument('--report-dir', help='Report directory (default: ' + DEFAULTS['report_dir'] + ')')
        if command == 'audit':
            sub.add_argument('--compare-download', action='store_true', help='Also calculate inventory counts with raw expansion enabled')
        if command == 'scan':
            sub.add_argument('--timeout', type=float, help='Seconds per DNS/HTTPS phase (1..60)')
            sub.add_argument('--attempts', type=int, help='Attempts for potential routing failures (2..3)')
            sub.add_argument('--workers', type=int, help='Concurrent domains (1..4)')
            sub.add_argument('--interval', type=float, help='Minimum seconds between domain attempts (0.25..60)')
            sub.add_argument('--resolver-url', help='HTTPS DNS JSON resolver URL')
            sub.add_argument('--resolver', action='append', help='Explicit DNS endpoint, repeatable; bypasses native discovery')
            sub.add_argument('--dns-interval', type=float, help='Minimum seconds between individual DNS queries (0.25..60)')
            sub.add_argument('--batch-size', type=int, help='Domains per stage (1..5000; default: 500)')
            sub.add_argument('--batch-pause', type=int, help='Seconds between stages (60..86400; default: 300)')
            sub.add_argument('--one-batch', action='store_true', help='Run one stage, save progress, then exit')
            sub.add_argument('--restart', action='store_true', help='Start a fresh run; any saved cooldown still applies')
            sub.add_argument('--quiet', action='store_true')
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        settings = load_settings(args)
        inventory = load_inventory(Path(settings['antizapret_dir']), [Path(path) for path in args.file],
                                   args.domain, settings['include_download'])
        if args.command != 'scan' or not args.quiet:
            for warning in inventory.warnings:
                print('WARNING: ' + warning, file=sys.stderr, flush=True)
            for notice in inventory.metadata.get('notices', []):
                print('INFO: ' + notice, file=sys.stderr, flush=True)
        if args.command == 'inventory':
            for entry in inventory.entries:
                state = 'excluded' if entry.excluded else 'already_warp' if entry.included else 'normal'
                print(f'{entry.domain}\t{state}\t' + ', '.join(entry.sources))
            return 0
        if args.command == 'audit':
            plan, dns_error = None, None
            try:
                plan = dns_plan(settings)
            except (OSError, ValueError, RuntimeError) as exc:
                dns_error = str(exc)
            comparison = None
            if args.compare_download:
                expanded = load_inventory(Path(settings['antizapret_dir']), [Path(path) for path in args.file],
                                          args.domain, True)
                comparison = {'mode': 'raw_expansion', 'unique_count': len(expanded.entries),
                              'unique_contributions': expanded.metadata.get('unique_contributions', {}),
                              'source_stats': expanded.metadata.get('source_stats', []),
                              'downloaded_entries_omitted': expanded.metadata.get('downloaded_entries_omitted', 0)}
                del expanded
            with report_lock(settings['report_dir']):
                audit = write_inventory_audit(settings['report_dir'], inventory, plan, dns_error, comparison)
            print(f"Inventory: {audit['unique_count']} unique domains; no DNS or HTTPS checks were sent.")
            if comparison:
                print(f"With raw expansion: {comparison['unique_count']} unique domains.")
            print('Audit: ' + str(Path(settings['report_dir']).resolve() / 'inventory-audit.txt'))
            if dns_error:
                print('DNS discovery needs attention: ' + dns_error, file=sys.stderr)
            return 0
        if not inventory.entries:
            raise ValueError('No domains found. Check --az-dir, result/include-hosts.txt and download/*domain.txt, or pass --file/--domain.')
        if not shutil.which('curl'):
            raise ValueError('curl is required. Install it before scanning.')
        plan = dns_plan(settings)
        inventory.metadata['dns_plan'] = plan
        probe_context = {'probe_version': 2, 'dns': plan, 'attempts': settings['attempts'],
                         'timeout_seconds': settings['timeout_seconds'], 'method': 'verified HTTPS HEAD IPv4'}
        if not args.quiet:
            print(f'Checking {len(inventory.entries)} domains from this VPS; donor access is unverified.', file=sys.stderr, flush=True)
            metadata = inventory.metadata
            print('Inventory: ' + metadata.get('coverage', 'unknown') +
                  f"; {len(metadata.get('native_files', []))} host lists, " +
                  f"{len(metadata.get('registry_files', []))} registry lists, " +
                  f"{len(metadata.get('rpz_files', []))} RPZ files.", file=sys.stderr, flush=True)
            print('Unique contributions: ' + json.dumps(metadata.get('unique_contributions', {}), sort_keys=True),
                  file=sys.stderr, flush=True)
            print('DNS mode: ' + plan['mode'] + '; reference: ' +
                  (plan.get('reference', {}).get('id') or plan.get('resolver_url', 'unknown')) +
                  f"; {len(plan.get('upstreams', []))} upstream diagnostic endpoints.", file=sys.stderr, flush=True)
            for warning in plan.get('warnings', []):
                print('WARNING: ' + warning, file=sys.stderr, flush=True)
            minimum = max(0, len(inventory.entries) - 1) * settings['interval_seconds']
            print('Fresh-run domain-attempt pacing floor: ' + _duration(minimum) +
                  '; this excludes individual DNS pacing, batch pauses, retries and network delays. '
                  'Saved checks reduce remaining work.', file=sys.stderr, flush=True)
            if plan['mode'] != 'explicit-doh':
                queries = sum(1 + sum(endpoint['id'] != plan['reference']['id']
                                      for endpoint in applicable_resolvers(plan, entry.domain))
                              for entry in inventory.entries)
                dns_minimum = max(0, queries - 1) * settings['dns_interval_seconds']
                print(f'Fresh-run DNS matrix: {queries} queries before retries; DNS pacing floor ' +
                      _duration(dns_minimum) + '. Domain and DNS pacing overlap; batch pauses and '
                      'network delays add time.', file=sys.stderr, flush=True)
            print(f"Stages: up to {settings['batch_size']} domains; "
                  f"{settings['batch_pause_seconds']}s pause between stages. "
                  'Completed checks are saved for resume.', file=sys.stderr, flush=True)

        started = last_progress = 0.0
        initial_completed = 0

        def progress(done, total):
            nonlocal last_progress
            now = time.monotonic()
            if now - last_progress < 60:
                return
            last_progress = now
            elapsed = max(0.0, now - started)
            remaining = elapsed / max(1, done - initial_completed) * (total - done)
            print(f'Progress: {done}/{total} completed ({100 * done / total:.2f}%); '
                  f'elapsed {_duration(elapsed)}; rough remaining {_duration(remaining)}.',
                  file=sys.stderr, flush=True)

        batch_number = 1

        def event(update):
            prefix = f"[{update['index']}/{update['total']}] {update['domain']} attempt {update['attempt']}/{update['attempts']}"
            prefix = f'Batch {batch_number} ' + prefix
            if update['type'] == 'start':
                print(prefix + ' QUERY DNS + HTTPS HEAD', file=sys.stderr, flush=True)
                return
            response = update['result']
            parts = [response['status']]
            if response.get('http_status'):
                parts.append('HTTP ' + str(response['http_status']))
            if response.get('curl_code') is not None:
                parts.append('curl ' + str(response['curl_code']))
            if response.get('address'):
                parts.append('IP ' + response['address'])
            parts.append(f"{update['elapsed_seconds']:.3f}s")
            print(prefix + ' RESPONSE ' + ' | '.join(parts) + ' | ' + response['detail'],
                  file=sys.stderr, flush=True)

        def log(message):
            if not args.quiet:
                print(message, file=sys.stderr, flush=True)

        dns_output_lock = threading.Lock()

        def dns_event(update):
            with dns_output_lock:
                prefix = f"DNS {update['domain']} via {update['resolver']} "
                if update['type'] == 'dns_start':
                    log(prefix + 'QUERY A')
                else:
                    answer = update['result']
                    log(prefix + 'RESPONSE ' + answer['status'] + ' | ' + str(answer.get('rcode')) +
                        ' | ' + ', '.join(answer.get('addresses', [])) + ' | ' + answer['detail'])

        report_dir = Path(settings['report_dir'])
        dns_pacer = _Pacer(settings['dns_interval_seconds'])
        with report_lock(report_dir), ScanCheckpoint(report_dir) as checkpoint:
            new_run = checkpoint.prepare(inventory, restart=args.restart, probe_context=probe_context)
            refresh_suggestions(report_dir, checkpoint)
            write_inventory_audit(report_dir, inventory, plan)
            if checkpoint.info().get('context_changed'):
                log('DNS/probe configuration changed; cached checks were invalidated. Saved cooldowns still apply.')
            pending = checkpoint.pending_entries(inventory)
            initial_completed = checkpoint.completed_count()
            started = last_progress = time.monotonic()
            log(('Starting' if new_run else 'Resuming') + f" run {checkpoint.info()['run_id']}: "
                f'{checkpoint.completed_count()}/{len(inventory.entries)} already completed.')

            def snapshot(batch_results, *, final=False):
                info = checkpoint.info()
                state = {'run_id': info['run_id'], 'completed': checkpoint.completed_count(),
                         'total': len(inventory.entries), 'counts': checkpoint.counts(),
                         'batch_index': info['batch_index'],
                         'scope': 'full_run' if final else 'latest_batch',
                         'pause_until': info['pause_until'], 'pause_reason': info['pause_reason']}
                if batch_results:
                    batch_path = report_dir / 'runs' / info['run_id'] / f"batch-{info['batch_index']:06d}"
                    write_reports(batch_path, inventory, batch_results,
                                  progress={**state, 'scope': 'latest_batch'})
                if final:
                    return write_reports(report_dir, inventory, checkpoint.iter_results(),
                                         result_count=state['completed'], counts=state['counts'], progress=state)
                return write_reports(report_dir, inventory, batch_results, progress=state,
                                     suggestions=checkpoint.candidate_domains())

            while pending:
                remaining = checkpoint.pause_remaining()
                if remaining:
                    log(f"Saved cooldown: {_duration(remaining)} remaining ({checkpoint.info()['pause_reason']}).")
                    while checkpoint.pause_remaining() > 0:
                        time.sleep(min(60, checkpoint.pause_remaining()))
                selected = pending[:settings['batch_size']]
                batch_number = checkpoint.info()['batch_index'] + 1
                log(f'Batch {batch_number}: checking {len(selected)} domains; '
                    f'{len(pending)} remain in the current inventory.')
                batch_results = {}
                limited = False

                def completed(result):
                    nonlocal limited
                    saved = checkpoint.save_result(result)
                    limits = [probe for probe in result['checks'] if probe['status'] == 'rate_limited']
                    if limits:
                        limited = True
                        delay = max([3600] + [probe.get('retry_after_seconds', 0) for probe in limits])
                        checkpoint.pause(delay, 'HTTP 429 rate limit')
                    batch_results[result['domain']] = saved

                already_done = checkpoint.completed_count()
                interrupted = False
                stop_event = threading.Event()

                def probe(domain, **options):
                    return check_domain(domain, **options,
                                        resolver_plan=None if plan['mode'] == 'explicit-doh' else plan,
                                        dns_pacer=lambda: dns_pacer.wait(stop_event),
                                        cancelled=stop_event.is_set,
                                        dns_event=None if args.quiet else dns_event)

                try:
                    scan_inventory(Inventory(selected, [], inventory.metadata), attempts=settings['attempts'],
                                   workers=settings['workers'], interval_seconds=settings['interval_seconds'],
                                   timeout_seconds=settings['timeout_seconds'], resolver_url=settings['resolver_url'],
                                   probe_fn=probe, stop_event=stop_event,
                                   completed=completed,
                                   progress=None if args.quiet else lambda done, total: progress(
                                       already_done + done, len(inventory.entries)),
                                   event=None if args.quiet else event)
                except KeyboardInterrupt:
                    interrupted = True
                if not batch_results and not interrupted:
                    raise RuntimeError('The stage returned no completed checks; saved progress was retained.')
                if not interrupted and not limited and len(batch_results) == len(selected):
                    pending = pending[len(selected):]
                else:
                    pending = checkpoint.pending_entries(inventory)
                if batch_results:
                    checkpoint.finish_batch()
                    if pending:
                        checkpoint.pause(settings['batch_pause_seconds'], 'batch cooldown')
                    snapshot(list(batch_results.values()), final=not pending)
                    if not pending:
                        checkpoint.mark_complete()
                    log(f'Saved {checkpoint.completed_count()}/{len(inventory.entries)} completed checks. '
                        f'Reports: {report_dir.resolve()}')
                if interrupted:
                    log('Scan interrupted; completed checks are saved. Run scan again to resume after the saved cooldown.')
                    return 130
                if limited:
                    log('Rate limit received; scan stopped. The saved cooldown is at least one hour '
                        'and honors a longer Retry-After. Run scan later to resume.')
                    return 0
                if args.one_batch:
                    break
            if not pending:
                if not checkpoint.info()['completed']:
                    snapshot([], final=True)
                    checkpoint.mark_complete()
                if not args.quiet:
                    print(f"Checked {checkpoint.completed_count()} domains; tentative candidates: "
                          f"{checkpoint.counts().get('candidate', 0)}.")
                    print('Reports: ' + str(report_dir.resolve()))
            else:
                log('One stage finished. Run scan again to resume; the saved cooldown still applies.')
        return 0
    except (OSError, ValueError, DomainError, ProbeError, RuntimeError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Scan interrupted. Completed checks in the checkpoint are retained; run scan again to resume.', file=sys.stderr)
        return 130
