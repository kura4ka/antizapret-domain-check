"""Command-line interface for the standalone domain checker."""

import argparse
import json
import math
from pathlib import Path
import shutil
import sys

from . import __version__
from .domains import DomainError, load_inventory
from .probe import ProbeError, validate_resolver_url, validate_timeout
from .scanner import report_lock, scan_inventory, write_reports


DEFAULT_CONFIG = '/etc/antizapret-domain-check/config.json'
LEGACY_REPORT_DIR = '/var/lib/antizapret-domain-check/reports'
DEFAULTS = {'config_version': 2, 'antizapret_dir': '/root/antizapret',
            'report_dir': '/root/antizapret-domain-check/reports',
            'timeout_seconds': 8, 'attempts': 2, 'workers': 2,
            'interval_seconds': 0.5, 'include_download': True,
            'resolver_url': 'https://1.1.1.1/dns-query'}


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
    if type(version) is not int or version not in (1, 2):
        raise ValueError('config_version must be 1 or 2.')
    upgraded = dict(document)
    if version == 1:
        if upgraded.get('report_dir') == LEGACY_REPORT_DIR:
            upgraded['report_dir'] = DEFAULTS['report_dir']
        if 'include_download' in upgraded and type(upgraded['include_download']) is not bool:
            raise ValueError('include_download must be true or false.')
        upgraded['include_download'] = True
    upgraded['config_version'] = 2
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
                 'include_download': 'include_download'}
    for flag, key in overrides.items():
        value = getattr(args, flag, None)
        if value is not None:
            settings[key] = value
    for key in ('antizapret_dir', 'report_dir'):
        if not isinstance(settings[key], str) or not settings[key] or '\x00' in settings[key]:
            raise ValueError(f'{key} must be a directory path.')
    if Path(settings['report_dir']).resolve().is_relative_to(Path(settings['antizapret_dir']).resolve()):
        raise ValueError('report_dir must be outside the AntiZapret directory; reports must not become native routing lists.')
    for key, minimum, maximum in (('attempts', 2, 3), ('workers', 1, 4)):
        if type(settings[key]) is not int or not minimum <= settings[key] <= maximum:
            raise ValueError(f'{key} must be an integer from {minimum} to {maximum}.')
    interval = settings['interval_seconds']
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not math.isfinite(interval) or not 0.25 <= interval <= 60:
        raise ValueError('interval_seconds must be between 0.25 and 60.')
    if type(settings['include_download']) is not bool:
        raise ValueError('include_download must be true or false.')
    settings['timeout_seconds'] = validate_timeout(settings['timeout_seconds'])
    settings['resolver_url'] = validate_resolver_url(settings['resolver_url'])
    return settings


def parser():
    result = argparse.ArgumentParser(description='Check AntiZapret domains from the client VPS and suggest WARP candidates.')
    result.add_argument('--version', action='version', version=__version__)
    commands = result.add_subparsers(dest='command', required=True)
    for command in ('inventory', 'scan'):
        sub = commands.add_parser(command, help='List collected domains' if command == 'inventory' else 'Check domains and write reports')
        sub.add_argument('--config', help='JSON settings file (default: ' + DEFAULT_CONFIG + ')')
        sub.add_argument('--az-dir', help='AntiZapret root (default: /root/antizapret)')
        sub.add_argument('--file', action='append', default=[], help='Also check domains from this text file; repeatable')
        sub.add_argument('--domain', action='append', default=[], help='Also check this domain; repeatable')
        sub.add_argument('--include-download', action=argparse.BooleanOptionalAction, default=None,
                         help='Expand parsed routing lists with downloaded registries (default: enabled; may be very large)')
        if command == 'scan':
            sub.add_argument('--report-dir', help='Report directory (default: ' + DEFAULTS['report_dir'] + ')')
            sub.add_argument('--timeout', type=float, help='Seconds per DNS/HTTPS phase (1..60)')
            sub.add_argument('--attempts', type=int, help='Attempts for potential routing failures (2..3)')
            sub.add_argument('--workers', type=int, help='Concurrent domains (1..4)')
            sub.add_argument('--interval', type=float, help='Minimum seconds between domain attempts (0.25..60)')
            sub.add_argument('--resolver-url', help='HTTPS DNS JSON resolver URL')
            sub.add_argument('--quiet', action='store_true')
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        settings = load_settings(args)
        inventory = load_inventory(Path(settings['antizapret_dir']), [Path(path) for path in args.file],
                                   args.domain, settings['include_download'])
        if args.command == 'inventory' or not args.quiet:
            for warning in inventory.warnings:
                print('WARNING: ' + warning, file=sys.stderr, flush=True)
        if args.command == 'inventory':
            for entry in inventory.entries:
                state = 'excluded' if entry.excluded else 'already_warp' if entry.included else 'normal'
                print(f'{entry.domain}\t{state}\t' + ', '.join(entry.sources))
            return 0
        if not inventory.entries:
            raise ValueError('No domains found. Check --az-dir, result/include-hosts.txt and download/*domain.txt, or pass --file/--domain.')
        if not shutil.which('curl'):
            raise ValueError('curl is required. Install it before scanning.')
        if not args.quiet:
            print(f'Checking {len(inventory.entries)} domains from this VPS; donor access is unverified.', file=sys.stderr, flush=True)
            metadata = inventory.metadata
            print('Inventory: ' + metadata.get('coverage', 'unknown') +
                  f"; {len(metadata.get('native_files', []))} host lists, " +
                  f"{len(metadata.get('registry_files', []))} registry lists, " +
                  f"{len(metadata.get('rpz_files', []))} RPZ files.", file=sys.stderr, flush=True)

        def event(update):
            prefix = f"[{update['index']}/{update['total']}] {update['domain']} attempt {update['attempt']}/{update['attempts']}"
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

        with report_lock(settings['report_dir']):
            results = scan_inventory(inventory, attempts=settings['attempts'], workers=settings['workers'],
                                     interval_seconds=settings['interval_seconds'],
                                     timeout_seconds=settings['timeout_seconds'], resolver_url=settings['resolver_url'],
                                     event=None if args.quiet else event)
            report = write_reports(settings['report_dir'], inventory, results)
        if not args.quiet:
            print(f"Checked {len(results)} domains; tentative candidates: {report['counts'].get('candidate', 0)}.")
            print('Reports: ' + str(Path(settings['report_dir']).resolve()))
        return 0
    except (OSError, ValueError, DomainError, ProbeError, RuntimeError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Scan interrupted. Check report timestamps before using suggestions.', file=sys.stderr)
        return 130
