"""Read-only inventory diagnostics and current, reviewable suggestions."""

from collections import Counter
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

from . import __version__


def _timestamp():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


@contextmanager
def _staged_text(path):
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=str(path.parent))
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as handle:
            os.chmod(temporary, 0o600)
            yield Path(temporary), handle
            if not handle.closed:
                handle.flush()
                os.fsync(handle.fileno())
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _state(entry):
    return 'excluded' if entry.excluded else 'already_warp' if entry.included else 'normal'


def _tsv(value):
    return str(value).replace('\\', '\\\\').replace('\t', '\\t').replace('\r', '\\r').replace('\n', '\\n')


def _counts_text(counts):
    return ', '.join(f'{key}={value}' for key, value in sorted(counts.items())) or 'unavailable'


def _source_accounting(sources):
    lines = []
    for source in sources:
        lines.append('  ' + str(source.get('path', 'unknown')))
        counts = ', '.join(f'{key}={source[key]}' for key in (
            'valid_entries', 'unique_hostnames', 'added_unique', 'duplicate_targets',
            'filtered_entries', 'invalid_entries', 'suffix_rules') if key in source)
        lines.append('    ' + (counts or 'No counts available.'))
        reasons = source.get('filter_reasons', {})
        if reasons:
            lines.append('    Filter reasons: ' + _counts_text(reasons))
    if not sources:
        lines.append('  No source accounting available.')
    return lines


def _audit_text(report):
    inventory, dns = report['inventory'], report['dns']
    lines = [f"AntiZapret inventory audit {report['version']} — {report['generated_at']}",
             'No DNS or HTTPS requests were made by this inventory audit.',
             f"Unique domains selected: {report['unique_count']}",
             'States: ' + ', '.join(f'{key}={value}' for key, value in report['states'].items()),
             f"Inventory coverage: {inventory.get('coverage', 'unknown')}; "
             f"download expansion: {inventory.get('include_download', 'unknown')}",
             f"Active routed domains: {report['active_routed_domains']}; "
             f"pending config domains: {report['pending_config_count']}",
             'Unique contributions: ' + _counts_text(report['unique_contributions']),
             f"Filtered downloaded source occurrences: {inventory.get('downloaded_entries_omitted', 0)}; "
             f"invalid source entries: {inventory.get('invalid_source_entries', 0)}; "
             f"valid suffix policy occurrences: {inventory.get('valid_suffix_policy_occurrences', 0)}",
             'Occurrence counts may include duplicate source rows; they are not unique-domain counts.',
             'DNS plan status: ' + dns['status']]
    if dns['error']:
        lines.append('DNS discovery error: ' + dns['error'])
    if isinstance(dns['plan'], dict):
        reference = dns['plan'].get('reference')
        if reference:
            lines.append('Reference DNS endpoint: ' + str(reference.get('id', reference) if isinstance(reference, dict) else reference))
        elif dns['plan'].get('resolver_url'):
            lines.append('Reference DNS endpoint: ' + str(dns['plan']['resolver_url']))
        selected = dns['plan'].get('context', {}).get('selected_groups', {})
        if selected:
            lines.append('Selected native DNS groups: ' + json.dumps(selected, sort_keys=True))
        for endpoint in dns['plan'].get('upstreams', []):
            lines.append('Configured DNS endpoint: ' + str(endpoint.get('id', endpoint)))
        for warning in dns['plan'].get('warnings', []):
            lines.append('DNS WARNING: ' + str(warning))
    if report.get('comparison') is not None:
        comparison = report['comparison']
        count = comparison.get('unique_count')
        lines.extend(['', 'Raw download expansion comparison:',
                      '  Unique domains: ' + str(count if count is not None else 'unavailable')])
        if type(count) is int:
            difference = count - report['unique_count']
            lines.append(f'  Unique-count difference from selected: {difference:+d}')
        lines.extend([
            '  Unique contributions: ' + _counts_text(comparison.get('unique_contributions', {})),
            '  Filtered downloaded source occurrences: ' + str(comparison.get('downloaded_entries_omitted', 0)),
            '', 'Comparison per-source accounting:'])
        lines.extend(_source_accounting(comparison.get('source_stats', [])))
        lines.append('')
    lines.extend('NOTICE: ' + str(notice) for notice in report['notices'])
    lines.extend('WARNING: ' + str(warning) for warning in report['warnings'])
    lines.extend(['', 'Per-source accounting:'])
    lines.extend(_source_accounting(report['source_stats']))
    lines.extend(['', 'inventory.tsv contains the selected domain, current WARP state, and source references.',
                  'inventory-audit.json contains the full source accounting, DNS plan, and comparison metadata.',
                  'No native AntiZapret lists or routing policies were written.'])
    return '\n'.join(lines) + '\n'


def write_inventory_audit(report_dir, inventory, dns_plan=None, dns_error=None, comparison=None):
    """Write accounting and a streamed TSV of exactly the selected inventory.

    DNS discovery is evidence supplied by the caller; this function performs no
    network queries. A supplied discovery error is reported, not raised. Input
    inventories follow load_inventory's invariant of unique domain entries.
    """
    report_dir = Path(report_dir)
    report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = dict(inventory.metadata)
    report = {'version': __version__, 'generated_at': _timestamp(),
              'scope': 'Read-only inventory audit; no DNS or HTTPS probes performed.',
              'unique_count': 0, 'states': {},
              'unique_contributions': dict(metadata.get('unique_contributions', {})),
              'source_stats': list(metadata.get('source_stats', [])),
              'active_routed_domains': metadata.get('active_routed_domains'),
              'pending_config_count': metadata.get('pending_config_count', 0),
              'pending_config_domains': list(metadata.get('pending_config_domains', [])),
              'warnings': list(inventory.warnings), 'notices': list(metadata.get('notices', [])),
              'inventory': metadata,
              'dns': {'status': 'error' if dns_error is not None else 'discovered' if dns_plan is not None else 'not_requested',
                      'plan': dns_plan, 'error': str(dns_error) if dns_error is not None else None},
              'comparison': comparison}
    names = ('inventory.tsv', 'inventory-audit.txt', 'inventory-audit.json')
    # All content is written and validated before any published file changes.
    with ExitStack() as stack:
        staged = {name: stack.enter_context(_staged_text(report_dir / name)) for name in names}
        tsv = staged['inventory.tsv'][1]
        tsv.write('domain\tstate\tsources\n')
        counts = Counter()
        previous = None
        for entry in sorted(inventory.entries, key=lambda item: item.domain):
            if entry.domain == previous:
                raise ValueError('The inventory audit requires deduplicated domain entries.')
            previous = entry.domain
            state = _state(entry)
            counts[state] += 1
            report['unique_count'] += 1
            tsv.write(_tsv(entry.domain) + '\t' + state + '\t' +
                      _tsv('; '.join(entry.sources)) + '\n')
        report['states'] = {state: counts.get(state, 0) for state in ('normal', 'already_warp', 'excluded')}
        json.dump(report, staged['inventory-audit.json'][1], ensure_ascii=True, indent=2, allow_nan=False)
        staged['inventory-audit.json'][1].write('\n')
        staged['inventory-audit.txt'][1].write(_audit_text(report))
        for temporary, handle in staged.values():
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
        for name, (temporary, _) in staged.items():
            os.replace(temporary, report_dir / name)
    return report


def refresh_suggestions(report_dir, checkpoint):
    """Publish current candidates before a resumed scan waits or sends traffic."""
    report_dir = Path(report_dir)
    report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = report_dir / 'suggested-include-warp-hosts.txt'
    info = checkpoint.info()
    with _staged_text(path) as (temporary, handle):
        handle.write('# Tentative candidates from client-VPS checks only.\n'
                     '# Donor access is unverified. Review failures and test before adding.\n'
                     '# Current exclusions/includes are applied; no AntiZapret file was changed.\n'
                     '# Generated: ' + _timestamp() + '\n'
                     '# Run: ' + str(info['run_id']) + '\n'
                     '# Probe context SHA256: ' + (info.get('probe_context_sha256') or 'unrecorded') + '\n'
                     '# Completed checks in current inventory: ' + str(info['completed_count']) + '\n')
        for domain in checkpoint.candidate_domains():
            handle.write(domain + '\n')
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        os.replace(temporary, path)
    return path
