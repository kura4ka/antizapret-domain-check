"""Read domain inventories without changing AntiZapret's native lists."""

from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
import re
import stat
import string
from urllib.parse import urlsplit


MAX_FILE_BYTES = 64 * 1024 * 1024
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_NATIVE_CUT = re.compile(r"[\]_~:/?#\[@!$&'()*+,;=]")


class DomainError(ValueError):
    """An input domain or list cannot be read as a domain inventory."""


@dataclass
class InventoryEntry:
    domain: str
    sources: list[str] = field(default_factory=list)
    included: bool = False
    excluded: bool = False


@dataclass
class Inventory:
    entries: list[InventoryEntry]
    warnings: list[str]
    metadata: dict = field(default_factory=dict)


def normalize_domain(value: str) -> str:
    """Return an ASCII hostname from a domain or an ordinary HTTP(S) URL.

    URL paths do not affect a domain-level check. Explicit URL ports must be
    the normal port for the given scheme; credentials are never accepted.
    """
    if not isinstance(value, str):
        raise DomainError("A domain must be text.")
    value = value.strip()
    if not value or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
        raise DomainError("A domain must not be empty or contain whitespace or control characters.")
    if "://" in value:
        try:
            parsed = urlsplit(value)
            scheme = parsed.scheme.lower()
            if scheme not in ("http", "https"):
                raise DomainError("Only HTTP and HTTPS URLs are accepted.")
            if "@" in parsed.netloc:
                raise DomainError("URLs with credentials are not accepted.")
            if parsed.port not in (None, {"http": 80, "https": 443}[scheme]):
                raise DomainError("Only the standard HTTP or HTTPS URL port is accepted.")
            value = parsed.hostname or ""
        except ValueError as exc:
            if isinstance(exc, DomainError):
                raise
            raise DomainError("Invalid URL hostname or port.") from exc
    elif any(char in value for char in "/:@?#[]\\"):
        raise DomainError("Use a bare hostname or a complete HTTP(S) URL.")
    if not value or "*" in value:
        raise DomainError("Wildcard domains are not accepted.")
    try:
        domain = value.lower().encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as exc:
        raise DomainError("The domain cannot be converted to IDNA.") from exc
    if domain.endswith("."):
        domain = domain[:-1]
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise DomainError("Use a domain name, not an IP address.")
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or labels[-1].isdigit() or any(
        not _LABEL.fullmatch(label) for label in labels
    ):
        raise DomainError("Invalid domain name; at least two valid DNS labels are required.")
    return domain


def _read_text(path: Path) -> str:
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise DomainError(f"Domain list is not a regular file: {path}")
        if metadata.st_size > MAX_FILE_BYTES:
            raise DomainError(f"Domain list exceeds the 64 MiB limit: {path}")
        with path.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise DomainError(f"Domain list exceeds the 64 MiB limit: {path}")
        text = data.decode("utf-8-sig")
        if "\x00" in text:
            raise DomainError(f"Domain list contains a NUL character: {path}")
        return text
    except (OSError, UnicodeError) as exc:
        raise DomainError(f"Cannot read a UTF-8 domain list: {path}") from exc


def _source(path: Path, line_number: int) -> str:
    return f"{path.as_posix()}:{line_number}"


def _normalize_native_rule(value: str) -> str:
    """Normalize DNS routing names, including single-label suffix rules."""
    value = value.translate({0x3002: '.', 0xff0e: '.', 0xff61: '.'})
    rule = value[:-1] if value.endswith('.') else value
    if '.' in rule:
        return normalize_domain(value)
    try:
        rule = rule.lower().encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise DomainError("Invalid native suffix rule.") from exc
    if not _LABEL.fullmatch(rule) or rule.isdigit():
        raise DomainError("Invalid native suffix rule.")
    return rule


def _file_stats(path, kind):
    return {'path': path.as_posix(), 'kind': kind, 'lines': 0, 'valid_entries': 0,
            'invalid_entries': 0, 'ignored_lines': 0, 'suffix_rules': 0,
            'catch_all_rules': 0, 'unique_hostnames': 0, 'added_unique': 0,
            'duplicate_targets': 0, 'filtered_entries': 0, 'filter_reasons': {}}


def _native_entries(path: Path, warnings: list[str], stats=None) -> tuple[list[tuple[str, int]], bool]:
    stats = _file_stats(path, 'native') if stats is None else stats
    result = []
    catch_all = False
    for number, line in enumerate(_read_text(path).splitlines(), 1):
        stats['lines'] += 1
        value = re.sub(r"\s+", "", line)
        if not value:
            stats['ignored_lines'] += 1
            continue
        if value == ".":
            if not path.name.endswith(('include-hosts.txt', 'include-warp-hosts.txt')):
                stats['ignored_lines'] += 1
                continue
            catch_all = True
            stats['catch_all_rules'] += 1
            continue
        if not value[0].isalnum():
            stats['ignored_lines'] += 1
            continue
        try:
            if "://" in value:
                raise DomainError("URLs are not native host-list entries.")
            value = _NATIVE_CUT.split(value, maxsplit=1)[0]
            # Native RPZ lists also accept single-label suffix rules such as
            # 'com'. They affect child domains but are not HTTP probe targets.
            rule = _normalize_native_rule(value)
            result.append((rule, number))
            stats['valid_entries'] += 1
            if '.' not in rule:
                stats['suffix_rules'] += 1
        except DomainError as exc:
            stats['invalid_entries'] += 1
            warnings.append(f"{_source(path, number)}: skipped invalid native entry ({exc})")
    stats['unique_hostnames'] = len({domain for domain, _ in result if '.' in domain})
    return result, catch_all


def _user_entries(path: Path) -> list[tuple[str, int]]:
    result = []
    for number, line in enumerate(_read_text(path).splitlines(), 1):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            result.append((normalize_domain(value), number))
        except DomainError as exc:
            raise DomainError(f"{_source(path, number)}: invalid user domain ({exc})") from exc
    return result


def _matching_rule(domain: str, rules: set[str]) -> bool:
    labels = domain.split(".")
    return any(".".join(labels[index:]) in rules for index in range(len(labels)))


def _include_files(directory: Path) -> set[Path]:
    return set(directory.glob("*include-hosts.txt")) | set(directory.glob("*include-warp-hosts.txt"))


@dataclass
class _Rules:
    """Native host rules cover their children; RPZ owners can be exact."""

    suffix: set[str] = field(default_factory=set)
    exact: set[str] = field(default_factory=set)
    wildcard: set[str] = field(default_factory=set)
    all_names: bool = False

    def matches(self, domain: str) -> bool:
        if self.all_names or domain in self.exact or _matching_rule(domain, self.suffix):
            return True
        labels = domain.split('.')
        return any('.'.join(labels[index:]) in self.wildcard for index in range(1, len(labels)))

    def native(self, entries, catch_all=False):
        self.suffix.update(domain for domain, _ in entries)
        self.all_names |= catch_all

    def rank(self, domain):
        """A more specific hostname wins; exact owners beat equal wildcards."""
        labels = domain.split('.')
        best = (0, 0) if self.all_names else (-1, -1)
        if domain in self.exact:
            best = (len(labels), 1)
        for index in range(len(labels)):
            suffix = '.'.join(labels[index:])
            if suffix in self.suffix:
                best = max(best, (len(labels) - index, int(index == 0)))
            if index and suffix in self.wildcard:
                best = max(best, (len(labels) - index, 0))
        return best


def _registry_entries(path: Path, warnings: list[str], stats=None):
    """Read the registry format consumed by parse.sh's download/*domain.txt."""
    invalid = 0
    stats = _file_stats(path, 'registry') if stats is None else stats
    seen = set()
    for number, line in enumerate(_read_text(path).splitlines(), 1):
        stats['lines'] += 1
        # update.sh runs parse.sh with LC_ALL=C; POSIX punctuation includes
        # underscores, unlike Python's Unicode-aware \w character class.
        value = line.strip().strip(string.punctuation).lower()
        if not value or '.' not in value:
            stats['ignored_lines'] += 1
            continue
        # Upstream accepts only these letters, digits and separators before idn.
        if not re.fullmatch(r'[а-яa-z0-9.-]+', value):
            invalid += 1
            continue
        try:
            domain = normalize_domain(value)
            stats['valid_entries'] += 1
            seen.add(domain)
            yield domain, number
        except DomainError:
            invalid += 1
    if invalid:
        warnings.append(f'{path.as_posix()}: skipped {invalid} invalid registry entries.')
    stats['invalid_entries'] = invalid
    stats['unique_hostnames'] = len(seen)


def _rpz_entries(path: Path, warnings: list[str], stats=None):
    """Read finite hostname CNAME policies; never evaluate zone directives."""
    records, unsupported, origin = {}, 0, ''
    stats = _file_stats(path, 'rpz') if stats is None else stats
    for number, line in enumerate(_read_text(path).splitlines(), 1):
        stats['lines'] += 1
        value = line.split(';', 1)[0].strip()
        if not value:
            stats['ignored_lines'] += 1
            continue
        tokens = value.split()
        if tokens[0].upper() == '$TTL':
            stats['ignored_lines'] += 1
            continue
        if tokens[0].upper() == '$ORIGIN':
            try:
                origin = '' if tokens[1] == '.' else _normalize_native_rule(tokens[1])
                stats['ignored_lines'] += 1
            except (IndexError, DomainError):
                unsupported += 1
            continue
        upper = [token.upper() for token in tokens]
        if 'SOA' in upper or all(re.fullmatch(r'[0-9()]+', token) for token in tokens):
            stats['ignored_lines'] += 1
            continue
        if 'CNAME' not in upper:
            unsupported += 1
            continue
        position = upper.index('CNAME')
        if not position or len(tokens) != position + 2 or any(
            token.upper() != 'IN' and not token.isdigit() for token in tokens[1:position]
        ):
            unsupported += 1
            continue
        owner, target = tokens[0], tokens[-1].lower()
        if target not in ('.', 'rpz-passthru.'):
            unsupported += 1
            continue
        if re.search(r'\.rpz-(?:ip|nsip|nsdname|client-ip)\.?$', owner, re.I):
            unsupported += 1
            continue
        wildcard = owner.startswith('*.') or owner == '*'
        if owner == '@' and origin:
            owner, kind = origin, 'exact'
        elif owner in ('*', '*.'):
            if origin:
                owner = origin
                kind = 'wildcard' if wildcard else 'exact'
            else:
                owner, kind = '', 'all'
        else:
            name = owner[2:] if wildcard else owner
            if origin and not name.endswith('.'):
                name += '.' + origin
            try:
                owner = _normalize_native_rule(name)
            except DomainError:
                unsupported += 1
                continue
            kind = 'wildcard' if wildcard else 'exact'
        records[(kind, owner)] = (target == '.', number)
        stats['valid_entries'] += 1
        if kind == 'all':
            stats['catch_all_rules'] += 1
        elif '.' not in owner:
            stats['suffix_rules'] += 1
    if unsupported:
        warnings.append(f'{path.as_posix()}: {unsupported} unsupported RPZ records/directives could not be enumerated.')
    stats['invalid_entries'] = unsupported
    stats['unique_hostnames'] = sum(kind == 'exact' and '.' in owner for kind, owner in records)
    return records


def _add_rpz_rules(records, includes, excludes):
    for (kind, owner), (routed, _) in records.items():
        target = includes if routed else excludes
        if kind == 'all':
            target.all_names = True
        else:
            getattr(target, kind).add(owner)


def load_inventory(
    az_dir: Path,
    user_files: list[Path],
    extra_domains: list[str],
    include_download: bool = False,
) -> Inventory:
    """Read generated routes first; raw registry expansion is explicitly opt-in.

    Generated RPZs override their native source lists. User additions remain
    visible before parsing, with pending provenance rather than active claims.
    """
    az_dir = Path(az_dir)
    config, download, result = az_dir / 'config', az_dir / 'download', az_dir / 'result'
    warnings, notices, stats = [], [], {}
    if not config.is_dir():
        warnings.append(f'AntiZapret config directory was not found: {config}')
    configured = _include_files(config)
    downloaded = _include_files(download)
    registry_files = set(download.glob('*domain.txt')) if include_download else set()
    normal_result, warp_result = result / 'include-hosts.txt', result / 'include-warp-hosts.txt'
    effective = {path for path in (normal_result, warp_result) if path.exists()}
    parsed_rpz_files = {path for path in (result / 'proxy.rpz', result / 'warp.rpz', result / 'warp2.rpz') if path.exists()}
    custom_rpz_files = set(config.glob('*proxy-rpz.txt')) | set(config.glob('*warp-rpz.txt'))
    rpz_files = parsed_rpz_files | custom_rpz_files
    has_parsed = bool(effective or parsed_rpz_files)
    normal_sources = set(config.glob('*exclude-hosts.txt'))
    removes = set(config.glob('*remove-hosts.txt'))
    preference_files = set(config.glob('*exclude-warp-hosts.txt'))
    if include_download:
        normal_sources |= set(download.glob('*exclude-hosts.txt'))
        removes |= set(download.glob('*remove-hosts.txt'))
    generated_excludes = {path for path in (result / 'exclude-hosts.txt', result / 'exclude-warp-hosts.txt') if path.exists()}
    native_files = configured | effective | generated_excludes | preference_files
    if include_download:
        native_files |= downloaded | normal_sources | removes
    # Source exceptions are needed only when generated coverage is unavailable.
    if not has_parsed:
        native_files |= normal_sources | removes
    loaded = {}
    for path in sorted(native_files, key=lambda item: item.as_posix()):
        kind = 'generated_native' if path.parent == result else 'config_native' if path.parent == config else 'download_native'
        stats[path] = _file_stats(path, kind)
        loaded[path] = _native_entries(path, warnings, stats[path])
    rpz = {}
    for path in sorted(rpz_files, key=lambda item: item.as_posix()):
        stats[path] = _file_stats(path, 'generated_rpz' if path.parent == result else 'config_rpz')
        rpz[path] = _rpz_entries(path, warnings, stats[path])

    def native_policy(includes, excludes):
        positive, negative = _Rules(), _Rules()
        for path in includes:
            if path in loaded:
                positive.native(*loaded[path])
        for path in excludes:
            if path in loaded:
                negative.native(*loaded[path])
        return positive, negative

    def rpz_policy(paths):
        positive, negative = _Rules(), _Rules()
        # A custom RPZ is already appended to the generated policy; do not
        # merge a newer source version into an existing generated result.
        records = {}
        for path in sorted(paths, key=lambda item: item.as_posix()):
            records.update(rpz[path])
        _add_rpz_rules(records, positive, negative)
        return positive, negative

    if result / 'proxy.rpz' in rpz:
        normal_policy = rpz_policy({result / 'proxy.rpz'})
    elif normal_result in effective:
        normal_policy = native_policy({normal_result}, {result / 'exclude-hosts.txt'})
    elif has_parsed:
        normal_policy = (_Rules(), _Rules())
    else:
        fallback_normal = {p for p in configured | (downloaded if include_download else set()) if p.name.endswith('include-hosts.txt')}
        normal_policy = native_policy(fallback_normal, normal_sources)
        custom_positive, custom_negative = rpz_policy({p for p in custom_rpz_files if p.name.endswith('proxy-rpz.txt')})
        for destination, source in zip(normal_policy, (custom_positive, custom_negative)):
            destination.exact.update(source.exact)
            destination.wildcard.update(source.wildcard)
            destination.all_names |= source.all_names

    warp_parsed = {p for p in parsed_rpz_files if p.name in ('warp.rpz', 'warp2.rpz')}
    if warp_parsed:
        warp_policies = [rpz_policy({path}) for path in sorted(warp_parsed)]
    elif warp_result in effective:
        warp_policies = [native_policy({warp_result}, {result / 'exclude-warp-hosts.txt'})]
    elif has_parsed:
        warp_policies = [(_Rules(), _Rules())]
    else:
        fallback_warp = {p for p in configured | (downloaded if include_download else set()) if p.name.endswith('include-warp-hosts.txt')}
        warp_policies = [native_policy(fallback_warp, preference_files)]
    if not has_parsed:
        custom_positive, custom_negative = rpz_policy({p for p in custom_rpz_files if p.name.endswith('warp-rpz.txt')})
        for destination, source in zip(warp_policies[0], (custom_positive, custom_negative)):
            destination.exact.update(source.exact)
            destination.wildcard.update(source.wildcard)
            destination.all_names |= source.all_names

    preference = _Rules()
    for path in preference_files:
        preference.native(*loaded[path])
    removed = {domain for path in removes if path in loaded for domain, _ in loaded[path][0]}
    source_excludes = _Rules()
    for path in normal_sources:
        if path in loaded:
            source_excludes.native(*loaded[path])

    def policy_routes(domain, policy):
        return policy[0].rank(domain) > policy[1].rank(domain)

    def currently_routed(domain):
        return policy_routes(domain, normal_policy) or any(policy_routes(domain, policy) for policy in warp_policies)

    def expansion_reason(domain):
        if any(policy_routes(domain, policy) for policy in warp_policies):
            return None
        if domain in removed:
            return 'exact_removal'
        if policy_routes(domain, normal_policy):
            return None
        if not has_parsed and not source_excludes.matches(domain):
            return None
        return 'policy_passthru' if normal_policy[1].matches(domain) else 'outside_effective_routes'

    if not has_parsed and (config.is_dir() or download.is_dir()):
        warnings.append('Parsed result/include-hosts.txt and result/include-warp-hosts.txt are missing; using source lists. Run AntiZapret parse.sh separately for effective routing coverage.')
    elif has_parsed and (normal_result not in effective or warp_result not in effective):
        warnings.append('Some parsed routing host lists are missing; available parsed RPZ policies and source fallbacks are used.')
    entries, pending, contributions = {}, set(), {}

    def add(domain, source, path, category, explicit=False):
        if domain in entries:
            if path in stats:
                stats[path]['duplicate_targets'] += 1
        else:
            entries[domain] = InventoryEntry(domain)
            if path in stats:
                stats[path]['added_unique'] += 1
            contributions[category] = contributions.get(category, 0) + 1
        if source not in entries[domain].sources:
            entries[domain].sources.append(source)
        if explicit and has_parsed and not currently_routed(domain):
            pending.add(domain)

    def omit(path, reason):
        stats[path]['filtered_entries'] += 1
        reasons = stats[path]['filter_reasons']
        reasons[reason] = reasons.get(reason, 0) + 1

    def add_native(path, category, explicit=False, expansion=False):
        for domain, number in loaded[path][0]:
            if '.' not in domain:
                continue
            reason = expansion_reason(domain) if expansion else None if explicit or currently_routed(domain) else 'outside_effective_routes'
            if reason:
                omit(path, reason)
            else:
                add(domain, _source(path, number), path, category, explicit)

    for path in sorted(effective, key=lambda item: item.as_posix()):
        add_native(path, 'generated_host_lists')
    for path in sorted(parsed_rpz_files, key=lambda item: item.as_posix()):
        for (kind, owner), (routed, number) in rpz[path].items():
            if routed and kind == 'exact' and '.' in owner:
                if currently_routed(owner):
                    add(owner, _source(path, number), path, 'generated_rpz')
                else:
                    omit(path, 'policy_passthru')
    for path in sorted(configured, key=lambda item: item.as_posix()):
        add_native(path, 'config_additions', explicit=True)
    for path in sorted(custom_rpz_files, key=lambda item: item.as_posix()):
        for (kind, owner), (routed, number) in rpz[path].items():
            if routed and kind == 'exact' and '.' in owner:
                add(owner, _source(path, number), path, 'config_rpz_additions', explicit=True)
    if include_download:
        for path in sorted(downloaded, key=lambda item: item.as_posix()):
            add_native(path, 'downloaded_host_expansion', expansion=True)
        for path in sorted(registry_files, key=lambda item: item.as_posix()):
            stats[path] = _file_stats(path, 'registry')
            for domain, number in _registry_entries(path, warnings, stats[path]):
                reason = expansion_reason(domain)
                if reason:
                    omit(path, reason)
                else:
                    add(domain, _source(path, number), path, 'registry_expansion')
    filtered = sum(stats[path]['filtered_entries'] for path in downloaded | registry_files if path in stats)
    if filtered:
        notices.append(f'{filtered} downloaded source occurrences were omitted by effective routing, exclusions or exact removals; this is not a unique-domain count.')
    if has_parsed:
        oldest_result = min(path.stat().st_mtime for path in effective | parsed_rpz_files)
        source_files = configured | (downloaded | registry_files if include_download else set()) | custom_rpz_files
        if any(path.stat().st_mtime > oldest_result for path in source_files):
            warnings.append('Some source lists are newer than parsed routing results; explicit config additions remain visible as pending where not currently routed; effective coverage follows generated results.')
    if pending:
        notices.append(f'{len(pending)} explicit config hostnames are pending or outside generated routing; they remain visible as requested user checks.')
    all_policies = [normal_policy] + warp_policies
    if any(policy[0].all_names for policy in all_policies):
        warnings.append('Catch-all routing covers names beyond this finite inventory; all possible Internet domains cannot be enumerated.')
    route_ips = result / 'route-ips.txt'
    if route_ips.exists() and route_ips.stat().st_size:
        notices.append('IP/CIDR routes do not enumerate hostnames; destinations known only by routed IP are outside this finite domain inventory.')
    for path in dict.fromkeys(Path(path) for path in user_files):
        if path not in stats:
            stats[path] = _file_stats(path, 'user_file')
            text = _read_text(path)
            stats[path]['lines'] = len(text.splitlines())
        values = _user_entries(path)
        stats[path]['valid_entries'] += len(values)
        stats[path]['unique_hostnames'] = len({domain for domain, _ in values})
        for domain, number in values:
            add(domain, _source(path, number), path, 'submitted_domains')
    for number, value in enumerate(extra_domains, 1):
        try:
            add(normalize_domain(value), f'--domain:{number}', None, 'submitted_domains')
        except DomainError as exc:
            raise DomainError(f'--domain:{number}: invalid domain ({exc})') from exc
    for entry in entries.values():
        entry.sources.sort()
        entry.included = any(policy[0].matches(entry.domain) for policy in warp_policies)
        active_warp = any(policy_routes(entry.domain, policy) for policy in warp_policies)
        entry.excluded = preference.matches(entry.domain) or (
            not active_warp and any(policy[1].matches(entry.domain) for policy in warp_policies))
    suffix_rules = sum(record['suffix_rules'] for record in stats.values())
    if suffix_rules:
        notices.append(f'{suffix_rules} valid single-label suffix policy occurrences were recognized; suffixes themselves are not probe hostnames.')
    metadata = {'coverage': 'parsed-and-source' if has_parsed else 'source-fallback',
                'include_download': include_download,
                'native_files': sorted(path.as_posix() for path in native_files),
                'registry_files': sorted(path.as_posix() for path in registry_files),
                'rpz_files': sorted(path.as_posix() for path in rpz_files),
                'downloaded_entries_omitted': filtered,
                'finite_inventory_only': True, 'notices': notices,
                'source_stats': sorted(stats.values(), key=lambda record: record['path']),
                'unique_contributions': dict(sorted(contributions.items())),
                'total_unique_domains': len(entries),
                'active_routed_domains': sum(currently_routed(domain) for domain in entries) if has_parsed else 0,
                'pending_config_domains': sorted(pending),
                'pending_config_count': len(pending),
                'valid_suffix_policy_occurrences': suffix_rules,
                'invalid_source_entries': sum(record['invalid_entries'] for record in stats.values())}
    return Inventory([entries[domain] for domain in sorted(entries)], warnings, metadata)
