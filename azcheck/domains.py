"""Read domain inventories without changing AntiZapret's native lists."""

from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
import re
import stat
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
    rule = value[:-1] if value.endswith(".") else value
    if "." in rule:
        return normalize_domain(value)
    try:
        rule = rule.lower().encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise DomainError("Invalid native suffix rule.") from exc
    if not _LABEL.fullmatch(rule) or rule.isdigit():
        raise DomainError("Invalid native suffix rule.")
    return rule


def _native_entries(path: Path, warnings: list[str]) -> tuple[list[tuple[str, int]], bool]:
    result = []
    catch_all = False
    for number, line in enumerate(_read_text(path).splitlines(), 1):
        value = re.sub(r"\s+", "", line)
        if not value:
            continue
        if value == ".":
            catch_all = True
            warnings.append(f"{_source(path, number)}: catch-all '.' has no hostname to check.")
            continue
        if not value[0].isalnum():
            continue
        try:
            if "://" in value:
                raise DomainError("URLs are not native host-list entries.")
            value = _NATIVE_CUT.split(value, maxsplit=1)[0]
            # Native RPZ lists also accept single-label suffix rules such as
            # 'com'. They affect child domains but are not HTTP probe targets.
            rule = _normalize_native_rule(value)
            result.append((rule, number))
        except DomainError as exc:
            warnings.append(f"{_source(path, number)}: skipped invalid native entry ({exc})")
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


def _registry_entries(path: Path, warnings: list[str]):
    """Read the registry format consumed by parse.sh's download/*domain.txt."""
    invalid = 0
    for number, line in enumerate(_read_text(path).splitlines(), 1):
        value = re.sub(r'^[^\w]+|[^\w]+$', '', line.strip()).lower()
        if not value or '.' not in value:
            continue
        # Upstream accepts only these letters, digits and separators before idn.
        if not re.fullmatch(r'[а-яa-z0-9.-]+', value):
            invalid += 1
            continue
        try:
            yield normalize_domain(value), number
        except DomainError:
            invalid += 1
    if invalid:
        warnings.append(f'{path.as_posix()}: skipped {invalid} invalid registry entries.')


def _rpz_entries(path: Path, warnings: list[str]):
    """Read finite hostname CNAME policies; never evaluate zone directives."""
    records, unsupported, origin = {}, 0, ''
    for number, line in enumerate(_read_text(path).splitlines(), 1):
        value = line.split(';', 1)[0].strip()
        if not value:
            continue
        tokens = value.split()
        if tokens[0].upper() == '$TTL':
            continue
        if tokens[0].upper() == '$ORIGIN':
            try:
                origin = '' if tokens[1] == '.' else _normalize_native_rule(tokens[1])
            except (IndexError, DomainError):
                unsupported += 1
            continue
        upper = [token.upper() for token in tokens]
        if 'SOA' in upper or all(re.fullmatch(r'[0-9()]+', token) for token in tokens):
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
    if unsupported:
        warnings.append(f'{path.as_posix()}: {unsupported} unsupported RPZ records/directives could not be enumerated.')
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
    include_download: bool = True,
) -> Inventory:
    """Collect the finite routing inventory produced by AntiZapret.

    Parsed result lists identify effective routes. Config additions remain
    visible immediately; downloaded registry entries expand routed parents to
    their known finite children. WARP flags retain native exclusion precedence.
    """
    az_dir = Path(az_dir)
    config, download, result = az_dir / 'config', az_dir / 'download', az_dir / 'result'
    warnings = []
    if not config.is_dir():
        warnings.append(f'AntiZapret config directory was not found: {config}')
    configured = _include_files(config)
    downloaded = _include_files(download)
    registry_files = set(download.glob('*domain.txt')) if include_download else set()
    normal_result = result / 'include-hosts.txt'
    warp_result = result / 'include-warp-hosts.txt'
    effective = {path for path in (normal_result, warp_result) if path.exists()}
    parsed_rpz_files = {path for path in (result / 'proxy.rpz', result / 'warp.rpz', result / 'warp2.rpz') if path.exists()}
    has_effective_normal = normal_result in effective or (result / 'proxy.rpz') in parsed_rpz_files
    normal_excludes = set(config.glob('*exclude-hosts.txt')) | set(download.glob('*exclude-hosts.txt'))
    normal_removes = set(config.glob('*remove-hosts.txt')) | set(download.glob('*remove-hosts.txt'))
    config_warp_files = set(config.glob('*include-warp-hosts.txt'))
    downloaded_warp_files = set(download.glob('*include-warp-hosts.txt'))
    warp_files = config_warp_files | downloaded_warp_files
    warp_excludes = set(config.glob('*exclude-warp-hosts.txt'))
    for path, files in ((result / 'exclude-hosts.txt', normal_excludes),
                        (result / 'exclude-warp-hosts.txt', warp_excludes)):
        if path.exists():
            files.add(path)
    native_files = configured | downloaded | effective | normal_excludes | normal_removes | warp_files | warp_excludes
    loaded = {path: _native_entries(path, warnings)
              for path in sorted(native_files, key=lambda item: item.as_posix())}
    proxy_includes, proxy_excludes = _Rules(), _Rules()
    warp_includes, warp_exclusions = _Rules(), _Rules()
    for path in normal_excludes:
        proxy_excludes.native(*loaded[path])
    # Config additions are intentional pending user rules. Downloaded rules
    # only describe current WARP routing after parse.sh has generated results.
    has_effective_warp = warp_result in effective or (result / 'warp.rpz').exists()
    classified_warp = config_warp_files | ({warp_result} if warp_result in effective else set())
    if not has_effective_warp:
        classified_warp |= downloaded_warp_files
    for path in classified_warp:
        warp_includes.native(*loaded[path])
    for path in warp_excludes:
        warp_exclusions.native(*loaded[path])
    removed = {domain for path in normal_removes for domain, _ in loaded[path][0]}
    if normal_result in effective:
        proxy_includes.native(*loaded[normal_result])
    elif not has_effective_normal:
        for path in configured | downloaded:
            if path.name.endswith('include-hosts.txt'):
                proxy_includes.native(*loaded[path])
    if not effective and not parsed_rpz_files and (config.is_dir() or download.is_dir()):
        warnings.append('Parsed result/include-hosts.txt and result/include-warp-hosts.txt are missing; using source lists. Run AntiZapret parse.sh separately for effective routing coverage.')
    elif (effective or parsed_rpz_files) and (normal_result not in effective or warp_result not in effective):
        warnings.append('Some parsed routing host lists are missing; available parsed RPZ policies and source fallbacks are used.')
    rpz_files = set(config.glob('*proxy-rpz.txt')) | set(config.glob('*warp-rpz.txt'))
    rpz_files |= parsed_rpz_files
    rpz = {path: _rpz_entries(path, warnings) for path in sorted(rpz_files, key=lambda item: item.as_posix())}
    for path, records in rpz.items():
        warp_policy = path.name.endswith('warp-rpz.txt') or path.name in ('warp.rpz', 'warp2.rpz')
        _add_rpz_rules(records, warp_includes if warp_policy else proxy_includes,
                       warp_exclusions if warp_policy else proxy_excludes)
    entries: dict[str, InventoryEntry] = {}

    def add(domain: str, source: str) -> None:
        entry = entries.setdefault(domain, InventoryEntry(domain))
        if source not in entry.sources:
            entry.sources.append(source)

    def add_native(path, allow=None):
        filtered = 0
        for domain, number in loaded[path][0]:
            if "." not in domain:
                warnings.append(f"{_source(path, number)}: suffix rule '{domain}' has no hostname to check.")
            elif allow is None or allow(domain):
                add(domain, _source(path, number))
            else:
                filtered += 1
        return filtered

    for path in sorted(configured | effective, key=lambda item: item.as_posix()):
        add_native(path)
    for path, records in rpz.items():
        for (kind, owner), (routed, number) in records.items():
            if routed and kind == 'exact' and '.' in owner:
                add(owner, _source(path, number))

    def routed(domain):
        # Generated RPZs can contain a routed child below a parent passthru.
        # Compare hostname specificity instead of letting every parent win.
        normal = proxy_includes.rank(domain) > proxy_excludes.rank(domain) and domain not in removed
        warp = warp_includes.matches(domain) and not warp_exclusions.matches(domain)
        # Without parsed rules, a registry name is an unverified source
        # candidate unless explicitly removed/excluded. Never execute setup.
        fallback = not has_effective_normal and domain not in removed and not proxy_excludes.matches(domain)
        return normal or warp or fallback

    filtered = 0
    if include_download:
        for path in sorted(downloaded, key=lambda item: item.as_posix()):
            filtered += add_native(path, routed)
        for path in sorted(registry_files, key=lambda item: item.as_posix()):
            for domain, number in _registry_entries(path, warnings):
                if routed(domain):
                    add(domain, _source(path, number))
                else:
                    filtered += 1
    if filtered:
        warnings.append(f'{filtered} downloaded entries were outside effective routing coverage or matched exclusions/removals; omitted from checks.')
    if effective or parsed_rpz_files:
        newest_result = min(path.stat().st_mtime for path in effective | parsed_rpz_files)
        source_files = configured | downloaded | registry_files | set(config.glob('*proxy-rpz.txt')) | set(config.glob('*warp-rpz.txt'))
        if any(path.stat().st_mtime > newest_result for path in source_files):
            warnings.append('Some source lists are newer than parsed routing results; new config entries are checked, but downloaded coverage follows the last parse.')
    if proxy_includes.all_names or warp_includes.all_names:
        warnings.append('Catch-all routing covers names beyond this finite inventory; all possible Internet domains cannot be enumerated.')
    route_ips = result / 'route-ips.txt'
    if route_ips.exists() and route_ips.stat().st_size:
        warnings.append('IP/CIDR routes do not enumerate hostnames; destinations known only by routed IP are outside this finite domain inventory.')
    for path in user_files:
        path = Path(path)
        for domain, number in _user_entries(path):
            add(domain, _source(path, number))
    for number, value in enumerate(extra_domains, 1):
        try:
            add(normalize_domain(value), f"--domain:{number}")
        except DomainError as exc:
            raise DomainError(f"--domain:{number}: invalid domain ({exc})") from exc
    for entry in entries.values():
        entry.sources.sort()
        entry.included = warp_includes.matches(entry.domain)
        entry.excluded = warp_exclusions.matches(entry.domain)
    metadata = {'coverage': 'parsed-and-source' if effective or parsed_rpz_files else 'source-fallback',
                'include_download': include_download,
                'native_files': sorted(path.as_posix() for path in native_files),
                'registry_files': sorted(path.as_posix() for path in registry_files),
                'rpz_files': sorted(path.as_posix() for path in rpz_files),
                'downloaded_entries_omitted': filtered,
                'finite_inventory_only': True}
    return Inventory([entries[domain] for domain in sorted(entries)], warnings, metadata)
