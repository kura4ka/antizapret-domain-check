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
            rule = value[:-1] if value.endswith(".") else value
            if "." not in rule:
                try:
                    rule = rule.lower().encode("idna").decode("ascii").lower()
                except UnicodeError as exc:
                    raise DomainError("Invalid native suffix rule.") from exc
                if not _LABEL.fullmatch(rule) or rule.isdigit():
                    raise DomainError("Invalid native suffix rule.")
            else:
                rule = normalize_domain(value)
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


def load_inventory(
    az_dir: Path,
    user_files: list[Path],
    extra_domains: list[str],
    include_download: bool = False,
) -> Inventory:
    """Collect configured and submitted domains, with native WARP status.

    ``included`` records an include-rule match and ``excluded`` records an
    exclusion-rule match. Both can be true: exclusions take precedence.
    Downloaded WARP rules always contribute to classification, but downloaded
    domains become check candidates only when ``include_download`` is enabled.
    """
    az_dir = Path(az_dir)
    config, download = az_dir / "config", az_dir / "download"
    warnings = []
    if not config.is_dir():
        warnings.append(f"AntiZapret config directory was not found: {config}")
    candidates = _include_files(config)
    if include_download:
        candidates |= _include_files(download)
    warp_files = set(config.glob("*include-warp-hosts.txt")) | set(download.glob("*include-warp-hosts.txt"))
    exclude_files = set(config.glob("*exclude-warp-hosts.txt"))
    loaded = {
        path: _native_entries(path, warnings)
        for path in sorted(candidates | warp_files | exclude_files, key=lambda item: item.as_posix())
    }
    warp_rules = {domain for path in warp_files for domain, _ in loaded[path][0]}
    exclude_rules = {domain for path in exclude_files for domain, _ in loaded[path][0]}
    warp_all = any(loaded[path][1] for path in warp_files)
    entries: dict[str, InventoryEntry] = {}

    def add(domain: str, source: str) -> None:
        entry = entries.setdefault(domain, InventoryEntry(domain))
        if source not in entry.sources:
            entry.sources.append(source)

    for path in sorted(candidates, key=lambda item: item.as_posix()):
        for domain, number in loaded[path][0]:
            if "." not in domain:
                warnings.append(f"{_source(path, number)}: suffix rule '{domain}' has no hostname to check.")
                continue
            add(domain, _source(path, number))
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
        entry.included = warp_all or _matching_rule(entry.domain, warp_rules)
        entry.excluded = _matching_rule(entry.domain, exclude_rules)
    return Inventory([entries[domain] for domain in sorted(entries)], warnings)
