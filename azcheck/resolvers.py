"""Read supported native DNS configuration without evaluating Lua or shell."""

import ast
import hashlib
import ipaddress
import math
from pathlib import Path
import re
import stat
import time
from urllib.parse import urlsplit

from .domains import DomainError, normalize_domain


MAX_CONFIG_BYTES = 1024 * 1024
MAX_POLICY_BYTES = 64 * 1024 * 1024
MAX_ANSWERS = 128
MAX_CNAME_HOPS = 16
_STRING = r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\""
_GROUP = re.compile(r'(?P<name>[A-Za-z_]\w*)\s*=\s*policy\.(?P<method>FORWARD|STUB)\s*\(\s*(?P<value>\{[^{}]*\}|' + _STRING + r')\s*\)', re.S)


class ResolverError(ValueError):
    """The native DNS plan cannot be identified or a resolver is invalid."""


def _read(path):
    path = Path(path)
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CONFIG_BYTES:
            raise ResolverError(f'DNS configuration must be a regular file below 1 MiB: {path}')
        with path.open('rb') as handle:
            data = handle.read(MAX_CONFIG_BYTES + 1)
        if len(data) > MAX_CONFIG_BYTES or b'\x00' in data:
            raise ResolverError(f'Invalid or oversized DNS configuration: {path}')
        return data.decode('utf-8-sig')
    except (OSError, UnicodeError) as exc:
        raise ResolverError(f'Cannot read native DNS configuration {path}: {exc}') from exc


def _uncomment(text):
    """Remove Lua comments while keeping quoted strings intact."""
    token = re.compile(r'(' + _STRING + r')|--\[\[.*?\]\]|--[^\n]*', re.S)
    return token.sub(lambda match: match.group(1) if match.group(1) else '\n' * match.group().count('\n'), text)


def _file_digest(path, maximum):
    """Hash policy inputs without materializing a large RPZ in memory."""
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ResolverError(f'Native DNS policy is not a regular file within its size limit: {path}')
        digest, read = hashlib.sha256(), 0
        with path.open('rb') as handle:
            while True:
                chunk = handle.read(min(65536, maximum - read + 1))
                if not chunk:
                    return digest.digest()
                read += len(chunk)
                if read > maximum:
                    raise ResolverError(f'Native DNS policy exceeds its size limit: {path}')
                digest.update(chunk)
    except OSError as exc:
        raise ResolverError(f'Cannot hash native DNS policy {path}: {exc}') from exc


def _literal_strings(value):
    value = value.strip()
    if value.startswith('{') and value.endswith('}'):
        value = value[1:-1]
    result = []
    position = 0
    token = re.compile(_STRING)
    while position < len(value):
        whitespace = re.match(r'[\s,]*', value[position:])
        position += whitespace.end()
        if position == len(value):
            break
        match = token.match(value, position)
        if match is None:
            raise ResolverError('Only literal DNS address lists can be discovered safely.')
        try:
            decoded = ast.literal_eval(match.group())
        except (SyntaxError, ValueError) as exc:
            raise ResolverError('Unsupported escaped DNS configuration literal.') from exc
        if not isinstance(decoded, str) or '\\' in decoded:
            raise ResolverError('Unsupported DNS configuration literal.')
        result.append(decoded)
        position = match.end()
        if position < len(value) and value[position] not in ', \t\r\n':
            raise ResolverError('Invalid literal DNS address list.')
    if not result:
        raise ResolverError('A configured DNS address list is empty.')
    return result


def parse_resolver(value, *, allow_loopback=False):
    """Parse a numeric UDP/TCP/TLS resolver without consulting system DNS."""
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        raise ResolverError('Use a numeric DNS endpoint such as udp://1.1.1.1:53.')
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ('udp', 'tcp', 'tls') or parsed.path or parsed.query:
            raise ValueError()
        if parsed.username is not None or parsed.password is not None:
            raise ValueError()
        address = ipaddress.ip_address(parsed.hostname or '')
        if not address.is_global and not (allow_loopback and address.is_loopback):
            raise ValueError()
        if address.is_multicast or address.is_unspecified:
            raise ValueError()
        port = parsed.port if parsed.port is not None else (853 if parsed.scheme == 'tls' else 53)
        if not 1 <= port <= 65535:
            raise ValueError()
        endpoint = {'address': str(address), 'port': port, 'transport': parsed.scheme}
        host = f'[{address}]' if address.version == 6 else str(address)
        endpoint['id'] = f'{parsed.scheme}://{host}:{port}'
        if parsed.scheme == 'tls':
            if not parsed.fragment:
                raise ValueError()
            endpoint['tls_hostname'] = normalize_domain(parsed.fragment)
            endpoint['id'] += '#' + endpoint['tls_hostname']
        elif parsed.fragment:
            raise ValueError()
        return endpoint
    except (ValueError, DomainError) as exc:
        raise ResolverError('DNS endpoints require a public numeric IP, a valid port, and for TLS a #certificate-hostname.') from exc


def _native_endpoint(value):
    if '://' in value:
        return parse_resolver(value)
    address, marker, port = value.rpartition('@')
    if not marker:
        address, port = value, '53'
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ResolverError('Native DNS targets must be numeric IP addresses: ' + value) from exc
    host = f'[{ip}]' if ip.version == 6 else str(ip)
    return parse_resolver(f'udp://{host}:{port}')


def _line(text, position):
    return text.count('\n', 0, position) + 1


def _groups(text, path):
    groups = {}
    for match in _GROUP.finditer(text):
        groups[match['name']] = {
            'method': match['method'],
            'endpoints': [_native_endpoint(value) for value in _literal_strings(match['value'])],
            'source': f'{Path(path).as_posix()}:{_line(text, match.start())}',
        }
    return groups


def _suffix(value):
    if '.' in value.rstrip('.'):
        return normalize_domain(value)
    try:
        rule = value.rstrip('.').lower().encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ResolverError('Invalid custom DNS suffix.') from exc
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', rule) or rule.isdigit():
        raise ResolverError('Invalid custom DNS suffix.')
    return rule


def _custom_rules(text, path):
    """Recognize only explicit suffix routing; any other code needs review."""
    rules = []
    pattern = re.compile(r'policy\.add\s*\(\s*policy\.suffix\s*\(\s*policy\.(FORWARD|STUB)\s*\(\s*(\{[^{}]*\}|' + _STRING + r')\s*\)\s*,\s*\{(?P<suffixes>[^{}]*)\}\s*\)\s*\)\s*;?', re.S)
    remaining = list(text)
    for match in pattern.finditer(text):
        suffix_text = match['suffixes']
        suffixes = []
        suffix_pattern = re.compile(r'(?:policy\.)?todname\s*\(\s*(' + _STRING + r')\s*\)')
        for suffix_match in suffix_pattern.finditer(suffix_text):
            suffixes.append(_suffix(ast.literal_eval(suffix_match.group(1))))
        if re.sub(r'[\s,]', '', suffix_pattern.sub('', suffix_text)) or not suffixes:
            raise ResolverError(f'Unsupported custom DNS suffix expression in {path}; provide an explicit resolver override.')
        rules.append({'method': match.group(1),
                      'endpoints': [_native_endpoint(value) for value in _literal_strings(match.group(2))],
                      'suffixes': suffixes, 'source': f'{Path(path).as_posix()}:{_line(text, match.start())}'})
        remaining[match.start():match.end()] = ' ' * (match.end() - match.start())
    if ''.join(remaining).strip():
        raise ResolverError(f'Unsupported active Lua in {path}; native resolver discovery cannot prove its DNS policies. Use an explicit resolver override.')
    return rules


def discover_resolvers(az_dir, knot_dir=Path('/etc/knot-resolver'),
                       fallback_path=Path('/usr/lib/knot-resolver/kres_modules/fallback.lua')):
    """Discover configured proxy upstreams from supported installed templates.

    This is static configuration discovery, not execution or proof that services
    are running. Querying the real-answer local listener preserves Knot's own
    DNS policies; direct per-upstream diagnostics may use different routing.
    """
    knot_dir, az_dir, fallback_path = Path(knot_dir), Path(az_dir), Path(fallback_path)
    paths = [knot_dir / 'kresd.conf', knot_dir / 'dns.lua', knot_dir / 'custom3.lua', az_dir / 'proxy.py']
    texts = {path: _read(path) for path in paths}
    kresd, definitions, custom = (_uncomment(texts[path]) for path in paths[:3])
    proxy = texts[paths[3]]
    raw_assignments = re.findall(r'^\s*local\s+(antizapret_dns|vpn_dns|proxy_dns)\s*=\s*([A-Za-z_]\w*|[0-9]+)\s*$', kresd, re.M)
    assignments = dict(raw_assignments)
    if (len(raw_assignments) != 3 or len(assignments) != 3
            or len(re.findall(r'\b(?:antizapret_dns|vpn_dns|proxy_dns)\s*=', kresd)) != 3):
        raise ResolverError('Native DNS selections have unsupported or repeated assignments; use an explicit resolver override.')

    def selection(name, visited=None):
        visited = set() if visited is None else visited
        if name in visited or name not in assignments:
            raise ResolverError('Cannot resolve native DNS group selection: ' + name)
        visited.add(name)
        value = assignments[name]
        return int(value) if value.isdigit() else selection(value, visited)

    function = re.search(r'\blocal\s+function\s+upstream\s*\(\s*dns\s*\)\s*'
                         r'(?P<body>.*?)^\s*end\s*\n\s*end\b', kresd, re.S | re.M)
    branch = r'dns\s*==\s*[0-9]+\s+then\s+return\s+[A-Za-z_]\w*\s*'
    supported_body = r'if\s+' + branch + r'(?:elseif\s+' + branch + r')*'
    supported_body += r'(?:else\s+panic\s*\(\s*(?:' + _STRING + r')\s*\)\s*)?'
    if function is None or re.fullmatch(supported_body, function['body']) is None:
        raise ResolverError('The native upstream selection function is unsupported; use an explicit resolver override.')
    pairs = re.findall(r'(?:if|elseif)\s+dns\s*==\s*([0-9]+)\s+then\s+return\s+([A-Za-z_]\w*)', function['body'])
    mapping = {int(number): name for number, name in pairs}
    if len(mapping) != len(pairs):
        raise ResolverError('The native upstream selection function repeats a DNS selection.')
    selected = {name: mapping.get(selection(name)) for name in ('antizapret_dns', 'vpn_dns', 'proxy_dns')}
    groups = _groups(definitions, paths[1])
    if _GROUP.sub('', definitions).strip():
        raise ResolverError('dns.lua contains unsupported active expressions; use an explicit resolver override.')
    if any(name not in groups for name in selected.values()):
        raise ResolverError('Cannot identify all selected native DNS groups from kresd.conf and dns.lua.')
    proxy_default = re.search(r'add_argument\(\s*[\'\"]--dns[\'\"]\s*,\s*default\s*=\s*([\'\"])([^\'\"]+)\1', proxy)
    if not proxy_default or proxy_default.group(2) != '127.3.3.3:53':
        raise ResolverError('The native proxy real-answer upstream is modified or cannot be identified; use an explicit resolver override.')
    block_match = re.search(r"elseif\s+string\.match\(systemd_instance,\s*['\"]\^3['\"]\)\s+then(?P<block>.*?)\nelse\s+panic", kresd, re.S)
    if block_match is None:
        raise ResolverError('Cannot identify the native real-answer Knot instance @3.')
    block = block_match['block']
    if (not re.search(r"net\.listen\(\s*['\"]127\.3\.3\.3['\"]\s*,\s*53\s*[,)]", block)
            or not re.search(r'policy\.add\(\s*policy\.all\(\s*upstream\(\s*proxy_dns\s*\)\s*\)\s*\)', block)
            or re.search(r'policy\.(?:FORWARD|STUB|TLS_FORWARD)\s*\(', block)):
        raise ResolverError('The real-answer Knot listener or upstream policy is modified; use an explicit resolver override.')
    if not re.search(r"dofile\(\s*['\"]/etc/knot-resolver/custom3\.lua['\"]\s*\)", block):
        raise ResolverError('Cannot identify the native custom3 DNS policy include.')
    known_policies = re.compile(r'policy\.add\(\s*policy\.all\(\s*policy\.FLAGS\(.*?\)\s*\)\s*\)|'
                                r'policy\.add\(\s*policy\.rpz\(\s*answer\s*,\s*[\'\"]/etc/knot-resolver/deny3\.rpz[\'\"]\s*,\s*true\s*\)\s*\)|'
                                r'policy\.add\(\s*policy\.all\(\s*upstream\(\s*proxy_dns\s*\)\s*\)\s*\)', re.S)
    if 'policy.add' in known_policies.sub('', block):
        raise ResolverError('The real-answer Knot instance has unsupported active DNS policies; use an explicit resolver override.')
    custom_rules = _custom_rules(custom, paths[2])
    warnings = ['Native DNS discovery reads saved configuration; service runtime and command-line overrides are not introspected.',
                'Direct upstream comparisons run as the checker user and may use different egress from Knot (for example DNS_WARP UID routing).']
    policy_digests = {}
    for filename, maximum in (('deny3.rpz', MAX_POLICY_BYTES), ('renumber3.lua', MAX_CONFIG_BYTES)):
        if filename not in block:
            continue
        path = knot_dir / filename
        if path.exists():
            policy_digests[path] = _file_digest(path, maximum)
            paths.append(path)
        else:
            policy_digests[path] = b'missing'
            warnings.append(f'Native DNS references a missing policy file: {path}; runtime answers may be unavailable.')
    if re.search(r"policy\.rpz\([^\n]*deny3\.rpz", block):
        warnings.append('The native reference includes deny3/renumber3 policies; these may differ from direct upstream answers.')
    reference = parse_resolver('udp://127.3.3.3:53', allow_loopback=True)
    reference.update({'role': 'reference', 'groups': ['proxy_dns'],
                      'sources': [paths[0].as_posix(), paths[3].as_posix()]})
    endpoints = {}

    def register(endpoint, group, source, role):
        existing = endpoints.setdefault(endpoint['id'], {**endpoint, 'groups': [], 'sources': [], 'roles': []})
        for key, value in (('groups', group), ('sources', source), ('roles', role)):
            if value not in existing[key]:
                existing[key].append(value)
        return endpoint['id']

    selected_proxy = groups[selected['proxy_dns']]
    base_ids = [register(endpoint, selected['proxy_dns'], selected_proxy['source'], 'upstream')
                for endpoint in selected_proxy['endpoints']]
    fallback_ids = []
    if re.search(r"['\"]fallback['\"]", block):
        fallback_text = _read(fallback_path)
        texts[fallback_path] = fallback_text
        paths.append(fallback_path)
        fallback_groups = _groups(_uncomment(fallback_text), fallback_path)
        if 'action' not in fallback_groups or fallback_groups['action']['method'] != 'FORWARD':
            raise ResolverError('Cannot identify the native fallback DNS action.')
        fallback_ids = [register(endpoint, 'fallback', fallback_groups['action']['source'], 'fallback')
                        for endpoint in fallback_groups['action']['endpoints']]
    routing = []
    for index, rule in enumerate(custom_rules, 1):
        ids = [register(endpoint, f'custom3:{index}', rule['source'], 'custom') for endpoint in rule['endpoints']]
        routing.append({'suffixes': rule['suffixes'], 'method': rule['method'], 'resolver_ids': ids, 'source': rule['source']})
    digest = hashlib.sha256()
    for path in sorted(texts, key=str):
        digest.update(path.as_posix().encode() + b'\0' + texts[path].encode() + b'\0')
    for path in sorted(policy_digests, key=str):
        digest.update(path.as_posix().encode() + b'\0' + policy_digests[path] + b'\0')
    return {'reference': reference, 'upstreams': list(endpoints.values()), 'warnings': warnings,
            'sources': [path.as_posix() for path in paths], 'fingerprint': digest.hexdigest(),
            'context': {'mode': 'native', 'selected_groups': selected,
                        'primary_resolver_ids': base_ids, 'primary_method': selected_proxy['method'],
                        'fallback_resolver_ids': fallback_ids, 'custom_rules': routing,
                        'path': 'proxy.py -> Knot @3 -> proxy_dns; direct matrix is diagnostic'}}


def applicable_resolvers(plan, domain):
    """Select the first applicable custom suffix policy, then native fallback."""
    domain = normalize_domain(domain)
    context = plan.get('context', {})
    ids = list(context.get('primary_resolver_ids', []))
    method = context.get('primary_method', 'FORWARD')
    for rule in context.get('custom_rules', []):
        if any(domain == suffix or domain.endswith('.' + suffix) for suffix in rule['suffixes']):
            ids, method = list(rule['resolver_ids']), rule['method']
            break
    if method == 'FORWARD':
        ids.extend(context.get('fallback_resolver_ids', []))
    # Explicit plans can supply an already selected upstream list.
    if not ids and 'primary_resolver_ids' not in context:
        ids = [endpoint['id'] for endpoint in plan.get('upstreams', [])]
    wanted = set(ids)
    return [endpoint for endpoint in plan.get('upstreams', []) if endpoint['id'] in wanted]


def _load_dns():
    try:
        import dns.exception
        import dns.flags
        import dns.message
        import dns.name
        import dns.query
        import dns.rcode
        import dns.rdatatype
        return dns
    except ImportError as exc:
        raise ResolverError('Native DNS checks require dnspython. Install python3-dnspython or rerun the installer.') from exc


def query_resolver(domain, endpoint, timeout=8.0):
    """Query one numeric endpoint; never resolve names through system DNS."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 1 <= timeout <= 60:
        raise ResolverError('DNS timeout must be between 1 and 60 seconds.')
    if '://' in domain:
        raise ResolverError('A bare domain is required for DNS queries.')
    domain = normalize_domain(domain)
    validated = parse_resolver(endpoint['id'], allow_loopback=endpoint.get('role') == 'reference')
    if any(validated.get(key) != endpoint.get(key) for key in ('address', 'port', 'transport', 'tls_hostname')):
        raise ResolverError('DNS endpoint metadata does not match its validated ID.')
    dns = _load_dns()
    started = time.monotonic()
    result = {'resolver': endpoint['id'], 'address': endpoint['address'], 'port': endpoint['port'],
              'transport': endpoint['transport'], 'rcode': None, 'status': 'dns_error', 'addresses': []}

    def finish(status, detail):
        result.update(status=status, detail=detail, elapsed_seconds=round(max(0, time.monotonic() - started), 3))
        return result

    try:
        question = dns.message.make_query(domain, dns.rdatatype.A, use_edns=False)
        options = {'timeout': timeout, 'port': endpoint['port']}
        if endpoint['transport'] == 'udp':
            try:
                reply = dns.query.udp(question, endpoint['address'], raise_on_truncation=True, **options)
            except dns.message.Truncated:
                result['used_tcp_fallback'] = True
                options['timeout'] = max(0.001, timeout - (time.monotonic() - started))
                reply = dns.query.tcp(question, endpoint['address'], **options)
            if reply.flags & dns.flags.TC:
                result['used_tcp_fallback'] = True
                options['timeout'] = max(0.001, timeout - (time.monotonic() - started))
                reply = dns.query.tcp(question, endpoint['address'], **options)
        elif endpoint['transport'] == 'tcp':
            reply = dns.query.tcp(question, endpoint['address'], **options)
        elif endpoint['transport'] == 'tls':
            reply = dns.query.tls(question, endpoint['address'], verify=True,
                                  server_hostname=endpoint['tls_hostname'], **options)
        else:
            raise ResolverError('Unsupported DNS transport.')
        if reply.flags & dns.flags.TC:
            return finish('dns_error', 'DNS response remained truncated after the supported transport fallback.')
        result['rcode'] = dns.rcode.to_text(reply.rcode())
        if reply.rcode() != dns.rcode.NOERROR:
            return finish('dns_error', 'Resolver returned ' + result['rcode'] + '.')
        if len(reply.answer) > MAX_ANSWERS or sum(len(rrset) for rrset in reply.answer) > MAX_ANSWERS:
            return finish('dns_error', 'DNS answer exceeded the record limit.')
        aliases = {}
        for rrset in reply.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                targets = {record.target.canonicalize() for record in rrset}
                if len(targets) != 1:
                    return finish('dns_error', 'DNS returned an ambiguous CNAME answer.')
                name = rrset.name.canonicalize()
                target = next(iter(targets))
                if name in aliases and aliases[name] != target:
                    return finish('dns_error', 'DNS returned conflicting CNAME answers.')
                aliases[name] = target
        terminal = dns.name.from_text(domain).canonicalize()
        visited = set()
        while terminal in aliases:
            if terminal in visited or len(visited) >= MAX_CNAME_HOPS:
                return finish('dns_error', 'DNS CNAME chain is cyclic or exceeded the hop limit.')
            visited.add(terminal)
            terminal = aliases[terminal]
        addresses = set()
        for rrset in reply.answer:
            if rrset.rdtype != dns.rdatatype.A or rrset.name.canonicalize() != terminal:
                continue
            for record in rrset:
                address = ipaddress.IPv4Address(record.address)
                if not address.is_global or address.is_multicast:
                    return finish('skipped', 'DNS returned a non-public IPv4 address; HTTPS use is prohibited.')
                addresses.add(str(address))
        if not addresses:
            return finish('dns_error', 'No public IPv4 A record was returned for the query/CNAME chain.')
        result['addresses'] = sorted(addresses, key=ipaddress.IPv4Address)
        return finish('ok', 'Resolver returned public IPv4 A records.')
    except ResolverError:
        raise
    except (dns.exception.DNSException, OSError, ValueError, KeyError) as exc:
        return finish('dns_error', f'DNS query failed ({type(exc).__name__}).')
