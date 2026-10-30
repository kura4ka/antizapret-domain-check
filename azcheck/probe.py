"""Bounded HTTPS header checks using public DNS instead of AntiZapret's fake IPs.

Only HTTPS port 443 is checked. Redirects are reported, never followed. A HEAD
response establishes reachability; it does not prove that a web application works.
"""

import ipaddress
import json
import math
import os
import re
import subprocess
import urllib.parse


DEFAULT_RESOLVER = 'https://1.1.1.1/dns-query'
MAX_DNS_BYTES = 65536
MAX_DNS_ANSWERS = 128
_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


class ProbeError(ValueError):
    """Invalid probe configuration, rather than a domain availability result."""


class _DNSProblem(Exception):
    pass


class _NonPublicAnswer(Exception):
    pass


def _domain_name(value):
    if not isinstance(value, str) or len(value) > 1024:
        raise ValueError('Invalid domain.')
    value = value.strip().lower()
    if value.endswith('.'):
        value = value[:-1]
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError('Invalid domain.') from exc
    labels = value.split('.')
    if len(value) > 253 or '.' not in value or labels[-1].isdigit() or any(not _LABEL.fullmatch(label) for label in labels):
        raise ValueError('A bare DNS domain is required.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('IP addresses are not domains.')


def validate_timeout(value):
    if isinstance(value, bool):
        raise ProbeError('Timeout must be between 1 and 60 seconds.')
    try:
        value = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ProbeError('Timeout must be between 1 and 60 seconds.') from exc
    if not math.isfinite(value) or not 1 <= value <= 60:
        raise ProbeError('Timeout must be between 1 and 60 seconds.')
    return value


def validate_resolver_url(value):
    """Require a TLS resolver endpoint, without credentials or custom ports."""
    if not isinstance(value, str) or len(value) > 2048 or any(c.isspace() for c in value):
        raise ProbeError('Resolver must be an HTTPS URL.')
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError()
        if parsed.port not in (None, 443) or parsed.fragment:
            raise ValueError()
        host = parsed.hostname
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            host = _domain_name(host)
        else:
            if not address.is_global or address.is_multicast:
                raise ValueError()
            host = '[' + str(address) + ']' if address.version == 6 else str(address)
        return urllib.parse.urlunsplit(('https', host, parsed.path or '/', parsed.query, ''))
    except (ValueError, UnicodeError) as exc:
        raise ProbeError('Resolver must use HTTPS, a public address or DNS name, and port 443 without credentials.') from exc


def _public_address(domain, timeout, resolver_url):
    parsed = urllib.parse.urlsplit(resolver_url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query = [(key, value) for key, value in query if key not in ('name', 'type')]
    query.extend((('name', domain), ('type', 'A')))
    url = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))
    command = [
        'curl', '--disable', '--silent', '--show-error', '--fail',
        '--proxy', '', '--noproxy', '*', '--proto', '=https',
        '--connect-timeout', str(min(timeout, 5.0)), '--max-time', str(timeout),
        '--max-filesize', str(MAX_DNS_BYTES), '--header', 'Accept: application/dns-json',
        '--user-agent', 'AntiZapret-Domain-Check/0.1', '--write-out', '\n%{http_code}', url,
    ]
    try:
        completed = subprocess.run(command, capture_output=True, timeout=timeout + 1,
                                   check=False, shell=False)
        if completed.returncode:
            raise _DNSProblem('Public DNS request failed (curl ' + str(completed.returncode) + ').')
        if len(completed.stdout) > MAX_DNS_BYTES + 4:
            raise _DNSProblem('DNS response exceeded the size limit.')
        payload, separator, http_status = completed.stdout.rpartition(b'\n')
        if not separator or http_status != b'200':
            raise _DNSProblem('Resolver did not return HTTP 200.')
        if len(payload) > MAX_DNS_BYTES:
            raise _DNSProblem('DNS response exceeded the size limit.')
        document = json.loads(payload)
        if not isinstance(document, dict) or type(document.get('Status')) is not int:
            raise _DNSProblem('Resolver returned an invalid DNS response.')
        if document['Status'] != 0:
            raise _DNSProblem('Resolver returned DNS status ' + str(document['Status']) + '.')
        if document.get('TC') is True:
            raise _DNSProblem('Resolver returned a truncated DNS response.')
        answers = document.get('Answer', [])
        if not isinstance(answers, list) or len(answers) > MAX_DNS_ANSWERS:
            raise _DNSProblem('Resolver returned an invalid answer list.')
        addresses = set()
        for answer in answers:
            if not isinstance(answer, dict):
                raise _DNSProblem('Resolver returned an invalid DNS answer.')
            if answer.get('type') != 1:
                continue
            if type(answer['type']) is not int or not isinstance(answer.get('data'), str):
                raise _DNSProblem('Resolver returned an invalid IPv4 answer.')
            try:
                address = ipaddress.IPv4Address(answer['data'])
            except (KeyError, ValueError, TypeError, ipaddress.AddressValueError) as exc:
                raise _DNSProblem('Resolver returned an invalid IPv4 address.') from exc
            if not address.is_global or address.is_multicast:
                raise _NonPublicAnswer('DNS returned a non-public IPv4 address; HTTPS check skipped.')
            addresses.add(str(address))
        if not addresses:
            raise _DNSProblem('No public IPv4 A record was returned.')
        return sorted(addresses, key=ipaddress.IPv4Address)[0]
    except _NonPublicAnswer:
        raise
    except _DNSProblem:
        raise
    except (OSError, ValueError, RecursionError, subprocess.TimeoutExpired) as exc:
        raise _DNSProblem('Public DNS lookup failed or timed out.') from exc


def _result(domain, status, detail, *, http_status=None, curl_code=None, address=None):
    return {'domain': domain, 'status': status, 'http_status': http_status,
            'curl_code': curl_code, 'address': address, 'detail': detail}


def check_domain(domain: str, timeout: float = 8.0, resolver_url: str = DEFAULT_RESOLVER) -> dict:
    """Check one domain without changing routing, following redirects or reading a body.

    Timeout applies to each DNS/HTTPS phase. Configuration errors raise
    ProbeError; domain-specific failures return an explicit status dictionary.
    """
    timeout = validate_timeout(timeout)
    resolver_url = validate_resolver_url(resolver_url)
    try:
        domain = _domain_name(domain)
    except ValueError:
        return _result(str(domain)[:253], 'skipped', 'A valid bare public DNS domain is required.')
    try:
        address = _public_address(domain, timeout, resolver_url)
    except _NonPublicAnswer as exc:
        return _result(domain, 'skipped', str(exc))
    except _DNSProblem as exc:
        return _result(domain, 'dns_error', str(exc))

    command = [
        'curl', '--disable', '--silent', '--show-error', '--head',
        '--proxy', '', '--noproxy', '*', '--proto', '=https', '--ipv4',
        '--connect-timeout', str(min(timeout, 5.0)), '--max-time', str(timeout),
        '--resolve', domain + ':443:' + address, '--output', os.devnull,
        '--write-out', '%{http_code}\n%{remote_ip}\n',
        '--user-agent', 'AntiZapret-Domain-Check/0.1', 'https://' + domain + '/',
    ]
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=timeout + 1, check=False, shell=False)
    except subprocess.TimeoutExpired:
        return _result(domain, 'transport_error', 'HTTPS header check timed out.', curl_code=28, address=address)
    except OSError:
        return _result(domain, 'transport_error', 'Could not execute curl; verify that it is installed.', curl_code=127, address=address)

    if len(completed.stdout) > 1024:
        return _result(domain, 'transport_error', 'Unexpected output from curl.',
                       curl_code=completed.returncode, address=address)
    fields = completed.stdout.splitlines()
    try:
        http_status = int(fields[0])
    except (ValueError, IndexError):
        http_status = None
    if completed.returncode:
        return _result(domain, 'transport_error', 'HTTPS header check failed (curl ' + str(completed.returncode) + ').',
                       http_status=http_status or None, curl_code=completed.returncode, address=address)
    if len(fields) != 2 or fields[1].strip() != address or http_status is None or not 200 <= http_status <= 599:
        return _result(domain, 'transport_error', 'curl did not confirm a valid response from the selected public address.',
                       curl_code=completed.returncode, address=address)
    if http_status < 400:
        status = 'ok'
    elif http_status in (403, 451):
        status = 'blocked'
    elif http_status == 429:
        status = 'rate_limited'
    elif http_status < 500:
        status = 'reachable'
    else:
        status = 'server_error'
    return _result(domain, status, 'HTTPS HEAD returned HTTP ' + str(http_status) + '; redirects were not followed.',
                   http_status=http_status, curl_code=completed.returncode, address=address)
