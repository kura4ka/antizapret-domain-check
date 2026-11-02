"""Native DNS discovery and packet checks use fixtures, never real DNS."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from azcheck import resolvers

try:
    import dns.exception
    import dns.flags
    import dns.message
    import dns.query
    import dns.rcode
    import dns.rrset
except ImportError:
    dns = None


KRESD = '''
local antizapret_dns = 1
local vpn_dns = 2
local proxy_dns = vpn_dns
dofile('/etc/knot-resolver/dns.lua')
local function upstream(dns)
 if dns == 1 then
  return russia_dns
 elseif dns == 2 then
  return world_dns
 elseif dns == 3 then
  return unused_dns
 end
end
if string.match(systemd_instance, '^1') then
 net.listen('127.1.1.1', 53, {})
elseif string.match(systemd_instance, '^3') then
 net.listen('127.3.3.3', 53, {})
 modules = {'fallback'}
 dofile('/etc/knot-resolver/custom3.lua')
 policy.add(policy.rpz(answer, '/etc/knot-resolver/deny3.rpz', true))
 policy.add(policy.all(upstream(proxy_dns)))
else panic('invalid')
end
'''
DEFINITIONS = '''
-- Other options are definitions, not active selections.
russia_dns = policy.FORWARD({'62.76.76.62', '195.208.4.1'})
world_dns = policy.FORWARD({'1.1.1.1', '9.9.9.10@9953'})
unused_dns = policy.STUB({'8.8.8.8'})
'''
FALLBACK = "local M = {action = policy.FORWARD({'1.1.1.1', '208.67.222.222@443'})}"


class NativeDiscoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.az = self.root / 'antizapret'
        self.knot = self.root / 'knot'
        self.az.mkdir()
        self.knot.mkdir()
        (self.knot / 'kresd.conf').write_text(KRESD)
        (self.knot / 'dns.lua').write_text(DEFINITIONS)
        (self.knot / 'custom3.lua').write_text('-- No active custom policies\n')
        (self.az / 'proxy.py').write_text('p.add_argument("--dns",default="127.3.3.3:53",help="native")\n')
        self.fallback = self.root / 'fallback.lua'
        self.fallback.write_text(FALLBACK)

    def discover(self):
        return resolvers.discover_resolvers(self.az, self.knot, self.fallback)

    def test_selected_proxy_group_and_fallback_are_preserved_with_ports_and_deduplication(self):
        plan = self.discover()
        self.assertEqual(plan['reference']['id'], 'udp://127.3.3.3:53')
        self.assertEqual(plan['context']['selected_groups'], {
            'antizapret_dns': 'russia_dns', 'vpn_dns': 'world_dns', 'proxy_dns': 'world_dns'})
        ids = [endpoint['id'] for endpoint in resolvers.applicable_resolvers(plan, 'example.com')]
        self.assertEqual(set(ids), {'udp://1.1.1.1:53', 'udp://9.9.9.10:9953', 'udp://208.67.222.222:443'})
        self.assertEqual(len(ids), len(set(ids)))
        cloudflare = next(endpoint for endpoint in plan['upstreams'] if endpoint['address'] == '1.1.1.1')
        self.assertEqual(cloudflare['groups'], ['world_dns', 'fallback'])
        self.assertFalse(any(endpoint['address'] in ('62.76.76.62', '8.8.8.8') for endpoint in plan['upstreams']))
        self.assertTrue(any('different egress' in warning for warning in plan['warnings']))
        self.assertEqual(len(plan['fingerprint']), 64)

    def test_selected_group_is_read_from_installed_config_and_stub_has_no_forward_fallback(self):
        (self.knot / 'kresd.conf').write_text(KRESD.replace('local vpn_dns = 2', 'local vpn_dns = 3'))
        plan = self.discover()
        self.assertEqual([item['address'] for item in resolvers.applicable_resolvers(plan, 'example.com')], ['8.8.8.8'])

    def test_literal_custom_suffix_policy_replaces_default_and_honors_first_rule(self):
        (self.knot / 'custom3.lua').write_text('''
policy.add(policy.suffix(policy.STUB({'8.8.8.8'}), {
 todname('example.com'), todname('ua'),
}))
policy.add(policy.suffix(policy.FORWARD({'8.8.4.4'}), {todname('sub.example.com')}))
''')
        plan = self.discover()
        for domain in ('sub.example.com', 'child.sub.example.com', 'news.ua'):
            self.assertEqual([item['address'] for item in resolvers.applicable_resolvers(plan, domain)], ['8.8.8.8'])
        self.assertNotIn('8.8.8.8', [item['address'] for item in resolvers.applicable_resolvers(plan, 'notexample.com')])

    def test_unknown_active_lua_is_rejected_without_execution(self):
        sentinel = self.root / 'should-not-exist'
        (self.knot / 'custom3.lua').write_text(f"os.execute('touch {sentinel.as_posix()}')\n")
        with self.assertRaisesRegex(resolvers.ResolverError, 'Unsupported active Lua'):
            self.discover()
        self.assertFalse(sentinel.exists())
        (self.knot / 'custom3.lua').write_text('')
        (self.knot / 'dns.lua').write_text(DEFINITIONS + "\nworld_dns = load_dynamic_dns()\n")
        with self.assertRaisesRegex(resolvers.ResolverError, 'unsupported active expressions'):
            self.discover()

    def test_missing_config_modified_proxy_unknown_selection_and_cycles_fail_clearly(self):
        for config in (KRESD.replace('local vpn_dns = 2', 'local vpn_dns = 99'),
                       KRESD.replace('local vpn_dns = 2', 'local vpn_dns = proxy_dns'),
                       KRESD.replace("'127.3.3.3'", "'127.7.7.7'")):
            with self.subTest(config=config):
                (self.knot / 'kresd.conf').write_text(config)
                with self.assertRaises(resolvers.ResolverError):
                    self.discover()
        (self.knot / 'kresd.conf').write_text(KRESD)
        (self.az / 'proxy.py').write_text('p.add_argument("--dns",default="127.9.9.9:53")\n')
        with self.assertRaisesRegex(resolvers.ResolverError, 'proxy real-answer upstream'):
            self.discover()
        (self.knot / 'dns.lua').unlink()
        with self.assertRaisesRegex(resolvers.ResolverError, 'Cannot read'):
            self.discover()

    def test_comments_do_not_create_targets_and_sources_are_not_modified(self):
        path = self.knot / 'dns.lua'
        path.write_text(DEFINITIONS + "\n--world_dns=policy.FORWARD({'8.8.4.4'})\n")
        before = {item: item.read_bytes() for item in (self.knot.iterdir())}
        first = self.discover()
        self.assertFalse(any(item['address'] == '8.8.4.4' for item in first['upstreams']))
        self.assertEqual(before, {item: item.read_bytes() for item in self.knot.iterdir()})
        path.write_text(path.read_text() + '\n-- configuration changed\n')
        self.assertNotEqual(self.discover()['fingerprint'], first['fingerprint'])

    def test_config_size_and_encoding_are_bounded(self):
        path = self.knot / 'custom3.lua'
        path.write_bytes(b'\x00')
        with self.assertRaises(resolvers.ResolverError):
            self.discover()
        path.write_bytes(b'#' * 16)
        with patch.object(resolvers, 'MAX_CONFIG_BYTES', 15), self.assertRaises(resolvers.ResolverError):
            self.discover()

    def test_native_answer_policy_contents_invalidate_dns_fingerprint(self):
        config = KRESD.replace("modules = {'fallback'}", "modules = {'fallback', renumber = dofile('/etc/knot-resolver/renumber3.lua')}")
        (self.knot / 'kresd.conf').write_text(config)
        deny, renumber = self.knot / 'deny3.rpz', self.knot / 'renumber3.lua'
        deny.write_text('$TTL 86400\n')
        renumber.write_text('return nil\n')
        first = self.discover()
        self.assertIn(deny.as_posix(), first['sources'])
        self.assertIn(renumber.as_posix(), first['sources'])
        deny.write_text('$TTL 86400\nexample.com CNAME .\n')
        second = self.discover()
        self.assertNotEqual(first['fingerprint'], second['fingerprint'])
        renumber.write_text("return {{'1.1.1.0/24', '8.8.8.8!'}}\n")
        self.assertNotEqual(second['fingerprint'], self.discover()['fingerprint'])
        with patch.object(resolvers, 'MAX_POLICY_BYTES', 8), self.assertRaisesRegex(resolvers.ResolverError, 'size limit'):
            self.discover()

    def test_modified_dynamic_or_duplicate_upstream_selection_is_rejected(self):
        for config in (KRESD.replace(' if dns == 1 then', ' return world_dns\n if dns == 1 then'),
                       KRESD.replace(' elseif dns == 2 then', ' elseif dns == 1 then'),
                       KRESD.replace('local proxy_dns = vpn_dns', 'local proxy_dns = vpn_dns\nproxy_dns = 3')):
            with self.subTest(config=config):
                (self.knot / 'kresd.conf').write_text(config)
                with self.assertRaises(resolvers.ResolverError):
                    self.discover()


class EndpointTests(unittest.TestCase):
    def test_numeric_endpoints_preserve_transport_port_and_tls_identity(self):
        self.assertEqual(resolvers.parse_resolver('udp://1.1.1.1')['id'], 'udp://1.1.1.1:53')
        self.assertEqual(resolvers.parse_resolver('tcp://[2606:4700:4700::1111]:5353')['port'], 5353)
        tls = resolvers.parse_resolver('tls://9.9.9.9:853#dns.quad9.net')
        self.assertEqual(tls['tls_hostname'], 'dns.quad9.net')
        self.assertEqual(tls['transport'], 'tls')

    def test_invalid_resolvers_never_use_system_dns_or_nonpublic_targets(self):
        for value in ('udp://localhost:53', 'udp://127.0.0.1:53', 'udp://10.0.0.1:53',
                      'udp://1.1.1.1:0', 'udp://1.1.1.1:65536', 'udp://1.1.1.1:53/path',
                      'udp://1.1.1.1:53#name', 'tls://1.1.1.1:853', 'https://1.1.1.1/query',
                      'udp://224.0.0.1:53', 'udp://user:pass@1.1.1.1:53'):
            with self.subTest(value=value), self.assertRaises(resolvers.ResolverError):
                resolvers.parse_resolver(value)


@unittest.skipIf(dns is None, 'dnspython is required for native DNS packet tests')
class DNSQueryTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = resolvers.parse_resolver('udp://1.1.1.1:53')

    def answer(self, *records, code=None, truncated=False):
        query = dns.message.make_query('example.com', 'A', use_edns=False)
        reply = dns.message.make_response(query)
        if code is not None:
            reply.set_rcode(code)
        if truncated:
            reply.flags |= dns.flags.TC
        for name, kind, value in records:
            reply.answer.append(dns.rrset.from_text(name.rstrip('.') + '.', 60, 'IN', kind, value))
        return reply

    def test_public_a_chain_only_ignores_unrelated_poisoned_records(self):
        reply = self.answer(('example.com', 'CNAME', 'cdn.example.net.'),
                            ('cdn.example.net', 'A', '1.1.1.1'),
                            ('unrelated.example', 'A', '8.8.8.8'))
        with patch('dns.query.udp', return_value=reply) as query:
            result = resolvers.query_resolver('example.com', self.endpoint)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['addresses'], ['1.1.1.1'])
        self.assertEqual(query.call_args.args[1], '1.1.1.1')
        self.assertEqual(query.call_args.kwargs['port'], 53)
        self.assertFalse(query.call_args.args[0].edns >= 0)

    def test_udp_truncation_uses_bounded_tcp_retry_to_same_address_and_port(self):
        self.endpoint = resolvers.parse_resolver('udp://9.9.9.10:9953')
        with patch('dns.query.udp', side_effect=dns.message.Truncated), \
             patch('dns.query.tcp', return_value=self.answer(('example.com', 'A', '1.1.1.1'))) as tcp:
            result = resolvers.query_resolver('example.com', self.endpoint)
        self.assertEqual(result['status'], 'ok')
        self.assertTrue(result['used_tcp_fallback'])
        self.assertEqual(tcp.call_args.args[1], '9.9.9.10')
        self.assertEqual(tcp.call_args.kwargs['port'], 9953)
        self.assertLessEqual(tcp.call_args.kwargs['timeout'], 8)

    def test_tls_checks_certificate_hostname_and_direct_tcp_stays_tcp(self):
        endpoint = resolvers.parse_resolver('tls://9.9.9.9:853#dns.quad9.net')
        reply = self.answer(('example.com', 'A', '1.1.1.1'))
        with patch('dns.query.tls', return_value=reply) as tls:
            self.assertEqual(resolvers.query_resolver('example.com', endpoint)['status'], 'ok')
        self.assertTrue(tls.call_args.kwargs['verify'])
        self.assertEqual(tls.call_args.kwargs['server_hostname'], 'dns.quad9.net')
        endpoint = resolvers.parse_resolver('tcp://1.1.1.1:53')
        with patch('dns.query.tcp', return_value=reply) as tcp:
            self.assertEqual(resolvers.query_resolver('example.com', endpoint)['status'], 'ok')
        tcp.assert_called_once()

    def test_nxdomain_timeout_empty_or_nonpublic_answers_do_not_become_public_success(self):
        replies = [(self.answer(code=dns.rcode.NXDOMAIN), 'dns_error', 'NXDOMAIN'),
                   (self.answer(), 'dns_error', 'NOERROR'),
                   (self.answer(('example.com', 'A', '127.0.0.1')), 'skipped', 'NOERROR'),
                   (self.answer(('unrelated.example', 'A', '1.1.1.1')), 'dns_error', 'NOERROR')]
        for reply, status, code in replies:
            with self.subTest(status=status, code=code), patch('dns.query.udp', return_value=reply):
                result = resolvers.query_resolver('example.com', self.endpoint)
            self.assertEqual(result['status'], status)
            self.assertEqual(result['rcode'], code)
            self.assertEqual(result['addresses'], [])
        with patch('dns.query.udp', side_effect=dns.exception.Timeout):
            self.assertEqual(resolvers.query_resolver('example.com', self.endpoint)['status'], 'dns_error')

    def test_only_discovered_reference_allows_loopback_endpoint(self):
        endpoint = resolvers.parse_resolver('udp://127.3.3.3:53', allow_loopback=True)
        with self.assertRaises(resolvers.ResolverError):
            resolvers.query_resolver('example.com', endpoint)
        endpoint['role'] = 'reference'
        with patch('dns.query.udp', return_value=self.answer(('example.com', 'A', '1.1.1.1'))):
            self.assertEqual(resolvers.query_resolver('example.com', endpoint)['status'], 'ok')

    def test_cname_cycles_and_overlong_chains_are_inconclusive(self):
        cycle = self.answer(('example.com', 'CNAME', 'alias.example.'),
                            ('alias.example', 'CNAME', 'example.com.'),
                            ('example.com', 'A', '1.1.1.1'))
        chain = [('example.com', 'CNAME', 'hop0.example.')]
        chain.extend((f'hop{i}.example', 'CNAME', f'hop{i + 1}.example.')
                     for i in range(resolvers.MAX_CNAME_HOPS))
        chain.append((f'hop{resolvers.MAX_CNAME_HOPS}.example', 'A', '1.1.1.1'))
        for reply in (cycle, self.answer(*chain)):
            with patch('dns.query.udp', return_value=reply):
                result = resolvers.query_resolver('example.com', self.endpoint)
            self.assertEqual(result['status'], 'dns_error')
            self.assertEqual(result['addresses'], [])


if __name__ == '__main__':
    unittest.main()
