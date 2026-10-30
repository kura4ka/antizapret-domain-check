"""Domain collection must include user lists and respect native WARP rules."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from azcheck.domains import DomainError, load_inventory, normalize_domain


class NormalizeDomainTests(unittest.TestCase):
    def test_domains_urls_idna_and_trailing_dot(self):
        cases = {
            " Example.COM. ": "example.com",
            "https://EXAMPLE.com:443/a?b=c#fragment": "example.com",
            "http://Example.com:80/path": "example.com",
            "пример.рф": "xn--e1afmkfd.xn--p1ai",
            "HTTPS://пример.рф/path": "xn--e1afmkfd.xn--p1ai",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(normalize_domain(value), expected)

    def test_malformed_names_credentials_ports_and_ips_are_rejected(self):
        cases = (
            "", "localhost", "com", "*.example.com", "https://*.example.com",
            "127.0.0.1", "001.002.003.004", "https://[::1]/", "https://1.1.1.1/",
            "https://user:secret@example.com/", "https://@example.com/",
            "https://example.com:80", "http://example.com:443", "https://example.com:8080",
            "example.com:443", "ftp://example.com/", "//example.com", "example.com/path",
            "a..example.com", ".example.com", "-name.example", "name_.example",
            "example.com..", "one.123", "hello world.example", "example.com\x00",
            "https://example.com/a b", "a" * 64 + ".example",
        )
        for value in cases:
            with self.subTest(value=value), self.assertRaises(DomainError):
                normalize_domain(value)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.az = self.root / "antizapret"
        (self.az / "config").mkdir(parents=True)
        (self.az / "download").mkdir()

    def write(self, name, text):
        path = self.az / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_all_native_include_globs_and_user_sources_are_merged(self):
        primary = self.write("config/include-hosts.txt", "# own\nEXAMPLE.com\n")
        self.write("config/custom-include-hosts.txt", "custom.example\n")
        self.write("config/include-warp-hosts.txt", "warp.example\n")
        self.write("config/relay-include-warp-hosts.txt", "relay.example\n")
        self.write("config/exclude-hosts.txt", "not-a-candidate.example\n")
        self.write("config/exclude-warp-hosts.txt", "also-not-a-candidate.example\n")
        self.write("config/include-adblock-hosts.txt", "adblock-not-a-candidate.example\n")
        self.write("download/include-hosts.txt", "downloaded.example\n")
        self.write("download/include-warp-hosts.txt", "default-warp.example\n")
        user = self.root / "users.txt"
        user.write_text("# users\nhttps://Example.com/a # duplicate\nUSER.example\n", encoding="utf-8")
        inventory = load_inventory(self.az, [user], ["extra.example", "example.com"])
        entries = {entry.domain: entry for entry in inventory.entries}
        self.assertEqual(list(entries), ["custom.example", "default-warp.example", "downloaded.example", "example.com", "extra.example", "relay.example", "user.example", "warp.example"])
        self.assertEqual(entries["example.com"].sources, sorted([
            f"{primary.as_posix()}:2", f"{user.as_posix()}:2", "--domain:2",
        ]))
        self.assertTrue(entries["relay.example"].included)
        self.assertFalse(entries["custom.example"].included)
        self.assertTrue(any('source lists' in warning for warning in inventory.warnings))

    def test_downloaded_domains_are_default_and_can_be_omitted_as_raw_expansion(self):
        self.write("download/include-hosts.txt", "blocked.example\n")
        self.write("download/custom-include-hosts.txt", "other.example\n")
        self.write("download/include-warp-hosts.txt", "default.example\n")
        self.write("download/custom-include-warp-hosts.txt", "other-warp.example\n")
        without = load_inventory(self.az, [], ["child.default.example"], include_download=False)
        self.assertEqual([entry.domain for entry in without.entries], ["child.default.example"])
        self.assertTrue(without.entries[0].included)
        with_download = load_inventory(self.az, [], [], include_download=True)
        self.assertEqual([entry.domain for entry in with_download.entries], [
            "blocked.example", "default.example", "other-warp.example", "other.example",
        ])

    def test_suffix_boundary_and_exclusion_precedence(self):
        self.write("config/include-warp-hosts.txt", "example.com\n")
        self.write("config/custom-exclude-warp-hosts.txt", "private.example.com\n")
        inventory = load_inventory(self.az, [], [
            "www.example.com", "deep.private.example.com", "notexample.com", "example.com.evil.org",
        ])
        entries = {entry.domain: entry for entry in inventory.entries}
        self.assertTrue(entries["www.example.com"].included)
        self.assertTrue(entries["deep.private.example.com"].included)
        self.assertTrue(entries["deep.private.example.com"].excluded)
        self.assertFalse(entries["notexample.com"].included)
        self.assertFalse(entries["example.com.evil.org"].included)
        self.assertFalse(entries["www.example.com"].excluded)

    def test_native_comments_punctuation_whitespace_and_invalid_lines(self):
        path = self.write("config/include-hosts.txt", (
            "# comment\n! ignored\n\n EXAMPLE.com # comment\nspace .example\n"
            "path.example/unused\nпример.рф\n.\nhttps://url.example/\nbad..example\n"
        ))
        inventory = load_inventory(self.az, [], [])
        self.assertEqual([entry.domain for entry in inventory.entries], [
            "example.com", "path.example", "space.example", "xn--e1afmkfd.xn--p1ai",
        ])
        self.assertEqual(sum('skipped invalid' in warning for warning in inventory.warnings), 2)
        self.assertTrue(any(f"{path.as_posix()}:8" in warning and "catch-all" in warning for warning in inventory.warnings))

    def test_native_tld_rules_classify_children_without_becoming_probe_targets(self):
        self.write("config/include-hosts.txt", "example.com\nsub.example.com\nelsewhere.net\nCOM\n")
        self.write("download/include-warp-hosts.txt", "com\nрф\n")
        self.write("config/exclude-warp-hosts.txt", "com\n")
        inventory = load_inventory(self.az, [], ["пример.рф", "example.com.evil.net"])
        entries = {entry.domain: entry for entry in inventory.entries}
        self.assertNotIn("com", entries)
        self.assertNotIn("xn--p1ai", entries)
        self.assertTrue(entries["example.com"].included)
        self.assertTrue(entries["example.com"].excluded)
        self.assertTrue(entries["sub.example.com"].included)
        self.assertTrue(entries["sub.example.com"].excluded)
        self.assertTrue(entries["xn--e1afmkfd.xn--p1ai"].included)
        self.assertFalse(entries["xn--e1afmkfd.xn--p1ai"].excluded)
        self.assertFalse(entries["elsewhere.net"].included)
        self.assertFalse(entries["example.com.evil.net"].excluded)
        self.assertTrue(any("suffix rule 'com'" in warning for warning in inventory.warnings))

    def test_native_tld_include_rules_do_not_allow_single_label_user_submissions(self):
        self.write("config/include-warp-hosts.txt", "com\n")
        inventory = load_inventory(self.az, [], ["website.com"])
        self.assertEqual([entry.domain for entry in inventory.entries], ["website.com"])
        self.assertTrue(inventory.entries[0].included)
        with self.assertRaises(DomainError):
            load_inventory(self.az, [], ["com"])

    def test_warp_catchall_classifies_domains_but_is_not_a_probe_candidate(self):
        self.write("config/include-warp-hosts.txt", ".\n")
        self.write("config/exclude-warp-hosts.txt", "direct.example\n")
        inventory = load_inventory(self.az, [], ["hello.example", "direct.example"])
        self.assertEqual(len(inventory.entries), 2)
        self.assertTrue(all(entry.included for entry in inventory.entries))
        self.assertTrue(inventory.entries[0].excluded)
        self.assertTrue(any('catch-all' in warning for warning in inventory.warnings))

    def test_user_bom_comments_url_fragments_and_duplicate_files(self):
        user = self.root / "users.txt"
        user.write_bytes("\ufeff# user list\r\nhttps://EXAMPLE.com/a#fragment\r\nпример.рф # note\r\n".encode("utf-8"))
        inventory = load_inventory(self.az, [user, user], [])
        self.assertEqual([entry.domain for entry in inventory.entries], ["example.com", "xn--e1afmkfd.xn--p1ai"])
        self.assertEqual(inventory.entries[0].sources, [f"{user.as_posix()}:2"])

    def test_missing_invalid_and_oversized_user_files_fail_explicitly(self):
        with self.assertRaises(DomainError):
            load_inventory(self.az, [self.root / "missing.txt"], [])
        user = self.root / "users.txt"
        user.write_text("valid.example\nhttps://user:secret@example.com\n", encoding="utf-8")
        with self.assertRaises(DomainError) as error:
            load_inventory(self.az, [user], [])
        self.assertIn(":2", str(error.exception))
        self.assertNotIn("secret", str(error.exception))
        user.write_bytes(b"example.com\n")
        with patch("azcheck.domains.MAX_FILE_BYTES", 5), self.assertRaises(DomainError):
            load_inventory(self.az, [user], [])

    def test_unknown_native_encoding_and_nul_fail_instead_of_silently_omitting_domains(self):
        path = self.az / "config/include-hosts.txt"
        for contents in (b"example.com\x00\n", b"\xff\xfe"):
            with self.subTest(contents=contents):
                path.write_bytes(contents)
                with self.assertRaises(DomainError):
                    load_inventory(self.az, [], [])

    def test_missing_antizapret_still_supports_explicit_domains_with_warning(self):
        inventory = load_inventory(self.root / "not-installed", [], ["example.com"])
        self.assertEqual([entry.domain for entry in inventory.entries], ["example.com"])
        self.assertEqual(len(inventory.warnings), 1)

    def test_effective_lists_expand_registry_subdomains_and_filter_unrouted_names(self):
        self.write('result/include-hosts.txt', 'example.com\n')
        self.write('result/include-warp-hosts.txt', 'warp.example\n')
        self.write('result/exclude-hosts.txt', 'direct.example.com\n')
        self.write('config/remove-hosts.txt', 'removed.example.com\n')
        registry = self.write('download/bol-van-domain.txt', (
            'www.example.com\ndeep.example.com\ndirect.example.com\n'
            'removed.example.com\nunrouted.example\nchild.warp.example\n'
        ))
        self.write('download/antifilter-download-domain.txt', 'other.example.com\n')
        self.write('config/include-hosts.txt', 'new-user.example\n')
        inventory = load_inventory(self.az, [], [])
        entries = {entry.domain: entry for entry in inventory.entries}
        self.assertEqual(set(entries), {'example.com', 'warp.example', 'www.example.com',
                                       'deep.example.com', 'child.warp.example',
                                       'other.example.com', 'new-user.example'})
        self.assertTrue(entries['child.warp.example'].included)
        self.assertIn(f'{registry.as_posix()}:1', entries['www.example.com'].sources)
        self.assertEqual(inventory.metadata['coverage'], 'parsed-and-source')
        self.assertEqual(inventory.metadata['downloaded_entries_omitted'], 3)

    def test_no_raw_download_option_still_keeps_effective_routing_inventory(self):
        self.write('result/include-hosts.txt', 'effective.example\n')
        self.write('result/include-warp-hosts.txt', 'warp.example\n')
        self.write('download/bol-van-domain.txt', 'sub.effective.example\n')
        self.write('download/include-hosts.txt', 'raw.example\n')
        inventory = load_inventory(self.az, [], [], include_download=False)
        self.assertEqual([entry.domain for entry in inventory.entries], ['effective.example', 'warp.example'])
        self.assertEqual(inventory.metadata['registry_files'], [])

    def test_source_fallback_registry_respects_removals_and_exclusions(self):
        self.write('download/bol-van-domain.txt', 'keep.example\nremoved.example\nchild.direct.example\n')
        self.write('download/remove-hosts.txt', 'removed.example\n')
        self.write('config/exclude-hosts.txt', 'direct.example\n')
        self.write('config/include-hosts.txt', 'new.example\n')
        inventory = load_inventory(self.az, [], [])
        self.assertEqual([entry.domain for entry in inventory.entries], ['keep.example', 'new.example'])
        self.assertEqual(inventory.metadata['coverage'], 'source-fallback')
        self.assertTrue(any('source lists' in warning for warning in inventory.warnings))

    def test_registry_punctuation_and_idna_follow_download_domain_syntax(self):
        self.write('download/antifilter-download-domain.txt', (
            '"Example.COM"\n*.пример.рф.\nhttps://ignored.example/path\n'
            'not a domain.example\n127.0.0.1\n'
        ))
        inventory = load_inventory(self.az, [], [])
        self.assertEqual([entry.domain for entry in inventory.entries], ['example.com', 'xn--e1afmkfd.xn--p1ai'])
        self.assertTrue(any('invalid registry' in warning for warning in inventory.warnings))

    def test_custom_and_effective_rpz_routes_include_literals_and_expand_wildcards(self):
        self.write('result/include-hosts.txt', '')
        self.write('result/include-warp-hosts.txt', '')
        self.write('result/proxy.rpz', ('$TTL 86400\n@ SOA . . (1 1 1 1 86400)\n'
                                        'literal.example CNAME .\n*.wild.example CNAME .\n'
                                        'direct.wild.example CNAME rpz-passthru.\n'))
        self.write('config/custom-proxy-rpz.txt', 'new-policy.example 60 IN CNAME .\n')
        self.write('config/warp-rpz.txt', ('api.example CNAME .\n*.warp.example CNAME .\n'
                                         'direct.warp.example CNAME rpz-passthru.\n'))
        self.write('download/bol-van-domain.txt', ('child.wild.example\ndirect.wild.example\n'
                                                  'wild.example\nchild.warp.example\n'))
        inventory = load_inventory(self.az, [], ['direct.warp.example'])
        entries = {entry.domain: entry for entry in inventory.entries}
        self.assertEqual(set(entries), {'literal.example', 'new-policy.example', 'api.example',
                                       'child.wild.example', 'child.warp.example', 'direct.warp.example'})
        self.assertTrue(entries['api.example'].included)
        self.assertTrue(entries['child.warp.example'].included)
        self.assertTrue(entries['direct.warp.example'].excluded)
        self.assertNotIn('wild.example', entries)
        self.assertNotIn('warp.example', entries)

    def test_rpz_origin_and_unsupported_records_are_explicit(self):
        path = self.write('config/proxy-rpz.txt', ('$ORIGIN example.com.\n'
                                                  'login IN CNAME .\n*.assets CNAME .\n'
                                                  'bad A 127.0.0.1\n32.4.3.2.1.rpz-ip CNAME .\n'))
        inventory = load_inventory(self.az, [], [])
        self.assertEqual([entry.domain for entry in inventory.entries], ['login.example.com'])
        self.assertTrue(any(path.as_posix() in warning and '2 unsupported RPZ' in warning for warning in inventory.warnings))

    def test_catchall_rpz_and_cidr_routes_warn_about_finite_inventory(self):
        self.write('result/include-hosts.txt', '')
        self.write('result/include-warp-hosts.txt', '')
        self.write('result/proxy.rpz', '*. CNAME .\n')
        self.write('result/route-ips.txt', '93.184.215.0/24\n')
        self.write('download/bol-van-domain.txt', 'known.example\n')
        inventory = load_inventory(self.az, [], [])
        self.assertEqual([entry.domain for entry in inventory.entries], ['known.example'])
        self.assertTrue(any('Catch-all routing' in warning for warning in inventory.warnings))
        self.assertTrue(any('IP/CIDR' in warning for warning in inventory.warnings))

    def test_adblock_and_deny_policies_are_not_route_inputs(self):
        self.write('download/oisd-include-adblock-hosts.txt', 'adblock.example\n')
        self.write('result/include-adblock-hosts.txt', 'result-adblock.example\n')
        self.write('config/deny-rpz.txt', 'denied.example CNAME .\n')
        self.write('result/deny.rpz', 'result-denied.example CNAME .\n')
        inventory = load_inventory(self.az, [], ['check.example'])
        self.assertEqual([entry.domain for entry in inventory.entries], ['check.example'])

    def test_effective_rpz_more_specific_routes_override_parent_passthru(self):
        self.write('result/include-hosts.txt', '')
        self.write('result/include-warp-hosts.txt', '')
        self.write('result/proxy.rpz', (
            '*.example CNAME rpz-passthru.\n'
            '*.routed.example CNAME .\n'
            'direct.routed.example CNAME rpz-passthru.\n'
            '*.direct.routed.example CNAME .\n'
        ))
        self.write('download/bol-van-domain.txt', (
            'child.routed.example\ndirect.routed.example\n'
            'deep.direct.routed.example\nother.example\n'
        ))
        inventory = load_inventory(self.az, [], [])
        self.assertEqual([entry.domain for entry in inventory.entries], [
            'child.routed.example', 'deep.direct.routed.example',
        ])

    def test_parsed_warp_does_not_claim_unparsed_download_rules_are_active(self):
        self.write('result/include-hosts.txt', 'normal.example\n')
        self.write('result/include-warp-hosts.txt', 'active.example\n')
        self.write('download/include-warp-hosts.txt', 'pending.example\nactive.example\n')
        self.write('config/include-warp-hosts.txt', 'user-pending.example\n')
        inventory = load_inventory(self.az, [], ['pending.example'])
        entries = {entry.domain: entry for entry in inventory.entries}
        self.assertFalse(entries['pending.example'].included)
        self.assertTrue(entries['active.example'].included)
        self.assertTrue(entries['user-pending.example'].included)
        self.assertEqual(entries['pending.example'].sources, ['--domain:1'])
        self.assertEqual(inventory.metadata['downloaded_entries_omitted'], 1)

    def test_parsed_rpz_without_host_files_still_filters_unparsed_sources(self):
        self.write('result/proxy.rpz', '*.active.example CNAME .\n')
        self.write('result/warp.rpz', 'warp.example CNAME .\n')
        self.write('download/include-hosts.txt', 'unparsed.example\n')
        self.write('download/include-warp-hosts.txt', 'unparsed-warp.example\n')
        self.write('download/bol-van-domain.txt', 'child.active.example\nunrouted.example\n')
        inventory = load_inventory(self.az, [], [])
        self.assertEqual([entry.domain for entry in inventory.entries], ['child.active.example', 'warp.example'])
        self.assertEqual(inventory.metadata['coverage'], 'parsed-and-source')


if __name__ == "__main__":
    unittest.main()
