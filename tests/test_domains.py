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
        self.assertEqual(list(entries), ["custom.example", "example.com", "extra.example", "relay.example", "user.example", "warp.example"])
        self.assertEqual(entries["example.com"].sources, sorted([
            f"{primary.as_posix()}:2", f"{user.as_posix()}:2", "--domain:2",
        ]))
        self.assertTrue(entries["relay.example"].included)
        self.assertFalse(entries["custom.example"].included)
        self.assertEqual(inventory.warnings, [])

    def test_downloaded_domains_are_opt_in_but_always_classify_warp(self):
        self.write("download/include-hosts.txt", "blocked.example\n")
        self.write("download/custom-include-hosts.txt", "other.example\n")
        self.write("download/include-warp-hosts.txt", "default.example\n")
        self.write("download/custom-include-warp-hosts.txt", "other-warp.example\n")
        without = load_inventory(self.az, [], ["child.default.example"])
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
        self.assertEqual(len(inventory.warnings), 3)
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
        self.assertEqual(len(inventory.warnings), 1)
        self.assertIn("suffix rule 'com'", inventory.warnings[0])

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
        self.assertEqual(len(inventory.warnings), 1)

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


if __name__ == "__main__":
    unittest.main()
