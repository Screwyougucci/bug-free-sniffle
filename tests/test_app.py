import unittest

from darthscanner.app_utils import parse_target_url


class AppTargetTests(unittest.TestCase):
    def test_adds_https_when_scheme_is_missing(self):
        self.assertEqual(parse_target_url("example.test/path"),
                         ("https://example.test/path", "example.test"))

    def test_repairs_scheme_missing_slashes(self):
        self.assertEqual(parse_target_url("https/example.com"),
                         ("https://example.com/", "example.com"))
        self.assertEqual(parse_target_url("https:/example.com"),
                         ("https://example.com/", "example.com"))

    def test_repairs_duplicate_protocol_prefix_from_gui(self):
        self.assertEqual(parse_target_url("https://https/example.com"),
                         ("https://example.com/", "example.com"))
        self.assertEqual(parse_target_url("https://https/apple.com"),
                         ("https://apple.com/", "apple.com"))

    def test_preserves_port_and_path_but_drops_query(self):
        self.assertEqual(parse_target_url("http://localhost:8080/check?q=1"),
                         ("http://localhost:8080/check", "localhost"))

    def test_drops_query_string_to_avoid_persisting_tokens(self):
        self.assertEqual(parse_target_url("https://example.test/path?token=secret#part"),
                         ("https://example.test/path", "example.test"))

    def test_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            parse_target_url("ftp://example.test/file")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            parse_target_url("https://user:pass@example.test/")

    def test_rejects_empty_target(self):
        with self.assertRaises(ValueError):
            parse_target_url("  ")

    def test_rejects_spaces(self):
        with self.assertRaises(ValueError):
            parse_target_url("https://example .com")


if __name__ == "__main__":
    unittest.main()