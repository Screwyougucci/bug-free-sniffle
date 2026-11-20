import unittest

from darthscanner.browser_discovery import _query_names, _safe_url, _same_origin


class BrowserDiscoveryHelpersTests(unittest.TestCase):
    def test_redacts_query_values_and_fragment(self):
        self.assertEqual(_safe_url("https://example.test/api?q=private&token=secret#frag"),
                         "https://example.test/api")

    def test_keeps_only_non_sensitive_parameter_names(self):
        self.assertEqual(_query_names("https://example.test/?q=abc&token=secret&page=2&api_key=x"),
                         ["q", "page"])

    def test_same_origin_is_exact_scheme_host_and_port(self):
        self.assertTrue(_same_origin("https://example.test/", "https://example.test/api"))
        self.assertFalse(_same_origin("https://example.test/", "https://sub.example.test/api"))
        self.assertFalse(_same_origin("https://example.test/", "http://example.test/api"))
        self.assertFalse(_same_origin("https://example.test/", "https://example.test:8443/api"))


if __name__ == "__main__":
    unittest.main()
