import unittest

from darthscanner.browser_discovery import (
    _query_names, _route_event_edges, _safe_url, _same_origin,
)


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

    def test_client_route_edges_keep_same_origin_paths_and_redact_query_values(self):
        edges = _route_event_edges([
            {"type": "pushState", "from": "https://example.test/home?user=alice",
             "to": "https://example.test/dashboard?token=secret&tab=security"},
            {"type": "pushState", "from": "https://example.test/dashboard",
             "to": "https://evil.test/steal"},
        ], "https://example.test/")
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["source_route"], "https://example.test/home")
        self.assertEqual(edges[0]["destination_route"], "https://example.test/dashboard")
        self.assertEqual(edges[0]["relationship"], "client-history-pushState")

    def test_client_route_edges_ignore_invalid_or_incomplete_events(self):
        edges = _route_event_edges([
            {"type": "popstate", "from": "https://example.test/a",
             "to": "javascript:alert(1)"},
            {"type": "hashchange", "to": "https://example.test/b"},
            {"type": "replaceState", "from": "https://example.test/a",
             "to": "https://example.test/a?private=value"},
        ], "https://example.test/")
        self.assertEqual(edges, [])


if __name__ == "__main__":
    unittest.main()
