import unittest

from darthscanner.discovery import discover_query_targets
from darthscanner.http_client import HttpResponse
from darthscanner.scope import Scope


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(True, ("owned.example",), max_pages=10, max_requests=50)

    def test_discovers_same_origin_query_links(self):
        page = HttpResponse(
            "https://owned.example/", 200, {"content-type": "text/html"},
            b'<a href="/search?q=hello&page=1">Search</a>'
            b'<a href="https://elsewhere.example/?q=no">External</a>',
            0.01,
        )
        found = discover_query_targets([page], self.scope)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["parameters"], ["q", "page"])
        self.assertEqual(found[0]["url"], "https://owned.example/search?q=hello&page=1")

    def test_sensitive_query_keys_are_skipped(self):
        page = HttpResponse(
            "https://owned.example/", 200, {"content-type": "text/html"},
            b'<a href="/private?access_token=secret">Private</a>'
            b'<a href="/search?q=hello">Search</a>', 0.01,
        )
        found = discover_query_targets([page], self.scope)
        self.assertEqual(len(found), 1)
        self.assertIn("/search?", found[0]["url"])

    def test_current_page_query_is_discovered(self):
        page = HttpResponse(
            "https://owned.example/items?id=7", 200,
            {"content-type": "application/json"}, b'{"id":7}', 0.01,
        )
        found = discover_query_targets([page], self.scope)
        self.assertEqual(found[0]["parameters"], ["id"])

    def test_out_of_scope_links_are_ignored(self):
        page = HttpResponse(
            "https://owned.example/", 200, {"content-type": "text/html"},
            b'<a href="https://other.example/?q=x">Other</a>', 0.01,
        )
        self.assertEqual(discover_query_targets([page], self.scope), [])

    def test_target_limit_is_enforced(self):
        page = HttpResponse(
            "https://owned.example/", 200, {"content-type": "text/html"},
            b'<a href="/a?q=1">A</a><a href="/b?q=2">B</a>', 0.01,
        )
        self.assertEqual(len(discover_query_targets([page], self.scope, 1)), 1)


if __name__ == "__main__":
    unittest.main()
