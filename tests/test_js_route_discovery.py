import unittest

from darthscanner.js_route_discovery import discover_static_get_routes
from darthscanner.scope import Scope


class JavaScriptRouteDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(True, ("example.test",), max_requests=30)

    def test_discovers_queryless_fetch_and_axios_routes(self):
        source = """
        fetch('/api/profile');
        axios.get('/api/items?category=books&page=2');
        """
        routes = discover_static_get_routes(
            "https://example.test/assets/app.js", source, self.scope
        )
        self.assertEqual(
            [item["endpoint"] for item in routes],
            ["https://example.test/api/profile", "https://example.test/api/items"],
        )
        self.assertEqual(routes[0]["parameters"], [])
        self.assertEqual(routes[1]["parameters"], ["category", "page"])
        self.assertEqual(routes[1]["client_api"], "axios.get")

    def test_discovers_explicit_xhr_get_and_records_line(self):
        routes = discover_static_get_routes(
            "https://example.test/app.js",
            "\n xhr.open('GET', '/api/account?view=compact');",
            self.scope,
        )
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0]["client_api"], "xhr.open")
        self.assertEqual(routes[0]["source_line"], 2)

    def test_query_values_are_not_retained(self):
        routes = discover_static_get_routes(
            "https://example.test/app.js",
            "fetch('/api/search?q=private-value&page=4');",
            self.scope,
        )
        self.assertEqual(routes[0]["endpoint"], "https://example.test/api/search")
        self.assertEqual(routes[0]["parameters"], ["q", "page"])
        self.assertNotIn("private-value", str(routes))
        self.assertNotIn("page=4", str(routes))

    def test_ignores_external_sensitive_and_non_get_calls(self):
        source = """
        fetch('https://other.test/api/data');
        fetch('/api/profile?access_token=secret');
        fetch('/api/write', {method: 'POST'});
        axios.post('/api/write');
        fetch(apiBase + '/api/dynamic');
        """
        self.assertEqual(
            discover_static_get_routes("https://example.test/app.js", source, self.scope),
            [],
        )

    def test_deduplicates_and_enforces_limit(self):
        source = "\n".join(
            [f"axios.get('/api/{i}');" for i in range(4)]
            + ["fetch('/api/0');"]
        )
        routes = discover_static_get_routes(
            "https://example.test/app.js", source, self.scope, max_routes=2
        )
        self.assertEqual(len(routes), 2)
        self.assertEqual(len({item["endpoint"] for item in routes}), 2)

    def test_rejects_invalid_limit(self):
        with self.assertRaises(ValueError):
            discover_static_get_routes(
                "https://example.test/app.js", "fetch('/api/x')", self.scope, 101
            )


if __name__ == "__main__":
    unittest.main()
