import unittest

from darthscanner.api_discovery import discover_static_get_targets
from darthscanner.scope import Scope


class StaticApiDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(True, ("example.test",), max_requests=20)

    def test_finds_literal_fetch_get_and_axios_get_routes(self):
        source = """
        fetch('/api/search?q=hello&page=1');
        axios.get("https://example.test/api/items?category=books");
        """
        results = discover_static_get_targets("https://example.test/assets/app.js", source, self.scope)
        self.assertEqual(
            [item["url"] for item in results],
            ["https://example.test/api/search?q=hello&page=1",
             "https://example.test/api/items?category=books"],
        )
        self.assertEqual(results[0]["parameters"], ["q", "page"])

    def test_finds_xhr_explicit_get(self):
        results = discover_static_get_targets(
            "https://example.test/app.js",
            """xhr.open('GET', '/api/profile?view=compact');""",
            self.scope,
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["parameters"], ["view"])

    def test_ignores_external_and_sensitive_routes(self):
        source = """
        fetch('https://other.test/api?q=x');
        axios.get('/api/account?access_token=abc');
        """
        self.assertEqual(
            discover_static_get_targets("https://example.test/app.js", source, self.scope),
            [],
        )

    def test_does_not_discover_non_get_or_dynamic_urls(self):
        source = """
        fetch('/api/write?name=x', {method: 'POST'});
        axios.post('/api/write?name=x');
        fetch(apiBase + '/api/search?q=x');
        """
        self.assertEqual(
            discover_static_get_targets("https://example.test/app.js", source, self.scope),
            [],
        )

    def test_target_limit_is_enforced(self):
        source = " ".join(f"axios.get('/api/{i}?q=x');" for i in range(5))
        results = discover_static_get_targets(
            "https://example.test/app.js", source, self.scope, max_targets=2
        )
        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
