import json
import tempfile
import unittest
from pathlib import Path

from darthscanner import subdomains
from darthscanner.scope import load_scope, ScopeError


class RecursiveSubdomainDiscoveryTests(unittest.TestCase):
    def setUp(self):
        subdomains._DISCOVERY_CACHE.clear()

    def test_discovers_multiple_nested_levels_and_parent_links(self):
        records = {
            "example.com": ["a.example.com", "not-example.com.attacker.test"],
            "a.example.com": ["b.a.example.com"],
            "b.a.example.com": ["c.b.a.example.com"],
        }
        queried = []

        def fetcher(zone, timeout):
            queried.append(zone)
            return records.get(zone, [])

        found = subdomains.discover_subdomain_tree(
            "example.com", max_depth=3, limit=10, resolver=lambda host: True,
            fetcher=fetcher, cache_ttl=0,
        )
        by_host = {item["host"]: item for item in found}
        self.assertEqual(set(by_host), {
            "a.example.com", "b.a.example.com", "c.b.a.example.com"
        })
        self.assertEqual(by_host["a.example.com"]["parent"], "example.com")
        self.assertEqual(by_host["b.a.example.com"]["parent"], "a.example.com")
        self.assertEqual(by_host["c.b.a.example.com"]["parent"], "b.a.example.com")
        self.assertEqual(by_host["c.b.a.example.com"]["depth"], 3)
        self.assertIn("b.a.example.com", queried)

    def test_depth_limit_stops_deeper_discovery(self):
        records = {
            "example.com": ["a.example.com"],
            "a.example.com": ["b.a.example.com"],
            "b.a.example.com": ["c.b.a.example.com"],
        }
        found = subdomains.discover_subdomain_tree(
            "example.com", max_depth=2, limit=10, resolver=lambda host: True,
            fetcher=lambda zone, timeout: records.get(zone, []), cache_ttl=0,
        )
        self.assertEqual([item["host"] for item in found], [
            "a.example.com", "b.a.example.com"
        ])

    def test_host_limit_is_enforced(self):
        found = subdomains.discover_subdomain_tree(
            "example.com", max_depth=4, limit=2, resolver=lambda host: True,
            fetcher=lambda zone, timeout: [
                "a.example.com", "b.example.com", "c.example.com"
            ] if zone == "example.com" else [], cache_ttl=0,
        )
        self.assertEqual(len(found), 2)

    def test_dns_failure_and_out_of_scope_names_are_rejected(self):
        found = subdomains.discover_subdomain_tree(
            "example.com", max_depth=3, limit=10,
            resolver=lambda host: host == "good.example.com",
            fetcher=lambda zone, timeout: [
                "good.example.com", "offline.example.com", "example.com.attacker.test"
            ], cache_ttl=0,
        )
        self.assertEqual([item["host"] for item in found], ["good.example.com"])

    def test_invalid_depth_and_limit_are_rejected(self):
        with self.assertRaises(ValueError):
            subdomains.discover_subdomain_tree("example.com", max_depth=9)
        with self.assertRaises(ValueError):
            subdomains.discover_subdomain_tree("example.com", limit=101)

    def test_scope_accepts_configured_discovery_bounds(self):
        payload = {
            "authorized": True,
            "allowed_hosts": ["example.com"],
            "include_subdomains": True,
            "root_domain": "example.com",
            "max_subdomain_depth": 7,
            "max_subdomain_hosts": 80,
        }
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scope.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            scope = load_scope(path)
        self.assertEqual(scope.max_subdomain_depth, 7)
        self.assertEqual(scope.max_subdomain_hosts, 80)

    def test_scope_rejects_out_of_range_discovery_bounds(self):
        payload = {
            "authorized": True,
            "allowed_hosts": ["example.com"],
            "include_subdomains": True,
            "root_domain": "example.com",
            "max_subdomain_depth": 9,
        }
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scope.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ScopeError):
                load_scope(path)


if __name__ == "__main__":
    unittest.main()
