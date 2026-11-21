import unittest

from darthscanner.subdomains import (
    discover_subdomain_tree,
    validate_discovery_limits,
)


class SubdomainLimitTests(unittest.TestCase):
    def test_accepts_configured_boundaries(self):
        self.assertEqual(validate_discovery_limits(1, 1), (1, 1))
        self.assertEqual(validate_discovery_limits(8, 100), (8, 100))

    def test_rejects_depth_above_hard_limit(self):
        with self.assertRaisesRegex(ValueError, "depth must be an integer from 1 to 8"):
            validate_discovery_limits(9, 25)
        with self.assertRaises(ValueError):
            validate_discovery_limits(9999999999, 25)

    def test_rejects_host_limit_above_hard_limit(self):
        with self.assertRaisesRegex(ValueError, "hosts must be an integer from 1 to 100"):
            validate_discovery_limits(5, 101)
        with self.assertRaises(ValueError):
            validate_discovery_limits(5, 29999999)

    def test_rejects_booleans_and_non_integer_values(self):
        for depth, hosts in ((True, 25), (5, False), (5.5, 25), (5, "25")):
            with self.subTest(depth=depth, hosts=hosts):
                with self.assertRaises(ValueError):
                    validate_discovery_limits(depth, hosts)

    def test_discovery_rejects_unbounded_values_before_fetching(self):
        called = []
        def fetcher(_zone, _timeout):
            called.append(True)
            return []
        with self.assertRaises(ValueError):
            discover_subdomain_tree(
                "example.com", max_depth=9999999999, limit=29999999, fetcher=fetcher
            )
        self.assertEqual(called, [])


if __name__ == "__main__":
    unittest.main()