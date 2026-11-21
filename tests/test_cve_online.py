import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from darthscanner.cve_online import lookup_cves_for_components
from darthscanner.fingerprint import SoftwareComponent


class OnlineCveCacheTests(unittest.TestCase):
    def setUp(self):
        self.component = SoftwareComponent(
            name="nginx",
            version="1.18.0",
            cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
            source="Server header",
            confidence="medium",
            source_url="https://owned.example/",
        )

    def test_nvd_result_is_cached_for_next_watch_cycle(self):
        with tempfile.TemporaryDirectory() as folder:
            cache = Path(folder) / "nvd-cache.json"
            with patch("darthscanner.cve_online._fetch_nvd", return_value=[]) as fetch:
                first, first_status = lookup_cves_for_components(
                    [self.component], cache_path=cache, max_network_lookups=1
                )
                second, second_status = lookup_cves_for_components(
                    [self.component], cache_path=cache, max_network_lookups=1
                )
            self.assertEqual(first, [])
            self.assertEqual(second, [])
            self.assertEqual(fetch.call_count, 1)
            self.assertEqual(first_status["network_lookups"], 1)
            self.assertEqual(second_status["cache_hits"], 1)

    def test_lookup_status_reports_deferred_components(self):
        other = SoftwareComponent(
            name="PHP", version="8.1.2",
            cpe="cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*",
            source="X-Powered-By",
            source_url="https://owned.example/",
        )
        with tempfile.TemporaryDirectory() as folder:
            with patch("darthscanner.cve_online._fetch_nvd", return_value=[]):
                _, status = lookup_cves_for_components(
                    [self.component, other],
                    cache_path=Path(folder) / "cache.json",
                    max_network_lookups=1,
                )
        self.assertEqual(status["components_checked"], 1)
        self.assertEqual(status["components_deferred"], 1)


if __name__ == "__main__":
    unittest.main()
