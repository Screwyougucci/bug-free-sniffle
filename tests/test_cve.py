import json
import tempfile
import unittest
from pathlib import Path

from darthscanner.cve import load_inventory, load_nvd_feed, match_cves, severity_from_cvss
from darthscanner.fingerprint import fingerprint_response
from darthscanner.http_client import HttpResponse
from darthscanner.fingerprint import SoftwareComponent


class CveMatchingTests(unittest.TestCase):
    def setUp(self):
        self.component = SoftwareComponent(
            name="nginx",
            version="1.18.0",
            cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
            source="test fixture",
        )
        self.feed = [{
            "id": "CVE-2021-44228",
            "descriptions": [{"lang": "en", "value": "Example test description."}],
            "metrics": {
                "cvssMetricV31": [{
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    }
                }]
            },
            "configurations": [{
                "nodes": [{
                    "operator": "OR",
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                        "versionEndExcluding": "1.20.0"
                    }]
                }]
            }],
            "references": [{"url": "https://example.test/advisory"}]
        }]

    def test_cvss_score_maps_to_standard_severity(self):
        self.assertEqual(severity_from_cvss(9.8), "critical")
        self.assertEqual(severity_from_cvss(8.1), "high")
        self.assertEqual(severity_from_cvss(6.5), "medium")
        self.assertEqual(severity_from_cvss(3.9), "low")
        self.assertEqual(severity_from_cvss(None), "info")

    def test_nvd_cpe_range_generates_detailed_candidate(self):
        findings = match_cves([self.component], self.feed)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.cve_ids, ["CVE-2021-44228"])
        self.assertEqual(finding.cvss_score, 9.8)
        self.assertEqual(finding.cvss_version, "3.1")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.kind, "candidate-vulnerability")
        self.assertIn("versionEndExcluding=1.20.0", finding.evidence)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2021-44228", finding.references)
        self.assertIn("vendor backports", finding.remediation.lower())

    def test_nonmatching_product_is_not_reported(self):
        other = SoftwareComponent(
            name="Apache",
            version="2.4.0",
            cpe="cpe:2.3:a:apache:http_server:2.4.0:*:*:*:*:*:*:*",
            source="test fixture",
        )
        self.assertEqual(match_cves([other], self.feed), [])

    def test_inventory_loader_accepts_cpe_23(self):
        payload = {"components": [{
            "name": "nginx",
            "version": "1.18.0",
            "cpe": self.component.cpe
        }]}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "inventory.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_inventory(path)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].cpe, self.component.cpe)

    def test_nvd_loader_requires_vulnerabilities_array(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "nvd.json"
            path.write_text(json.dumps({"vulnerabilities": [{"cve": self.feed[0]}]}), encoding="utf-8")
            self.assertEqual(len(load_nvd_feed(path)), 1)

    def test_version_at_exclusive_end_is_not_matched(self):
        newer = SoftwareComponent(
            name="nginx",
            version="1.20.0",
            cpe="cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*",
            source="test fixture",
        )
        self.assertEqual(match_cves([newer], self.feed), [])


class FingerprintTests(unittest.TestCase):
    def test_server_headers_produce_cpe_inventory(self):
        response = HttpResponse(
            "https://owned.example/",
            200,
            {"server": "nginx/1.18.0", "x-powered-by": "PHP/8.1.2"},
            b"",
            0.1,
        )
        components = fingerprint_response(response)
        cpes = {component.cpe for component in components}
        self.assertIn("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", cpes)
        self.assertIn("cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*", cpes)


if __name__ == "__main__":
    unittest.main()
