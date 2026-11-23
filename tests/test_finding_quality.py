import unittest

from darthscanner.checks import Finding, inspect_http
from darthscanner.http_client import HttpResponse
from darthscanner.report import build_report


class FindingQualityTests(unittest.TestCase):
    def test_missing_security_headers_are_hardening_only(self):
        response = HttpResponse(
            "https://owned.example/",
            200,
            {"content-type": "text/html"},
            b"<html><body>hello</body></html>",
            0.1,
        )
        findings = inspect_http(response)
        self.assertTrue(findings)
        for finding in findings:
            if finding.category in {"http-headers", "csp", "cors", "information", "cookies", "cache"}:
                self.assertEqual(finding.kind, "hardening-observation")
                self.assertEqual(finding.severity, "info")
                self.assertIsNone(finding.cvss_score)

    def test_plaintext_basic_auth_remains_actionable(self):
        response = HttpResponse(
            "http://owned.example/admin",
            401,
            {"www-authenticate": 'Basic realm="admin"'},
            b"",
            0.1,
        )
        findings = inspect_http(response)
        finding = next(item for item in findings if item.category == "authentication")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.kind, "finding")

    def test_report_separates_candidates_from_hardening(self):
        hardening = Finding(
            category="http-headers", title="Missing CSP", severity="info",
            confidence="high", url="https://owned.example/",
            evidence="No CSP header.", remediation="Add CSP.",
            kind="hardening-observation",
        )
        candidate = Finding(
            category="authentication", title="Basic auth over HTTP",
            severity="high", confidence="high", url="http://owned.example/admin",
            evidence="Basic challenge over plaintext.", remediation="Require TLS.",
        )
        report = build_report(
            target="https://owned.example/",
            requests_made=1,
            pages=[],
            findings=[hardening, candidate],
        )
        coverage = report["coverage"]
        self.assertEqual(coverage["findings_total"], 2)
        self.assertEqual(coverage["actionable_candidates"], 1)
        self.assertEqual(coverage["hardening_observations"], 1)
        self.assertEqual(coverage["confirmed_vulnerabilities"], 0)


if __name__ == "__main__":
    unittest.main()
