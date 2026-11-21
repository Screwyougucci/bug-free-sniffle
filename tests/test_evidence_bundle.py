import unittest
from types import SimpleNamespace

from darthscanner.checks import _http_evidence, inspect_http


class EvidenceBundleTests(unittest.TestCase):
    def response(self):
        body = b"<html><body>safe test page</body></html>"
        return SimpleNamespace(
            url="https://example.test/account?session=secret-value&view=profile",
            status=200,
            headers={
                "content-type": "text/html; charset=utf-8",
                "content-security-policy": "default-src 'self'",
                "set-cookie": "session=private-cookie",
                "authorization": "Bearer private-token",
            },
            body=body,
            elapsed_seconds=0.125,
            text=body.decode("utf-8"),
        )

    def test_evidence_redacts_secret_query_and_excludes_sensitive_headers(self):
        details, steps = _http_evidence(self.response())
        self.assertIn("session=%5BREDACTED%5D", details["request_url"])
        self.assertNotIn("secret-value", details["request_url"])
        self.assertNotIn("set-cookie", details["response_headers"])
        self.assertNotIn("authorization", details["response_headers"])
        self.assertFalse(details["body_saved"])
        self.assertEqual(len(details["response_body_sha256"]), 64)
        self.assertTrue(any("GET" in step for step in steps))

    def test_findings_include_repeatable_evidence(self):
        findings = inspect_http(self.response())
        self.assertTrue(findings)
        for finding in findings:
            payload = finding.to_dict()
            self.assertEqual(payload["evidence_details"]["response_status"], 200)
            self.assertTrue(payload["reproduction_steps"])
            self.assertFalse(payload["evidence_details"]["body_saved"])


if __name__ == "__main__":
    unittest.main()
