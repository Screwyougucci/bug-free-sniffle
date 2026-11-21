import unittest

from darthscanner.identity import finding_identity


class EvidenceIdentityTests(unittest.TestCase):
    def test_evidence_id_changes_when_response_proof_changes(self):
        base = {
            "url": "https://example.test/",
            "category": "http-headers",
            "title": "Missing CSP",
            "evidence": "CSP header missing",
            "evidence_details": {
                "request_method": "GET",
                "request_url": "https://example.test/",
                "response_status": 200,
                "response_body_sha256": "a" * 64,
                "response_headers": {"content-type": "text/html"},
            },
        }
        first = finding_identity(base)
        changed = dict(base)
        changed["evidence_details"] = dict(base["evidence_details"])
        changed["evidence_details"]["response_body_sha256"] = "b" * 64
        second = finding_identity(changed)
        self.assertEqual(first["finding_id"], second["finding_id"])
        self.assertNotEqual(first["evidence_id"], second["evidence_id"])


if __name__ == "__main__":
    unittest.main()
