import unittest

from darthscanner.evidence import build_reproduction_evidence, redact_url


class EvidenceTests(unittest.TestCase):
    def test_redacts_secret_query_values(self):
        self.assertEqual(
            redact_url("https://example.test/item?id=7&access_token=supersecret"),
            "https://example.test/item?id=7&access_token=%5BREDACTED%5D",
        )

    def test_builds_benign_replay_evidence(self):
        result = build_reproduction_evidence([{
            "endpoint_url": "https://example.test/search?q=hello",
            "parameter": "q",
            "case": "empty",
            "baseline_status": 200,
            "baseline_sha256": "base-hash",
            "status": 500,
            "response_bytes": 123,
            "response_sha256": "response-hash",
            "content_type": "application/json",
            "elapsed_seconds": 0.25,
            "anomaly_score": 65,
        }])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["method"], "GET")
        self.assertEqual(result[0]["baseline"]["response_sha256"], "base-hash")
        self.assertIn('--case "empty"', result[0]["reproduction_command"])
        self.assertFalse(result[0]["source_location"]["available"])

    def test_redacts_sensitive_parameter_mutation(self):
        result = build_reproduction_evidence([{
            "endpoint_url": "https://example.test/api?api_key=secret",
            "parameter": "api_key",
            "case": "empty",
            "mutation_value": "secret",
        }])[0]
        self.assertEqual(result["mutation_value"], "[REDACTED]")
        self.assertNotIn("secret", result["endpoint_url"])


if __name__ == "__main__":
    unittest.main()
