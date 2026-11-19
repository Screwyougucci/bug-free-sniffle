import unittest

from darthscanner.fuzzer import normalized_body_hash, run_fuzz
from darthscanner.scope import Scope
from darthscanner.http_client import HttpResponse


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.max_requests = len(responses)
        self.requests_made = 0

    def get(self, url):
        response = self.responses.pop(0)
        self.requests_made += 1
        return response


class FuzzerCoverageTests(unittest.TestCase):
    def test_normalization_ignores_request_ids_and_uuids(self):
        first = b'{"request_id":"abcdef123456","item":"ok","id":"123e4567-e89b-12d3-a456-426614174000"}'
        second = b'{"request_id":"fedcba654321","item":"ok","id":"123e4567-e89b-12d3-a456-426614174001"}'
        self.assertEqual(normalized_body_hash(first), normalized_body_hash(second))

    def test_real_body_change_is_retained(self):
        self.assertNotEqual(
            normalized_body_hash(b'{"result":"alpha"}'),
            normalized_body_hash(b'{"result":"beta"}'),
        )

    def test_anomaly_score_and_replay_fields_are_recorded(self):
        scope = Scope(True, ("owned.example",), max_requests=10)
        responses = [
            HttpResponse("https://owned.example/search?q=x", 200,
                         {"content-type": "application/json"}, b'{"ok":true}', 0.1),
            HttpResponse("https://owned.example/search?q=", 500,
                         {"content-type": "text/plain"}, b"internal error", 0.2),
        ]
        client = FakeClient(responses)
        observations = run_fuzz(
            "https://owned.example/search?q=x", "q", scope, client, max_cases=1
        )
        self.assertEqual(len(observations), 1)
        self.assertGreaterEqual(observations[0].anomaly_score, 45)
        self.assertEqual(observations[0].endpoint_url, "https://owned.example/search?q=x")
        self.assertEqual(observations[0].mutation_value, "")


if __name__ == "__main__":
    unittest.main()
