import unittest
from urllib.parse import parse_qs, urlsplit

from darthscanner.fuzzer import run_fuzz_many
from darthscanner.http_client import HttpResponse
from darthscanner.scope import Scope


class FakeClient:
    def __init__(self, max_requests=20):
        self.max_requests = max_requests
        self.requests_made = 0
        self.urls = []

    def get(self, url):
        self.requests_made += 1
        self.urls.append(url)
        query = parse_qs(urlsplit(url).query)
        body = ("result:" + repr(query)).encode()
        return HttpResponse(
            url, 200, {"content-type": "text/plain", "location": ""},
            body, 0.01,
        )


class AdaptiveFuzzerTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(True, ("owned.example",), max_requests=20, request_delay_seconds=0.5)

    def test_fuzzes_all_existing_parameters_with_shared_case_limit(self):
        client = FakeClient()
        observations = run_fuzz_many(
            "https://owned.example/search?q=base&page=1",
            ["*"], self.scope, client, max_cases=4,
        )
        self.assertEqual(len(observations), 4)
        self.assertEqual(client.requests_made, 6)  # two baselines + four mutations
        self.assertEqual({item.parameter for item in observations}, {"q", "page"})
        self.assertTrue(all(item.baseline_sha256 for item in observations))
        self.assertTrue(all(isinstance(item.response_changed, bool) for item in observations))

    def test_single_parameter_mode_preserves_existing_behavior(self):
        client = FakeClient()
        observations = run_fuzz_many(
            "https://owned.example/search?q=base&page=1",
            ["page"], self.scope, client, max_cases=3,
        )
        self.assertEqual(len(observations), 3)
        self.assertEqual({item.parameter for item in observations}, {"page"})
        self.assertEqual(client.requests_made, 4)

    def test_rejects_missing_parameters(self):
        with self.assertRaises(ValueError):
            run_fuzz_many(
                "https://owned.example/search?q=base",
                ["missing"], self.scope, FakeClient(), max_cases=2,
            )

    def test_rejects_too_many_parameters(self):
        query = "&".join(f"p{i}=x" for i in range(9))
        with self.assertRaises(ValueError):
            run_fuzz_many(
                "https://owned.example/search?"+query,
                ["*"], self.scope, FakeClient(), max_cases=16,
            )

    def test_respects_shared_request_budget(self):
        client = FakeClient(max_requests=3)
        with self.assertRaises(ValueError):
            run_fuzz_many(
                "https://owned.example/search?a=x&b=y",
                ["*"], self.scope, client, max_cases=8,
            )
        self.assertEqual(client.requests_made, 0)


if __name__ == "__main__":
    unittest.main()
