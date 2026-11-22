import unittest
from types import SimpleNamespace

from darthscanner.fuzzer import (
    discover_query_parameters,
    run_fuzz,
    run_fuzz_suite,
    sanitize_url,
)
from darthscanner.http_client import HttpResponse
from darthscanner.scope import Scope


class FakeClient:
    def __init__(self, responses, max_requests=20):
        self.responses = list(responses)
        self.max_requests = max_requests
        self.requests_made = 0
        self.urls = []

    def get(self, url):
        self.urls.append(url)
        self.requests_made += 1
        return self.responses.pop(0)


def response(status=200, body=b"normal response", elapsed=0.1, content_type="text/html"):
    return HttpResponse(
        url="https://example.test/search?q=hello&token=secret",
        status=status,
        headers={"content-type": content_type, "set-cookie": "private=secret"},
        body=body,
        elapsed_seconds=elapsed,
    )


class ProfessionalFuzzerTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(
            authorized=True,
            allowed_hosts=("example.test",),
            max_requests=50,
            request_delay_seconds=0.5,
        )

    def test_discovers_unique_query_parameters_in_order(self):
        self.assertEqual(
            discover_query_parameters("https://example.test/?q=x&page=1&q=y"),
            ["q", "page"],
        )

    def test_secret_like_parameters_are_not_auto_discovered(self):
        self.assertEqual(
            discover_query_parameters("https://example.test/?q=hello&session=secret&access_token=private"),
            ["q"],
        )

    def test_report_url_redacts_secret_query_values(self):
        safe = sanitize_url("https://example.test/?q=hello&access_token=private")
        self.assertIn("q=hello", safe)
        self.assertNotIn("private", safe)
        self.assertIn("REDACTED", safe)

    def test_new_server_error_and_diagnostic_are_scored_with_safe_evidence(self):
        fake = FakeClient([
            response(), response(),
            response(500, b"Internal Server Error: traceback (most recent call last)", 0.2),
        ], max_requests=3)
        items = run_fuzz(
            "https://example.test/search?q=hello&token=secret",
            "q", self.scope, fake, max_cases=1, baseline_repeats=2,
        )
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertIn("new-server-error", item.signal_types)
        self.assertIn("new-diagnostic-signature", item.signal_types)
        self.assertGreaterEqual(item.anomaly_score, 65)
        self.assertEqual(item.confidence, "low")
        self.assertEqual(item.baseline_repeats, 2)
        self.assertTrue(item.baseline_stable)
        self.assertNotIn("secret", item.request_url)
        self.assertNotIn("value", item.__dict__)
        self.assertTrue(item.input_sha256)
        self.assertTrue(item.baseline_sha256)
        self.assertTrue(item.response_sha256)
        self.assertTrue(item.reproduction_steps)
        self.assertNotIn("set-cookie", item.response_headers)

    def test_suite_respects_shared_request_budget(self):
        fake = FakeClient([response() for _ in range(8)], max_requests=8)
        items = run_fuzz_suite(
            "https://example.test/search?q=hello&page=1",
            ["q", "page"], self.scope, fake, max_cases=12,
        )
        self.assertEqual(fake.requests_made, 8)
        self.assertEqual({item.parameter for item in items}, {"q", "page"})

    def test_unstable_baseline_reduces_confidence(self):
        fake = FakeClient([
            response(200), response(404), response(200),
        ], max_requests=3)
        items = run_fuzz(
            "https://example.test/search?q=hello",
            "q", self.scope, fake, max_cases=1,
        )
        self.assertIn("unstable-baseline", items[0].signal_types)
        self.assertNotEqual(items[0].confidence, "high")

    def test_auto_verification_repeats_a_promising_get_observation(self):
        fake = FakeClient([
            response(), response(),
            response(500, b"Internal Server Error: traceback (most recent call last)", 0.2),
            response(500, b"Internal Server Error: traceback (most recent call last)", 0.2),
        ], max_requests=4)
        state = {"used": False}
        items = run_fuzz(
            "https://example.test/search?q=hello", "q", self.scope, fake,
            max_cases=1, baseline_repeats=2, auto_verify=True,
            reserve_requests=0, verification_state=state,
        )
        check = items[0].automatic_verification
        self.assertTrue(check["attempted"])
        self.assertEqual(check["outcome"], "repeatable-observation")
        self.assertIn("new-server-error", check["reproduced_signals"])
        self.assertFalse(check["exploit_confirmed"])
        self.assertFalse(check["response_body_saved"])
        self.assertTrue(state["used"])
        self.assertEqual(fake.requests_made, 4)

    def test_auto_verification_respects_reserved_request_budget(self):
        fake = FakeClient([
            response(), response(),
            response(500, b"Internal Server Error: traceback (most recent call last)", 0.2),
        ], max_requests=4)
        items = run_fuzz(
            "https://example.test/search?q=hello", "q", self.scope, fake,
            max_cases=1, baseline_repeats=2, auto_verify=True,
            reserve_requests=1,
        )
        self.assertFalse(items[0].automatic_verification["attempted"])
        self.assertEqual(fake.requests_made, 3)


if __name__ == "__main__":
    unittest.main()
