import unittest

from darthscanner.fuzz_correlation import correlate_fuzz_observations


def obs(path="/search", parameter="q", signals=None, digest="a"):
    return {
        "request_url": f"https://owned.example{path}?{parameter}=x",
        "parameter": parameter,
        "signal_types": signals or [],
        "response_sha256": digest,
    }


class FuzzCorrelationTests(unittest.TestCase):
    def test_related_server_error_and_diagnostic_are_correlated(self):
        results = correlate_fuzz_observations([
            obs(signals=["new-server-error"], digest="one"),
            obs(signals=["new-diagnostic-signature"], digest="two"),
        ])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["category"], "input-error-handling-and-diagnostic-disclosure")
        self.assertEqual(results[0]["confidence"], "medium")
        self.assertIsNone(results[0]["cvss_score"])
        self.assertEqual(results[0]["exploitability"], "not_confirmed")

    def test_different_hosts_do_not_correlate(self):
        first = obs(signals=["new-server-error"])
        second = obs(signals=["new-diagnostic-signature"])
        second["request_url"] = "https://other.example/search?q=x"
        self.assertEqual(correlate_fuzz_observations([first, second]), [])

    def test_different_paths_do_not_correlate(self):
        self.assertEqual(correlate_fuzz_observations([
            obs(path="/one", signals=["new-server-error"]),
            obs(path="/two", signals=["new-diagnostic-signature"]),
        ]), [])

    def test_different_parameters_do_not_correlate(self):
        self.assertEqual(correlate_fuzz_observations([
            obs(parameter="q", signals=["new-server-error"]),
            obs(parameter="page", signals=["new-diagnostic-signature"]),
        ]), [])

    def test_unstable_baseline_is_excluded(self):
        self.assertEqual(correlate_fuzz_observations([
            obs(signals=["new-server-error", "unstable-baseline"]),
            obs(signals=["new-diagnostic-signature"]),
        ]), [])

    def test_latency_and_size_pair_is_low_confidence(self):
        results = correlate_fuzz_observations([
            obs(signals=["timing-outlier"], digest="one"),
            obs(signals=["large-response-delta"], digest="two"),
        ])
        self.assertEqual(results[0]["category"], "input-dependent-processing-review")
        self.assertEqual(results[0]["confidence"], "medium")
        self.assertIn("not prove resource exhaustion", results[0]["rationale"])

