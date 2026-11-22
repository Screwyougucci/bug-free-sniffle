import json
from pathlib import Path
import tempfile
import unittest

from darthscanner.fuzz_reports import build_fuzz_finding_reports


class FuzzFindingReportTests(unittest.TestCase):
    def observation(self, signals):
        return {
            "parameter": "q",
            "case": "unicode",
            "status": 500 if "new-server-error" in signals else 200,
            "baseline_status": 200,
            "response_bytes": 512,
            "baseline_bytes": 200,
            "size_delta_bytes": 312,
            "elapsed_seconds": 0.25,
            "timing_ratio": 1.2,
            "request_url": "https://owned.example/search?q=hello",
            "input_sha256": "input-hash",
            "response_sha256": "response-hash",
            "baseline_sha256": "baseline-hash",
            "content_type": "text/html",
            "response_headers": {"content-type": "text/html"},
            "signal_types": signals,
            "confidence": "medium",
            "capture_time_utc": "2026-11-21T00:00:00+00:00",
            "reproduction_steps": ["Repeat the same bounded GET request."],
            "automatic_verification": {
                "attempted": True, "outcome": "repeatable-observation",
                "reproduced_signals": ["new-server-error"], "exploit_confirmed": False,
                "response_body_saved": False, "raw_test_value_saved": False,
            },
        }

    def test_multiple_patterns_get_separate_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            reports = build_fuzz_finding_reports(
                [self.observation(["input-reflection", "new-server-error"])], folder
            )
            self.assertEqual(len(reports), 2)
            self.assertNotEqual(reports[0]["report_id"], reports[1]["report_id"])
            self.assertTrue((Path(folder) / "index.json").exists())
            for report in reports:
                path = Path(folder) / (report["report_id"] + ".json")
                self.assertTrue(path.exists())
                saved = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(saved["classification"], "unconfirmed-vulnerability-hypothesis")
                self.assertTrue(saved["requires_human_confirmation"])
                self.assertFalse(saved["evidence"]["response_body_saved"])
                self.assertFalse(saved["evidence"]["raw_test_value_saved"])
                self.assertNotIn("raw_value", saved["evidence"])
                self.assertEqual(saved["proof_of_concept"]["request_method"], "GET")
                self.assertFalse(saved["proof_of_concept"]["automatic_verification"]["exploit_confirmed"])

    def test_redirect_is_not_mislabeled_open_redirect(self):
        with tempfile.TemporaryDirectory() as folder:
            reports = build_fuzz_finding_reports([self.observation(["redirect"])], folder)
            self.assertEqual(reports[0]["category"], "redirect-behavior-review")
            self.assertNotIn("open redirect", reports[0]["title"].lower())

    def test_unstable_baseline_is_not_reported_as_vulnerability(self):
        with tempfile.TemporaryDirectory() as folder:
            reports = build_fuzz_finding_reports(
                [self.observation(["input-reflection", "unstable-baseline"])], folder
            )
            self.assertEqual(reports, [])

    def test_no_signal_creates_empty_index_only(self):
        with tempfile.TemporaryDirectory() as folder:
            reports = build_fuzz_finding_reports([self.observation([])], folder)
            self.assertEqual(reports, [])
            index = json.loads((Path(folder) / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(index["report_count"], 0)


if __name__ == "__main__":
    unittest.main()
