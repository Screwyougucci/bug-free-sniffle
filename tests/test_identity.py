import unittest

from darthscanner.identity import (
    finding_identity,
    normalize_url,
    report_identity,
    resource_id,
    target_id,
    update_finding_registry,
    update_full_scan_history,
)


class DiscoveryIdentityTests(unittest.TestCase):
    def test_target_id_tracks_origin_not_path(self):
        self.assertEqual(target_id("https://example.test/a"), target_id("https://example.test/b"))
        self.assertNotEqual(target_id("https://example.test/a"), target_id("http://example.test/a"))

    def test_resource_id_ignores_query_and_fragment(self):
        self.assertEqual(
            resource_id("https://example.test/a?token=secret#section"),
            resource_id("https://example.test/a?other=value"),
        )
        self.assertEqual(normalize_url("https://example.test/a?token=secret#x"), "https://example.test/a")

    def test_report_identity_deduplicates_resources(self):
        result = report_identity("https://example.test", [
            {"url": "https://example.test/a?x=1"},
            {"url": "https://example.test/a?x=2"},
        ])
        self.assertTrue(result["target_id"].startswith("tgt-"))
        self.assertEqual(len(result["resources"]), 1)

    def test_finding_identity_has_separate_evidence_and_behavior_ids(self):
        finding = {
            "finding_id": "ABC123",
            "category": "headers",
            "title": "Missing header",
            "kind": "finding",
            "url": "https://example.test/",
            "evidence": "Header absent",
        }
        first = finding_identity(finding)
        second = finding_identity({**finding, "evidence": "Different evidence"})
        self.assertEqual(first["finding_id"], second["finding_id"])
        self.assertEqual(first["behavior_id"], second["behavior_id"])
        self.assertNotEqual(first["evidence_id"], second["evidence_id"])
        self.assertTrue(first["resource_id"].startswith("res-"))
        self.assertTrue(first["test_id"].startswith("tst-"))

    def test_registry_tracks_new_recurring_changed_and_resolved(self):
        history = {}
        finding = {
            "finding_id": "F-1",
            "category": "headers",
            "title": "Missing CSP",
            "severity": "low",
            "cvss_score": 6.1,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "evidence": "CSP absent",
            "url": "https://example.test/",
        }
        first = update_finding_registry(history, [finding], now="2026-01-01T00:00:00Z")
        self.assertEqual(first["new"], ["F-1"])
        self.assertEqual(history["finding_registry"]["F-1"]["title"], "Missing CSP")
        self.assertEqual(history["finding_registry"]["F-1"]["severity"], "low")
        self.assertEqual(history["finding_registry"]["F-1"]["cvss_score"], 6.1)
        self.assertEqual(history["finding_registry"]["F-1"]["cvss_vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")
        second = update_finding_registry(history, [finding], now="2026-01-02T00:00:00Z")
        self.assertEqual(second["recurring"], ["F-1"])
        changed = update_finding_registry(
            history, [{**finding, "evidence": "CSP header still absent; response changed"}],
            now="2026-01-03T00:00:00Z",
        )
        self.assertEqual(changed["changed"], ["F-1"])
        update_finding_registry(
            history, [{**finding, "evidence": "CSP header still absent; response changed"}],
            complete_round=True, now="2026-01-04T00:00:00Z",
        )
        resolved = update_finding_registry(history, [], complete_round=True, now="2026-01-05T00:00:00Z")
        self.assertEqual(resolved["resolved"], ["F-1"])
        self.assertEqual(history["finding_registry"]["F-1"]["status"], "resolved")


    def test_full_scan_persists_findings_and_marks_round_complete(self):
        history = {
            "cycles_completed": 3,
            "seen_finding_ids": ["OLD-1"],
            "finding_registry": {},
            "round_seen_finding_ids": [],
        }
        findings = [{
            "finding_id": "NEW-1",
            "category": "injection-review",
            "kind": "finding",
            "title": "Input handling review",
            "severity": "medium",
            "url": "https://example.test/search",
            "evidence": "A bounded read-only check produced a repeatable signal.",
        }]
        result = update_full_scan_history(
            history,
            "https://example.test/",
            findings,
            "reports/deep-scan-latest.json",
            now="2026-11-23T20:00:00Z",
        )
        self.assertEqual(result["new"], ["NEW-1"])
        self.assertEqual(history["cycles_completed"], 4)
        self.assertEqual(history["last_focus"], "all")
        self.assertEqual(history["last_report"], "reports/deep-scan-latest.json")
        self.assertEqual(history["target"], "https://example.test/")
        self.assertIn("NEW-1", history["finding_registry"])
        self.assertEqual(history["round_seen_finding_ids"], [])


if __name__ == "__main__":
    unittest.main()
