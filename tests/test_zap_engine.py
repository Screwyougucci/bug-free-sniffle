import os
from pathlib import Path, PureWindowsPath
import tempfile
import unittest
from unittest.mock import patch

from darthscanner.zap_engine import (
    ZapNotInstalledError,
    ZapRuntime,
    alerts_to_findings,
    build_launch_command,
    find_zap_launcher,
    is_same_origin,
    scope_regex_for_target,
)


class ZapEngineTests(unittest.TestCase):
    def test_scope_regex_is_exact_host_and_port(self):
        pattern = scope_regex_for_target("https://shop.owned.example:8443/catalog")
        self.assertEqual(pattern, r"^https://shop\.owned\.example:8443/.*$")
        self.assertNotIn(".*owned", pattern)

    def test_scope_regex_rejects_invalid_target(self):
        with self.assertRaises(ValueError):
            scope_regex_for_target("file:///etc/passwd")

    def test_result_filter_rejects_external_hosts_and_subdomains(self):
        target = "https://owned.example:8443/"
        self.assertTrue(is_same_origin(target, "https://owned.example:8443/path"))
        self.assertFalse(is_same_origin(target, "https://api.owned.example:8443/path"))
        self.assertFalse(is_same_origin(target, "https://outside.example:8443/path"))
        self.assertFalse(is_same_origin(target, "http://owned.example:8443/path"))
        self.assertFalse(is_same_origin(target, "https://owned.example/path"))

    def test_zap_alerts_are_normalized_and_secrets_redacted(self):
        alerts = [{
            "name": "Example injection candidate",
            "risk": "High",
            "confidence": "High",
            "url": "https://owned.example/search?token=secret123",
            "method": "GET",
            "param": "q",
            "attack": "Bearer abcdefghijklmnop",
            "evidence": "password=supersecret",
            "solution": "Use parameterized handling.",
            "cweid": "89",
            "pluginId": "40018",
            "reference": "https://owasp.org/example CVE-2025-12345",
        }]
        findings = alerts_to_findings(alerts)
        self.assertEqual(len(findings), 1)
        item = findings[0]
        self.assertEqual(item.severity, "high")
        self.assertEqual(item.confidence, "high")
        self.assertEqual(item.url, "https://owned.example/search?token=%5BREDACTED%5D")
        self.assertEqual(item.cwe_ids, ["CWE-89"])
        self.assertEqual(item.cve_ids, ["CVE-2025-12345"])
        self.assertNotIn("secret123", item.url)
        self.assertNotIn("abcdefghijklmnop", item.evidence)
        self.assertNotIn("supersecret", item.evidence)
        self.assertFalse(item.evidence_details["response_body_saved"])
        self.assertFalse(item.evidence_details["raw_attack_value_saved"])

    def test_alert_without_url_is_ignored(self):
        self.assertEqual(alerts_to_findings([{"name": "bad"}]), [])

    def test_batch_launcher_uses_cmd_on_windows(self):
        launcher = PureWindowsPath("C:/ZAP/zap.bat")
        with patch("darthscanner.zap_engine.os.name", "nt"):
            command = build_launch_command(launcher, 8090, "secret")
        self.assertEqual(command[:2], ["cmd.exe", "/c"])
        self.assertEqual(command[2].replace("\\", "/"), "C:/ZAP/zap.bat")
        self.assertIn("127.0.0.1", command)
        self.assertIn("api.key=secret", command)

    def test_executable_launcher_runs_directly(self):
        launcher = PureWindowsPath("C:/ZAP/zap.exe")
        with patch("darthscanner.zap_engine.os.name", "nt"):
            command = build_launch_command(launcher, 8090, "secret")
        self.assertEqual(command[0].replace("\\", "/"), "C:/ZAP/zap.exe")

    def test_scan_orchestration_uses_zap_and_filters_out_of_scope_results(self):
        calls = []
        def fake_api(component, kind, operation, params):
            calls.append((component, kind, operation, params))
            if (component, kind, operation) == ("core", "view", "version"):
                return {"version": "2.17.0"}
            if (component, kind, operation) == ("context", "action", "newContext"):
                return {"contextId": "1"}
            if (component, kind, operation) == ("spider", "action", "scan"):
                return {"scan": "1"}
            if (component, kind, operation) == ("spider", "view", "status"):
                return {"status": "100"}
            if (component, kind, operation) == ("clientSpider", "action", "scan"):
                return {"scan": "2"}
            if (component, kind, operation) == ("clientSpider", "view", "status"):
                return {"status": "complete"}
            if (component, kind, operation) == ("pscan", "view", "recordsToScan"):
                return {"recordsToScan": "0"}
            if (component, kind, operation) == ("core", "view", "alerts"):
                return {"alerts": [
                    {"name": "In-scope alert", "risk": "Medium", "confidence": "High",
                     "url": "https://owned.example/login", "cweid": "200"},
                    {"name": "External alert", "risk": "High", "confidence": "High",
                     "url": "https://outside.example/login"},
                ]}
            if (component, kind, operation) == ("core", "view", "urls"):
                return {"urls": ["https://owned.example/", "https://outside.example/"]}
            return {}

        engine = ZapEngine(api_call=fake_api)
        engine.runtime = ZapRuntime(
            process=None, base_url="http://127.0.0.1:8090",
            api_key="test-key", launcher=PureWindowsPath("C:/ZAP/zap.bat"),
        )
        result = engine.scan("https://owned.example/")
        self.assertEqual(result["engine_version"], "2.17.0")
        self.assertEqual(result["discovered_url_count"], 1)
        self.assertEqual(result["alert_count"], 1)
        self.assertEqual(result["out_of_scope_alerts_excluded"], 1)
        self.assertEqual(len(result["findings"]), 1)
        include_call = next(item for item in calls if item[:3] == ("context", "action", "includeInContext"))
        self.assertEqual(include_call[3]["regex"], r"^https://owned\.example/.*$")

    def test_launcher_can_be_configured_by_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            launcher = Path(folder) / "zap.bat"
            launcher.write_text("@echo off\n", encoding="utf-8")
            old = os.environ.get("DARTH_ZAP_PATH")
            try:
                os.environ["DARTH_ZAP_PATH"] = str(launcher)
                self.assertEqual(find_zap_launcher(), launcher.resolve())
            finally:
                if old is None:
                    os.environ.pop("DARTH_ZAP_PATH", None)
                else:
                    os.environ["DARTH_ZAP_PATH"] = old


if __name__ == "__main__":
    unittest.main()
