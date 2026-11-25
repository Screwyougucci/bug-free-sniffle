import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from darthscanner.zap_engine import (
    ZapNotInstalledError,
    alerts_to_findings,
    build_launch_command,
    find_zap_launcher,
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
        with patch("darthscanner.zap_engine.os.name", "nt"):
            command = build_launch_command(Path("C:/ZAP/zap.bat"), 8090, "secret")
        self.assertEqual(command[:3], ["cmd.exe", "/c", "C:/ZAP/zap.bat".replace("/", "\\\\")])
        self.assertIn("127.0.0.1", command)
        self.assertIn("api.key=secret", command)

    def test_executable_launcher_runs_directly(self):
        with patch("darthscanner.zap_engine.os.name", "nt"):
            command = build_launch_command(Path("C:/ZAP/zap.exe"), 8090, "secret")
        self.assertEqual(command[0], "C:/ZAP/zap.exe".replace("/", "\\\\"))

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
