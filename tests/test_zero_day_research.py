import tempfile
import unittest
from pathlib import Path

from darthscanner.fuzzer import _variants, run_fuzz
from darthscanner.http_client import HttpResponse
from darthscanner.scope import Scope
from darthscanner.source_audit import audit_python_source


class SourceAuditTests(unittest.TestCase):
    def test_detects_common_security_review_leads_without_running_source(self):
        source = '''
import pickle
import subprocess
import requests
import sqlite3

def handler(user_value, url, command, blob, cursor):
    dynamic = eval(user_value)
    obj = pickle.loads(blob)
    subprocess.run(command, shell=True)
    requests.get(url)
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_value}'")
    requests.get("https://example.test", verify=False)
'''
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.py"
            path.write_text(source, encoding="utf-8")
            findings, reviewed, skipped = audit_python_source(folder)
        titles = {item.title for item in findings}
        self.assertEqual(reviewed, 1)
        self.assertEqual(skipped, 0)
        self.assertIn("Dynamic code execution via eval/exec", titles)
        self.assertIn("Potential unsafe deserialization", titles)
        self.assertIn("Subprocess call enables shell=True", titles)
        self.assertIn("Potential server-side request forgery data flow", titles)
        self.assertIn("SQL query may be assembled through string formatting", titles)
        self.assertIn("TLS certificate verification is disabled", titles)
        self.assertTrue(all(item.kind == "source-review-lead" for item in findings))
        self.assertTrue(all(item.cwe_ids for item in findings))

    def test_hardcoded_secret_is_redacted(self):
        source = 'API_KEY = "not-a-real-secret-for-test-123456"\n'
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "secrets.py"
            path.write_text(source, encoding="utf-8")
            findings, _, _ = audit_python_source(path)
        finding = next(item for item in findings if "hard-coded" in item.title)
        self.assertIn("[REDACTED]", finding.evidence)
        self.assertNotIn("not-a-real-secret", finding.evidence)

    def test_skips_virtualenv_and_non_python_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "good.py").write_text("value = 1\n", encoding="utf-8")
            (root / "notes.txt").write_text("eval(user_input)", encoding="utf-8")
            (root / ".venv").mkdir()
            (root / ".venv" / "bad.py").write_text("eval(user_input)", encoding="utf-8")
            findings, reviewed, skipped = audit_python_source(root)
        self.assertEqual(findings, [])
        self.assertEqual(reviewed, 1)
        self.assertGreaterEqual(skipped, 0)

    def test_rejects_missing_path(self):
        with self.assertRaises(ValueError):
            audit_python_source("this-path-should-not-exist-381928")


class _FakeFuzzClient:
    max_requests = 10

    def __init__(self):
        self.requests_made = 0

    def get(self, url):
        self.requests_made += 1
        if self.requests_made == 1:
            return HttpResponse(url, 200, {"content-type": "text/plain"}, b"baseline", 0.01)
        return HttpResponse(url, 500, {"content-type": "text/html"},
                            b"Traceback (most recent call last)", 0.02)


class ZeroDayFuzzResearchTests(unittest.TestCase):
    def test_corpus_contains_32_bounded_non_exploit_values(self):
        cases = _variants()
        self.assertEqual(len(cases), 32)
        self.assertLessEqual(max(len(value) for _, value in cases), 256)

    def test_fuzzer_records_error_and_differential_evidence(self):
        scope = Scope(True, ("owned.example",), request_delay_seconds=0.5, max_requests=10)
        client = _FakeFuzzClient()
        observations = run_fuzz(
            "https://owned.example/search?q=baseline",
            "q", scope, client, max_cases=1,
        )
        self.assertEqual(len(observations), 1)
        item = observations[0]
        self.assertEqual(item.baseline_status, 200)
        self.assertEqual(item.status, 500)
        self.assertTrue(item.response_sha256)
        self.assertIn("5xx", item.note)
        self.assertIn("diagnostic/error signature", item.note)


if __name__ == "__main__":
    unittest.main()
