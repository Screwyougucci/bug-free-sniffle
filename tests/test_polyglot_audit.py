import tempfile
import unittest
from pathlib import Path

from darthscanner.polyglot_audit import audit_source


class PolyglotAuditTests(unittest.TestCase):
    def test_javascript_shell_and_tls_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.js"
            path.write_text(
                "child_process.exec(userInput)\n"
                "const agent = { rejectUnauthorized: false };\n",
                encoding="utf-8",
            )
            findings, reviewed, skipped = audit_source(path)
            self.assertEqual(reviewed, 1)
            self.assertEqual(skipped, 0)
            self.assertGreaterEqual(len(findings), 2)
            self.assertTrue(any(item.cwe_ids == ["CWE-78"] for item in findings))
            self.assertTrue(any(item.cwe_ids == ["CWE-295"] for item in findings))

    def test_php_unsafe_deserialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "handler.php"
            path.write_text("unserialize($request);\n", encoding="utf-8")
            findings, _, _ = audit_source(path)
            self.assertTrue(any(item.cwe_ids == ["CWE-502"] for item in findings))

    def test_secret_value_is_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.ts"
            path.write_text('const api_key = "very-real-secret-value";\n', encoding="utf-8")
            findings, _, _ = audit_source(path)
            secret_findings = [item for item in findings if item.cwe_ids == ["CWE-798"]]
            self.assertEqual(len(secret_findings), 1)
            self.assertNotIn("very-real-secret-value", secret_findings[0].evidence)

    def test_python_uses_existing_ast_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "unsafe.py"
            path.write_text("eval(user_input)\n", encoding="utf-8")
            findings, reviewed, _ = audit_source(path)
            self.assertEqual(reviewed, 1)
            self.assertTrue(any("eval/exec" in item.title for item in findings))

    def test_unsupported_file_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notes.txt"
            path.write_text("nothing", encoding="utf-8")
            findings, reviewed, skipped = audit_source(path)
            self.assertEqual((findings, reviewed, skipped), ([], 0, 1))


if __name__ == "__main__":
    unittest.main()
