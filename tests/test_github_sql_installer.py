import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from darthscanner.tool_installer import _safe_extract_zip
from darthscanner.toolchain import ToolchainError
from darthscanner.sqlmap_engine import run_sqlmap_checks


class GithubInstallerArchiveTests(unittest.TestCase):
    def test_safe_zip_extracts_expected_file(self):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("runtime/bin/java.exe", b"MZ-test")
        with tempfile.TemporaryDirectory() as folder:
            paths = _safe_extract_zip(payload.getvalue(), Path(folder))
            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0].read_bytes(), b"MZ-test")

    def test_safe_zip_rejects_parent_traversal(self):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("../outside.txt", "bad")
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ToolchainError):
                _safe_extract_zip(payload.getvalue(), Path(folder))


class SqlMapScopeTests(unittest.TestCase):
    def test_sqlmap_only_considers_two_same_origin_query_urls(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "sqlmap" / "sqlmap.py"
            source.parent.mkdir()
            source.write_text("# sqlmap test stub", encoding="utf-8")
            out = root / "reports"
            fake_result = type("Result", (), {"stdout": "all tested parameters do not appear to be injectable", "returncode": 0})()
            with patch("darthscanner.sqlmap_engine.tool_root", return_value=root), \
                 patch("darthscanner.sqlmap_engine._python_command", return_value="python"), \
                 patch("darthscanner.sqlmap_engine.subprocess.run", return_value=fake_result) as run:
                results = run_sqlmap_checks([
                    "https://example.com/item?id=1",
                    "https://evil.test/?q=1",
                    "https://example.com/search?q=abc",
                    "https://example.com/third?x=2",
                ], "https://example.com", out)
            self.assertEqual(len(results), 2)
            self.assertEqual(run.call_count, 2)
            args = run.call_args_list[0].args[0]
            self.assertIn("--risk=1", args)
            self.assertIn("--level=1", args)
            self.assertIn("--technique=BEU", args)
            self.assertNotIn("--dump", args)
            self.assertNotIn("--dbs", args)
            self.assertNotIn("--os-shell", args)
            self.assertTrue((out / "sqlmap-summary.json").is_file())

    def test_sqlmap_skips_urls_without_query_parameters(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "sqlmap" / "sqlmap.py"
            source.parent.mkdir()
            source.write_text("# stub", encoding="utf-8")
            with patch("darthscanner.sqlmap_engine.tool_root", return_value=root), \
                 patch("darthscanner.sqlmap_engine._python_command", return_value="python"), \
                 patch("darthscanner.sqlmap_engine.subprocess.run") as run:
                results = run_sqlmap_checks(["https://example.com/about"], "https://example.com", root / "out")
            self.assertEqual(results, [])
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
