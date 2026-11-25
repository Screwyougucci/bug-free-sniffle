import json
from pathlib import Path
import tempfile
import unittest

from darthscanner.toolchain import (
    SAFE_PATH_WORDLIST,
    ToolchainError,
    _checksum_for,
    _is_in_scope,
    _read_jsonl,
    run_toolchain_watch,
)


class ToolchainTests(unittest.TestCase):
    def test_exact_origin_scope(self):
        self.assertTrue(_is_in_scope("https://example.com", "https://example.com/login", False))
        self.assertFalse(_is_in_scope("https://example.com", "https://sub.example.com/", False))
        self.assertFalse(_is_in_scope("https://example.com", "https://example.com.evil.test/", True))

    def test_subdomain_scope_requires_explicit_flag(self):
        self.assertFalse(_is_in_scope("https://example.com", "https://api.example.com/", False))
        self.assertTrue(_is_in_scope("https://example.com", "https://api.example.com/", True))
        self.assertFalse(_is_in_scope("https://example.com", "http://api.example.com/", True))

    def test_checksum_manifest_requires_exact_asset(self):
        manifest = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ffuf_2_windows_amd64.zip\n"
        self.assertEqual(
            _checksum_for(manifest, "ffuf_2_windows_amd64.zip"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        with self.assertRaises(ToolchainError):
            _checksum_for(manifest, "other.zip")

    def test_jsonl_reader_ignores_malformed_lines_and_caps(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "results.jsonl"
            path.write_text('{"url":"https://example.com"}\nnot-json\n{"url":"https://example.com/a"}\n', encoding="utf-8")
            self.assertEqual(len(_read_jsonl(path)), 2)
            self.assertEqual(len(_read_jsonl(path, limit=1)), 1)

    def test_wordlist_is_benign_discovery_only(self):
        self.assertIn("robots.txt", SAFE_PATH_WORDLIST)
        self.assertIn("sitemap.xml", SAFE_PATH_WORDLIST)
        self.assertNotIn("union select", SAFE_PATH_WORDLIST.lower())
        self.assertNotIn("sleep(", SAFE_PATH_WORDLIST.lower())

    def test_duration_is_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ToolchainError):
                run_toolchain_watch(
                    "https://example.com", Path(folder),
                    duration_hours=25,
                )

    def test_installer_requires_tools_before_network_run(self):
        with tempfile.TemporaryDirectory() as folder:
            # Redirect the tool root by setting LOCALAPPDATA before tool_root is called.
            import os
            old = os.environ.get("LOCALAPPDATA")
            os.environ["LOCALAPPDATA"] = folder
            try:
                with self.assertRaises(ToolchainError):
                    run_toolchain_watch(
                        "https://example.com", Path(folder) / "out",
                        duration_hours=1,
                    )
            finally:
                if old is None:
                    os.environ.pop("LOCALAPPDATA", None)
                else:
                    os.environ["LOCALAPPDATA"] = old


if __name__ == "__main__":
    unittest.main()
