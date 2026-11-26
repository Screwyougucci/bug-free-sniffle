import hashlib
import unittest
from unittest.mock import patch

from darthscanner.tool_installer import _checksum_for, _asset_sha256, _select_windows_asset


class ReliableInstallerTests(unittest.TestCase):
    def test_sha256sum_format(self):
        digest = "a" * 64
        self.assertEqual(_checksum_for(f"{digest}  ffuf_2_windows_amd64.zip\n".encode(), "ffuf_2_windows_amd64.zip"), digest)

    def test_openssl_format(self):
        digest = "b" * 64
        self.assertEqual(_checksum_for(f"SHA256(ffuf_2_windows_amd64.zip)= {digest}\n".encode(), "ffuf_2_windows_amd64.zip"), digest)

    def test_windows_path_in_manifest(self):
        digest = "c" * 64
        self.assertEqual(_checksum_for(f"{digest} *release\\ffuf_2_windows_amd64.zip\n".encode(), "ffuf_2_windows_amd64.zip"), digest)

    def test_github_asset_digest_is_used(self):
        digest = "d" * 64
        actual, source = _asset_sha256({"name": "tool.zip", "digest": "sha256:" + digest}, [])
        self.assertEqual(actual, digest)
        self.assertIn("GitHub", source)

    def test_manifest_fallback_tries_publisher_checksum_asset(self):
        digest = "e" * 64
        asset = {"name": "tool.zip"}
        checksum = {"name": "SHA256SUMS", "browser_download_url": "https://github.com/org/repo/releases/download/v1/SHA256SUMS"}
        with patch("darthscanner.tool_installer._read_url", return_value=f"{digest}  tool.zip\n".encode()):
            actual, source = _asset_sha256(asset, [asset, checksum])
        self.assertEqual(actual, digest)
        self.assertIn("SHA256SUMS", source)

    def test_missing_digest_fails_closed(self):
        with self.assertRaises(Exception):
            _asset_sha256({"name": "tool.zip"}, [{"name": "tool.zip"}])

    def test_asset_selector_chooses_windows_x64_zip(self):
        assets = [
            {"name": "ffuf_2_windows_arm64.zip", "browser_download_url": "https://github.com/a/b/releases/download/v/arm.zip"},
            {"name": "ffuf_2_windows_amd64.zip", "browser_download_url": "https://github.com/a/b/releases/download/v/x64.zip"},
        ]
        self.assertEqual(_select_windows_asset(assets, "ffuf")["name"], "ffuf_2_windows_amd64.zip")


if __name__ == "__main__":
    unittest.main()
