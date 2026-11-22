import base64
import json
import unittest
from unittest.mock import patch

from darthscanner.github_audit import (
    audit_github_repository,
    discover_github_repositories,
    parse_repository_url,
)

class GitHubAuditTests(unittest.TestCase):
    def test_parse_repository_url(self):
        self.assertEqual(parse_repository_url("https://github.com/acme/widget/tree/main"), ("acme", "widget"))
        self.assertEqual(parse_repository_url("github.com/acme/widget.git"), ("acme", "widget"))

    def test_rejects_non_github_and_profile_urls(self):
        with self.assertRaises(ValueError):
            parse_repository_url("https://evil.example/acme/widget")
        with self.assertRaises(ValueError):
            parse_repository_url("https://github.com/acme")

    def test_discovers_unique_repository_links_and_ignores_file_routes(self):
        html = '<a href="https://github.com/acme/widget">code</a> https://github.com/acme/widget/issues/4 https://github.com/acme/other'
        self.assertEqual(discover_github_repositories(html), [
            "https://github.com/acme/widget", "https://github.com/acme/other"
        ])

    def test_audits_bounded_blob_and_redacts_secret_evidence(self):
        source = 'API_KEY = "super-secret-value-12345"\nrequests.get(url, verify=False)\n'
        blob = {
            "encoding": "base64",
            "content": base64.b64encode(source.encode()).decode(),
        }
        def fake_request(url, token, limit):
            if url.endswith("/repos/acme/widget"):
                return json.dumps({"default_branch": "main", "visibility": "public"}).encode()
            if "/git/trees/" in url:
                return json.dumps({"truncated": False, "tree": [
                    {"type": "blob", "path": "app.py", "sha": "abc", "size": len(source)}
                ]}).encode()
            if url.endswith("/git/blobs/abc"):
                return json.dumps(blob).encode()
            raise AssertionError(url)
        with patch("darthscanner.github_audit._request", side_effect=fake_request):
            findings, summary = audit_github_repository("https://github.com/acme/widget")
        self.assertEqual(summary["files_reviewed"], 1)
        self.assertGreaterEqual(len(findings), 2)
        secret = next(item for item in findings if item.title == "Possible hard-coded secret")
        self.assertIn("[REDACTED]", secret.source_excerpt)
        self.assertNotIn("super-secret-value", secret.evidence)
        self.assertEqual(secret.source_line, 1)
        self.assertIn("github.com/acme/widget/blob/main/app.py", secret.source_url)

if __name__ == "__main__":
    unittest.main()
