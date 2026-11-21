import unittest

from darthscanner.scope import Scope, ScopeError
from darthscanner.checks import source_excerpt_for


class Response:
    def __init__(self, body):
        self.text = body


class SubdomainScopeTests(unittest.TestCase):
    def test_authorized_subdomain_matches_root_boundary(self):
        scope = Scope(
            authorized=True,
            allowed_hosts=("example.com",),
            root_domain="example.com",
            include_subdomains=True,
        )
        self.assertEqual(scope.validate_url("https://api.example.com/"), "https://api.example.com/")

    def test_apex_is_allowed_as_exact_host(self):
        scope = Scope(
            authorized=True,
            allowed_hosts=("example.com",),
            root_domain="example.com",
            include_subdomains=True,
        )
        self.assertEqual(scope.validate_url("https://example.com/"), "https://example.com/")

    def test_lookalike_suffix_is_rejected(self):
        scope = Scope(
            authorized=True,
            allowed_hosts=("example.com",),
            root_domain="example.com",
            include_subdomains=True,
        )
        with self.assertRaises(ScopeError):
            scope.validate_url("https://example.com.attacker.test/")

    def test_other_domain_is_rejected_when_subdomain_mode_is_off(self):
        scope = Scope(authorized=True, allowed_hosts=("example.com",))
        with self.assertRaises(ScopeError):
            scope.validate_url("https://api.example.com/")


class SourceEvidenceTests(unittest.TestCase):
    def test_exact_html_snippet_and_line_are_captured(self):
        response = Response('<html>\n<a target="_blank" href="/docs">docs</a>\n</html>')
        excerpt, line = source_excerpt_for(response, "Target-blank link lacks opener isolation")
        self.assertIn('target="_blank"', excerpt)
        self.assertEqual(line, 2)

    def test_secret_value_is_redacted_from_snippet(self):
        response = Response('<button onclick="token=supersecret123">click</button>')
        excerpt, _ = source_excerpt_for(response, "Inline JavaScript event handler found")
        self.assertNotIn("supersecret123", excerpt)
        self.assertIn("[REDACTED]", excerpt)


if __name__ == "__main__":
    unittest.main()
