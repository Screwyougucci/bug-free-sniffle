import tempfile
import unittest
from pathlib import Path

from darthscanner.checks import inspect_http
from darthscanner.fuzzer import mutate_query_parameter
from darthscanner.http_client import HttpResponse
from darthscanner.scope import Scope, ScopeError, load_scope, require_authorization


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(True, ("owned.example",), max_requests=20)

    def test_exact_host_allowed(self):
        self.assertEqual(self.scope.validate_url("https://owned.example/path"), "https://owned.example/path")

    def test_subdomain_not_implicitly_allowed(self):
        with self.assertRaises(ScopeError):
            self.scope.validate_url("https://sub.owned.example/")

    def test_credentials_rejected(self):
        with self.assertRaises(ScopeError):
            self.scope.validate_url("https://user:pass@owned.example/")

    def test_non_http_scheme_rejected(self):
        with self.assertRaises(ScopeError):
            self.scope.validate_url("file:///etc/passwd")

    def test_authorization_requires_both_flags(self):
        with self.assertRaises(ScopeError):
            require_authorization(self.scope, False)
        with self.assertRaises(ScopeError):
            require_authorization(Scope(False, ("owned.example",)), True)

    def test_scope_file_validation(self):
        payload = '{"authorized":true,"allowed_hosts":["owned.example"],"max_pages":5}'
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "scope.json"
            file.write_text(payload, encoding="utf-8")
            loaded = load_scope(file)
            self.assertEqual(loaded.max_pages, 5)
            self.assertEqual(loaded.allowed_hosts, ("owned.example",))


class FuzzerTests(unittest.TestCase):
    def test_only_named_parameter_is_changed(self):
        result = mutate_query_parameter("https://owned.example/?q=old&lang=en", "q", "new value")
        self.assertIn("q=new+value", result)
        self.assertIn("lang=en", result)

    def test_duplicate_parameter_is_rejected(self):
        with self.assertRaises(ValueError):
            mutate_query_parameter("https://owned.example/?q=a&q=b", "q", "c")

    def test_missing_parameter_is_rejected(self):
        with self.assertRaises(ValueError):
            mutate_query_parameter("https://owned.example/?lang=en", "q", "c")


class PassiveChecksTests(unittest.TestCase):
    def test_missing_headers_are_reported_for_html(self):
        response = HttpResponse("https://owned.example/", 200,
                                {"content-type": "text/html"}, b"<html></html>", 0.1)
        findings = inspect_http(response)
        titles = {finding.title for finding in findings}
        self.assertIn("Content Security Policy is missing", titles)
        self.assertIn("HSTS header is missing", titles)

    def test_non_html_does_not_trigger_html_header_findings(self):
        response = HttpResponse("https://owned.example/api", 200,
                                {"content-type": "application/json"}, b"{}", 0.1)
        self.assertFalse(any(f.category == "http-headers" for f in inspect_http(response)))


if __name__ == "__main__":
    unittest.main()
