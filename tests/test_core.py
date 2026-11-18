import tempfile
import unittest
from pathlib import Path

from darthscanner.checks import inspect_html, inspect_http
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

    def test_fuzz_corpus_has_twenty_bounded_cases(self):
        from darthscanner.fuzzer import _variants
        cases = _variants()
        self.assertEqual(len(cases), 20)
        self.assertLessEqual(max(len(value) for _, value in cases), 256)


class PassiveChecksTests(unittest.TestCase):
    def test_missing_headers_are_reported_for_html(self):
        response = HttpResponse("https://owned.example/", 200,
                                {"content-type": "text/html"}, b"<html></html>", 0.1)
        findings = inspect_http(response)
        titles = {finding.title for finding in findings}
        self.assertIn("Content Security Policy is missing", titles)
        self.assertIn("HSTS header is missing", titles)

    def test_non_html_does_not_trigger_html_only_header_findings(self):
        response = HttpResponse("https://owned.example/api", 200,
                                {"content-type": "application/json"}, b"{}", 0.1)
        titles = {finding.title for finding in inspect_http(response)}
        self.assertNotIn("Content Security Policy is missing", titles)
        self.assertNotIn("Referrer-Policy is missing", titles)
        self.assertNotIn("Permissions-Policy is missing", titles)
        self.assertIn("HSTS header is missing", titles)

    def test_csp_unsafe_directives_are_flagged(self):
        response = HttpResponse("https://owned.example/", 200, {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; script-src * 'unsafe-inline' 'unsafe-eval'",
        }, b"<html></html>", 0.1)
        titles = {finding.title for finding in inspect_http(response)}
        self.assertIn("CSP permits inline scripts", titles)
        self.assertIn("CSP permits eval-like script execution", titles)
        self.assertIn("CSP script source permits a wildcard", titles)

    def test_wildcard_cors_is_observation_not_confirmed_vulnerability(self):
        response = HttpResponse("https://owned.example/api", 200, {
            "content-type": "application/json",
            "access-control-allow-origin": "*",
        }, b"{}", 0.1)
        finding = next(f for f in inspect_http(response) if f.category == "cors")
        self.assertEqual(finding.kind, "observation")
        self.assertEqual(finding.severity, "info")

    def test_mixed_content_is_reported(self):
        response = HttpResponse("https://owned.example/", 200,
                                {"content-type": "text/html"},
                                b'<script src="http://cdn.example/app.js"></script>', 0.1)
        titles = {finding.title for finding in inspect_html(response)}
        self.assertIn("HTTPS page references an insecure HTTP resource", titles)

    def test_password_get_form_is_reported(self):
        response = HttpResponse("https://owned.example/login", 200,
                                {"content-type": "text/html"},
                                b'<form><input type="password" name="pw"></form>', 0.1)
        titles = {finding.title for finding in inspect_html(response)}
        self.assertIn("Password form uses GET", titles)

    def test_password_form_on_http_is_reported(self):
        response = HttpResponse("http://owned.example/login", 200,
                                {"content-type": "text/html"},
                                b'<form method="post"><input type="password" name="pw"></form>', 0.1)
        titles = {finding.title for finding in inspect_html(response)}
        self.assertIn("Password form is not guaranteed to submit over HTTPS", titles)

    def test_debug_and_directory_listing_signatures_are_reported(self):
        response = HttpResponse("https://owned.example/debug", 200,
                                {"content-type": "text/html"},
                                b"<h1>Index of /backup</h1> Werkzeug Debugger", 0.1)
        titles = {finding.title for finding in inspect_http(response)}
        self.assertIn("Directory index appears to be enabled", titles)
        self.assertIn("Werkzeug interactive debugger signature detected", titles)

    def test_database_error_signature_is_reported_without_copying_body(self):
        response = HttpResponse("https://owned.example/search", 500,
                                {"content-type": "text/plain"},
                                b"You have an error in your SQL syntax near sensitive-value", 0.1)
        findings = inspect_http(response)
        finding = next(f for f in findings if f.category == "error-disclosure")
        self.assertNotIn("sensitive-value", finding.evidence)

    def test_host_cookie_prefix_violation_is_reported(self):
        response = HttpResponse("https://owned.example/", 200, {
            "content-type": "text/html",
            "set-cookie": "__Host-session=abc; Path=/login; Domain=owned.example"
        }, b"<html></html>", 0.1)
        titles = {finding.title for finding in inspect_http(response)}
        self.assertIn("Cookie '__Host-session' violates the __Host- prefix requirements", titles)

    def test_findings_include_detailed_fields_and_stable_id(self):
        response = HttpResponse("https://owned.example/", 200,
                                {"content-type": "text/html"}, b"<html></html>", 0.1)
        finding = next(f for f in inspect_http(response)
                       if f.title == "Content Security Policy is missing")
        data = finding.to_dict()
        self.assertTrue(data["finding_id"])
        self.assertTrue(data["description"])
        self.assertTrue(data["impact"])
        self.assertTrue(data["remediation_steps"])


if __name__ == "__main__":
    unittest.main()
