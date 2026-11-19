import unittest

from darthscanner.checks import inspect_http


class Response:
    def __init__(self, url, headers, status=200, body=b""):
        self.url = url
        self.headers = {key.lower(): value for key, value in headers.items()}
        self.status = status
        self.body = body
        self.elapsed_seconds = 0.01

    @property
    def text(self):
        return self.body.decode("utf-8", errors="replace")


class MicroHttpAuditTests(unittest.TestCase):
    def test_flags_shared_cache_on_sensitive_route(self):
        response = Response(
            "https://app.example/account/profile",
            {"content-type": "application/json", "cache-control": "public, s-maxage=600"},
        )
        findings = inspect_http(response)
        candidate = next(item for item in findings if item.title == "Sensitive-looking route permits shared caching")
        self.assertEqual(candidate.severity, "medium")
        self.assertIn("s-maxage", candidate.evidence)

    def test_does_not_flag_private_or_no_store_sensitive_response(self):
        for policy in ("private, max-age=60", "no-store"):
            response = Response(
                "https://app.example/account/profile",
                {"content-type": "application/json", "cache-control": policy},
            )
            findings = inspect_http(response)
            self.assertFalse(any(item.title == "Sensitive-looking route permits shared caching" for item in findings))

    def test_does_not_flag_public_cache_on_non_sensitive_route(self):
        response = Response(
            "https://app.example/catalog",
            {"content-type": "application/json", "cache-control": "public, s-maxage=600"},
        )
        findings = inspect_http(response)
        self.assertFalse(any(item.title == "Sensitive-looking route permits shared caching" for item in findings))

    def test_flags_concrete_cors_origin_without_vary_origin(self):
        response = Response(
            "https://app.example/api/profile",
            {"access-control-allow-origin": "https://portal.example"},
        )
        findings = inspect_http(response)
        self.assertTrue(any(item.title == "Origin-specific CORS response does not declare Vary: Origin" for item in findings))

    def test_accepts_vary_origin_case_insensitively(self):
        response = Response(
            "https://app.example/api/profile",
            {"access-control-allow-origin": "https://portal.example", "vary": "Accept-Encoding, ORIGIN"},
        )
        findings = inspect_http(response)
        self.assertFalse(any(item.title == "Origin-specific CORS response does not declare Vary: Origin" for item in findings))

    def test_does_not_flag_wildcard_cors_for_missing_vary(self):
        response = Response(
            "https://app.example/public-data",
            {"access-control-allow-origin": "*"},
        )
        findings = inspect_http(response)
        self.assertFalse(any(item.title == "Origin-specific CORS response does not declare Vary: Origin" for item in findings))


if __name__ == "__main__":
    unittest.main()
