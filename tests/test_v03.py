import csv
import tempfile
import unittest
from pathlib import Path

from darthscanner.checks import Finding
from darthscanner.exposure import probe_sensitive_paths
from darthscanner.fingerprint import fingerprint_response
from darthscanner.http_client import HttpResponse, SafeHttpClient
from darthscanner.method_checks import inspect_http_methods
from darthscanner.report import build_report, write_report_bundle
from darthscanner.scope import Scope


class _FakeHeadClient:
    def __init__(self, max_requests=10):
        self.max_requests = max_requests
        self.requests_made = 0
        self.urls = []

    def head(self, url):
        self.requests_made += 1
        self.urls.append(url)
        return HttpResponse(url, 200, {
            "content-type": "text/plain",
            "content-length": "123"
        }, b"", 0.01)


class _FakeOptionsClient:
    def __init__(self):
        self.requests_made = 0
        self.max_requests = 5
        self.called = []

    def options(self, url):
        self.called.append("OPTIONS")
        self.requests_made += 1
        return HttpResponse(url, 200, {"allow": "GET, HEAD, OPTIONS, TRACE, PUT"}, b"", 0.01)


class HttpClientHeadTests(unittest.TestCase):
    def test_head_does_not_read_any_response_body(self):
        class Response:
            status = 200
            headers = {"Content-Type": "text/plain"}
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, *args):
                raise AssertionError("HEAD response body must never be read")

        class Opener:
            def open(self, request, timeout):
                self.method = request.get_method()
                return Response()

        scope = Scope(True, ("owned.example",), request_delay_seconds=0.5)
        client = SafeHttpClient(scope)
        opener = Opener()
        client._opener = opener
        response = client.head("https://owned.example/.env")
        self.assertEqual(opener.method, "HEAD")
        self.assertEqual(response.body, b"")
        self.assertEqual(response.status, 200)


class ExposureTests(unittest.TestCase):
    def test_sensitive_paths_use_bounded_head_requests_only(self):
        scope = Scope(True, ("owned.example",), max_requests=3)
        client = _FakeHeadClient(max_requests=3)
        findings = probe_sensitive_paths("https://owned.example/app?x=1", scope, client, max_paths=2)
        self.assertEqual(client.requests_made, 2)
        self.assertTrue(all("/" in url for url in client.urls))
        self.assertEqual(len(findings), 2)
        self.assertTrue(all("No response body was requested" in item.evidence for item in findings))
        self.assertTrue(all(item.category == "exposure" for item in findings))


class HttpMethodTests(unittest.TestCase):
    def test_options_advertisements_are_reported_without_invoking_methods(self):
        scope = Scope(True, ("owned.example",))
        client = _FakeOptionsClient()
        findings = inspect_http_methods("https://owned.example/", scope, client)
        self.assertEqual(client.called, ["OPTIONS"])
        titles = {item.title for item in findings}
        self.assertIn("Server advertises the HTTP TRACE method", titles)
        self.assertIn("Server advertises the PUT method", titles)


class FingerprintExpansionTests(unittest.TestCase):
    def test_additional_server_software_is_fingerprinted(self):
        response = HttpResponse(
            "https://owned.example/",
            200,
            {"server": "Caddy/2.7.6", "x-powered-by": "Uvicorn/0.23.2"},
            b"",
            0.01,
        )
        names = {item.name for item in fingerprint_response(response)}
        self.assertIn("Caddy", names)
        self.assertIn("Uvicorn", names)


class ReportExportTests(unittest.TestCase):
    def test_finding_confidence_and_dedupe_ignore_query_string(self):
        low = Finding("web", "Test finding", "low", "low",
                      "https://owned.example/item?id=1", "Evidence A", "Fix it")
        high = Finding("web", "Test finding", "low", "high",
                       "https://owned.example/item?id=2", "Evidence B", "Fix it")
        self.assertEqual(low.finding_id, high.finding_id)
        report = build_report(target="https://owned.example", requests_made=2,
                              pages=[], findings=[low, high])
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["confidence_score"], 90)

    def test_html_dashboard_and_csv_export_are_written(self):
        finding = Finding(
            "web", "Unsafe <script> demo", "medium", "high",
            "https://owned.example/path", "Observed evidence",
            "Apply remediation",
            cwe_ids=["CWE-79"],
            cvss_score=6.5,
            cvss_version="3.1",
        )
        with tempfile.TemporaryDirectory() as tmp:
            json_path = str(Path(tmp) / "report.json")
            html_path = str(Path(tmp) / "report.html")
            csv_path = str(Path(tmp) / "findings.csv")
            write_report_bundle(
                json_path, html_path, csv_path,
                target="https://owned.example", requests_made=1,
                pages=[], findings=[finding],
            )
            html = Path(html_path).read_text(encoding="utf-8")
            self.assertIn('id="severity"', html)
            self.assertIn('id="cwe"', html)
            self.assertIn('id="cvss"', html)
            self.assertNotIn("Unsafe <script> demo", html)
            with Path(csv_path).open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["cwe_ids"], "CWE-79")
            self.assertEqual(rows[0]["cvss_score"], "6.5")


if __name__ == "__main__":
    unittest.main()
