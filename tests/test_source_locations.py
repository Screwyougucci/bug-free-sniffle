import unittest

from darthscanner.checks import inspect_http
from darthscanner.http_client import HttpResponse


class SourceLocationTests(unittest.TestCase):
    def test_debug_finding_points_to_response_line_and_url(self):
        body = (
            b"<html>\n<body>\n"
            b"Traceback (most recent call last):\n"
            b"  File \"/srv/app.py\", line 42, in handler\n"
            b"</body>\n</html>"
        )
        response = HttpResponse(
            url="https://owned.example/error",
            status=500,
            headers={"content-type": "text/html; charset=utf-8"},
            body=body,
            elapsed_seconds=0.12,
        )
        findings = inspect_http(response)
        finding = next(item for item in findings if item.category == "debug")
        self.assertEqual(finding.source_url, response.url)
        self.assertEqual(finding.source_kind, "HTML response source")
        self.assertEqual(finding.source_line, 3)
        self.assertIn("Traceback", finding.source_excerpt)


if __name__ == "__main__":
    unittest.main()
