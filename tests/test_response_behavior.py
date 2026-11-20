import unittest

from darthscanner.http_client import HttpResponse
from darthscanner.response_audit import inspect_response_behavior


def response(body, content_type="application/json", status=200):
    return HttpResponse(
        "https://owned.example/api", status,
        {"content-type": content_type}, body, 0.01,
    )


class ResponseBehaviorTests(unittest.TestCase):
    def test_duplicate_json_members_are_reported(self):
        findings = inspect_response_behavior(response(b'{"role":"user","role":"admin"}'))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "parser-ambiguity")
        self.assertEqual(findings[0].severity, "medium")
        self.assertNotIn("admin", findings[0].evidence)

    def test_html_body_with_json_media_type_is_reported(self):
        findings = inspect_response_behavior(response(
            b"<!doctype html><html><body>fallback</body></html>"
        ))
        self.assertEqual(findings[0].kind, "protocol-inconsistency")

    def test_malformed_json_is_reported(self):
        findings = inspect_response_behavior(response(b'{"broken":'))
        self.assertTrue(any("not valid UTF-8 JSON" in item.title for item in findings))

    def test_non_success_malformed_json_is_not_reported(self):
        findings = inspect_response_behavior(response(b'not-json', status=500))
        self.assertEqual(findings, [])

    def test_no_body_is_ignored(self):
        item = HttpResponse("https://owned.example/", 200, {}, b"", 0.01)
        self.assertEqual(inspect_response_behavior(item), [])

    def test_html_label_with_json_body_is_informational(self):
        findings = inspect_response_behavior(response(b'{"ok":true}', "text/html"))
        self.assertEqual(findings[0].severity, "info")


if __name__ == "__main__":
    unittest.main()
