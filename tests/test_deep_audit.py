import unittest

from darthscanner.deep_audit import inspect_deep_patterns


class Response:
    status = 200
    url = "https://example.test/"
    headers = {"content-type": "text/html; charset=utf-8"}

    def __init__(self, body):
        self.body = body

    @property
    def text(self):
        return self.body


class DeepAuditTests(unittest.TestCase):
    def test_message_data_without_origin_check_is_low_confidence(self):
        body = """<script>
        window.addEventListener("message", function(event) {
            render(event.data);
        });
        </script>"""
        findings = inspect_deep_patterns(Response(body))
        item = next(x for x in findings if "origin validation" in x.title)
        self.assertEqual(item.confidence, "low")
        self.assertEqual(item.kind, "static-review-candidate")

    def test_message_handler_with_origin_check_is_not_flagged(self):
        body = """<script>
        window.addEventListener("message", function(event) {
            if (event.origin !== "https://trusted.example") return;
            render(event.data);
        });
        </script>"""
        findings = inspect_deep_patterns(Response(body))
        self.assertFalse(any("origin validation" in x.title for x in findings))

    def test_react_raw_html_is_reported_as_review_candidate(self):
        findings = inspect_deep_patterns(Response(
            "<script>const view = {dangerouslySetInnerHTML: {__html: value}};</script>"
        ))
        self.assertTrue(any("dangerouslySetInnerHTML" in x.title for x in findings))

    def test_api_documentation_is_discovered_but_not_fetched(self):
        findings = inspect_deep_patterns(Response(
            '<a href="/api/openapi.json">API docs</a>'
        ))
        item = next(x for x in findings if x.category == "api-discovery")
        self.assertIn("/api/openapi.json", item.evidence)

    def test_external_api_documentation_is_not_reported(self):
        findings = inspect_deep_patterns(Response(
            '<a href="https://other.example/swagger.json">API docs</a>'
        ))
        self.assertFalse(any(x.category == "api-discovery" for x in findings))

    def test_non_html_is_ignored(self):
        response = Response("<script>document.cookie</script>")
        response.headers = {"content-type": "application/json"}
        self.assertEqual(inspect_deep_patterns(response), [])


if __name__ == "__main__":
    unittest.main()
