import unittest

from darthscanner.browser_audit import inspect_browser_code


class Response:
    status = 200
    url = "https://example.test/"
    headers = {"content-type": "text/html; charset=utf-8"}

    def __init__(self, body):
        self.body = body

    @property
    def text(self):
        return self.body


class BrowserAuditTests(unittest.TestCase):
    def test_finds_inline_event_handler_without_recording_value(self):
        findings = inspect_browser_code(Response('<button onclick="secretValue()">Go</button>'))
        self.assertTrue(any(item.category == "xss-indicator" for item in findings))
        self.assertNotIn("secretValue", " ".join(item.evidence for item in findings))

    def test_finds_javascript_url(self):
        findings = inspect_browser_code(Response('<a href="javascript:run()">click</a>'))
        self.assertTrue(any("javascript: URL" in item.title for item in findings))

    def test_flags_source_and_sink_cooccurrence_as_low_confidence(self):
        body = '<script>const x = location.hash; document.body.innerHTML = x;</script>'
        findings = inspect_browser_code(Response(body))
        candidate = next(item for item in findings if "source-and-sink" in item.title)
        self.assertEqual(candidate.confidence, "low")
        self.assertEqual(candidate.kind, "static-review-candidate")

    def test_does_not_flag_unrelated_script(self):
        findings = inspect_browser_code(Response('<script>console.log("hello")</script>'))
        self.assertEqual(findings, [])

    def test_ignores_non_html(self):
        response = Response('<script>location.hash; document.write("x")</script>')
        response.headers = {"content-type": "application/json"}
        self.assertEqual(inspect_browser_code(response), [])


if __name__ == "__main__":
    unittest.main()
