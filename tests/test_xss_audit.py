import unittest

from darthscanner.xss_audit import inspect_html_xss, inspect_javascript_xss


class XssAuditTests(unittest.TestCase):
    def test_traces_location_to_inner_html(self):
        findings = inspect_javascript_xss(
            "https://example.test/app.js",
            "const input = window.location.hash;\nnode.innerHTML = input;",
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("innerHTML", findings[0].title)
        self.assertEqual(findings[0].kind, "source-to-sink-candidate")

    def test_traces_multiple_local_aliases(self):
        findings = inspect_javascript_xss(
            "https://example.test/app.js",
            "const first = new URLSearchParams(location.search).get('q');\n"
            "let second = first;\nnode.insertAdjacentHTML('beforeend', second);",
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("insertAdjacentHTML", findings[0].title)

    def test_direct_source_to_document_write(self):
        findings = inspect_javascript_xss(
            "https://example.test/app.js",
            "document.write(location.hash);",
        )
        self.assertEqual(len(findings), 1)

    def test_sanitized_value_is_not_reported(self):
        findings = inspect_javascript_xss(
            "https://example.test/app.js",
            "const input = location.search;\n"
            "const clean = DOMPurify.sanitize(input);\n"
            "node.innerHTML = clean;",
        )
        self.assertEqual(findings, [])

    def test_text_content_is_not_a_dangerous_sink(self):
        findings = inspect_javascript_xss(
            "https://example.test/app.js",
            "const input = location.hash;\nnode.textContent = input;",
        )
        self.assertEqual(findings, [])

    def test_unrelated_source_and_sink_do_not_create_dataflow(self):
        findings = inspect_javascript_xss(
            "https://example.test/app.js",
            "const input = location.hash;\nnode.innerHTML = fixedMarkup;",
        )
        self.assertEqual(findings, [])

    def test_comments_do_not_create_source_or_sink(self):
        findings = inspect_javascript_xss(
            "https://example.test/app.js",
            "// node.innerHTML = location.hash;\nconst safe = 'plain';",
        )
        self.assertEqual(findings, [])

    def test_reflected_value_in_inline_script_is_reported_without_value(self):
        findings = inspect_html_xss(
            "https://example.test/search?q=needle-value",
            "<html><script>const term = 'needle-value';</script></html>",
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("inline script", findings[0].evidence)
        self.assertNotIn("needle-value", findings[0].evidence)

    def test_reflected_value_in_event_attribute_is_reported(self):
        findings = inspect_html_xss(
            "https://example.test/?q=needle-value",
            '<button onclick="run(\'needle-value\')">Go</button>',
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("event-handler", findings[0].evidence)

    def test_secret_query_parameters_are_not_retained_or_analyzed(self):
        findings = inspect_html_xss(
            "https://example.test/?access_token=secret-value",
            "<script>const token = 'secret-value';</script>",
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
