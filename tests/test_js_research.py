import unittest

from darthscanner.js_research import extract_same_origin_script_urls, inspect_javascript_source


class Response:
    status = 200
    url = "https://example.test/app/"
    headers = {"content-type": "text/html; charset=utf-8"}

    def __init__(self, body):
        self.body = body

    @property
    def text(self):
        return self.body


class JavaScriptResearchTests(unittest.TestCase):
    def test_extracts_only_same_origin_script_urls(self):
        response = Response(
            '<script src="/assets/app.js"></script>'
            '<script src="https://cdn.example.net/lib.js"></script>'
            '<script src="/assets/app.js"></script>'
        )
        self.assertEqual(
            extract_same_origin_script_urls(response),
            ["https://example.test/assets/app.js"],
        )

    def test_ignores_malformed_script_url(self):
        response = Response('<script src="https://example.test:invalid/bad.js"></script>')
        self.assertEqual(extract_same_origin_script_urls(response), [])

    def test_finds_source_and_sink_candidate(self):
        findings = inspect_javascript_source(
            "https://example.test/app.js",
            "const value = location.hash; element.innerHTML = value;",
        )
        self.assertTrue(any("source and dangerous" in item.title for item in findings))
        self.assertTrue(all(item.confidence == "low" for item in findings))

    def test_traces_browser_input_variable_to_dom_sink(self):
        findings = inspect_javascript_source(
            "https://example.test/app.js",
            "const queryValue = location.search;\\n"
            "const safe = DOMPurify.sanitize(other);\\n"
            "element.innerHTML = queryValue;",
        )
        self.assertTrue(any("flows into a risky" in item.title for item in findings))

    def test_finds_message_listener_without_obvious_origin_check(self):
        findings = inspect_javascript_source(
            "https://example.test/app.js",
            "window.addEventListener('message', function(event) { render(event.data); });",
        )
        self.assertTrue(any("origin check" in item.title for item in findings))

    def test_finds_prototype_mutation_candidate(self):
        findings = inspect_javascript_source(
            "https://example.test/app.js",
            "target.__proto__ = source;",
        )
        self.assertTrue(any("prototype mutation" in item.title for item in findings))

    def test_traces_multiple_local_aliases_to_dom_sink(self):
        source = (
            "const first = window.location.search;\\n"
            "let second = first;\\n"
            "const third = second;\\n"
            "node.innerHTML = third;"
        )
        findings = inspect_javascript_source("https://example.test/app.js", source)
        self.assertTrue(any("reaches a risky" in item.title for item in findings))

    def test_sanitized_reassignment_breaks_simple_taint_chain(self):
        source = (
            "let value = location.hash;\\n"
            "value = DOMPurify.sanitize(value);\\n"
            "node.innerHTML = value;"
        )
        findings = inspect_javascript_source("https://example.test/app.js", source)
        self.assertFalse(any("reaches a risky" in item.title for item in findings))

    def test_recognizes_url_search_params_get_source(self):
        source = (
            "const value = new URLSearchParams(location.search).get('q');\\n"
            "node.insertAdjacentHTML('beforeend', value);"
        )
        findings = inspect_javascript_source("https://example.test/app.js", source)
        self.assertTrue(any("reaches a risky" in item.title for item in findings))

    def test_safe_text_content_is_not_a_risky_sink(self):
        source = "const value = location.hash; node.textContent = value;"
        findings = inspect_javascript_source("https://example.test/app.js", source)
        self.assertFalse(any("reaches a risky" in item.title for item in findings))

    def test_ignores_benign_javascript(self):
        self.assertEqual(
            inspect_javascript_source("https://example.test/app.js", "console.log('hello');"),
            [],
        )


if __name__ == "__main__":
    unittest.main()
