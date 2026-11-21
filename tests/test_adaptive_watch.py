import unittest

from darthscanner.watch import (
    FOCUSES,
    choose_next_focus,
    eligible_focuses,
)


class AdaptiveWatchTests(unittest.TestCase):
    def test_svg_skips_html_cookie_cors_and_javascript_checks(self):
        report = {
            "pages": [{
                "resource_type": "svg",
                "content_type": "image/svg+xml",
                "status": 200,
                "has_set_cookie": False,
                "has_cors_headers": False,
                "has_redirect": False,
                "script_count": 0,
            }]
        }
        self.assertEqual(eligible_focuses(report), ["headers", "fingerprint"])

    def test_html_enables_html_browser_and_script_review(self):
        report = {
            "pages": [{
                "resource_type": "html",
                "content_type": "text/html",
                "status": 200,
                "has_set_cookie": True,
                "has_cors_headers": True,
                "has_redirect": False,
                "script_count": 2,
            }]
        }
        self.assertEqual(
            eligible_focuses(report),
            ["headers", "cookies", "cors", "html", "browser", "javascript", "fingerprint"],
        )

    def test_scheduler_chooses_uncompleted_focus_first(self):
        eligible = ["headers", "html", "browser", "fingerprint"]
        self.assertEqual(choose_next_focus(eligible, ["headers"]), "html")
        self.assertEqual(choose_next_focus(eligible, ["headers", "html"]), "browser")

    def test_scheduler_starts_new_round_after_all_checks(self):
        eligible = ["headers", "fingerprint"]
        self.assertEqual(choose_next_focus(eligible, ["headers", "fingerprint"]), "headers")

    def test_empty_report_uses_safe_web_fallback(self):
        self.assertEqual(eligible_focuses({"pages": []}), ["headers", "fingerprint"])


if __name__ == "__main__":
    unittest.main()
