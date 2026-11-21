import unittest

from darthscanner.watch import (
    PROFILES,
    choose_next_focus,
    discover_signals,
    eligible_focuses,
    profile_for_cycle,
)


class WatchProfileTests(unittest.TestCase):
    def test_legacy_profile_helper_remains_deterministic(self):
        observed = [profile_for_cycle(index) for index in range(16)]
        self.assertEqual(observed, list(PROFILES) * 2)

    def test_cycle_must_be_non_negative(self):
        with self.assertRaises(ValueError):
            profile_for_cycle(-1)
        with self.assertRaises(ValueError):
            choose_next_focus(["headers"], [], -1)

    def test_svg_response_only_enables_relevant_checks(self):
        report = {"pages": [{
            "content_type": "image/svg+xml",
            "resource_type": "svg",
            "status": 200,
            "has_set_cookie": False,
            "has_cors_headers": False,
            "has_redirect": False,
            "script_count": 0,
        }]}
        self.assertEqual(eligible_focuses(report), ["headers", "fingerprint"])
        self.assertIn("svg_content", discover_signals(report))

    def test_html_with_scripts_and_cookie_enables_dependent_checks(self):
        report = {"pages": [{
            "content_type": "text/html; charset=utf-8",
            "resource_type": "html",
            "status": 200,
            "has_set_cookie": True,
            "has_cors_headers": True,
            "has_redirect": False,
            "script_count": 3,
        }]}
        self.assertEqual(
            eligible_focuses(report),
            ["headers", "cookies", "cors", "html", "browser", "javascript", "fingerprint"],
        )
        self.assertEqual(
            set(discover_signals(report)),
            {"cookie_present", "cors_present", "html_present", "scripts_present", "resource:html"},
        )

    def test_untried_applicable_focus_beats_repeated_unproductive_focus(self):
        history = {
            "focus_stats": {
                "headers": {"attempts": 4, "finding_count": 0, "empty_runs": 4},
                "javascript": {"attempts": 0, "finding_count": 0, "empty_runs": 0},
            }
        }
        self.assertEqual(
            choose_next_focus(["headers", "javascript"], [], history=history),
            "javascript",
        )

    def test_discovery_evidence_changes_choice(self):
        history = {
            "focus_stats": {
                "headers": {"attempts": 1, "finding_count": 0, "empty_runs": 1},
                "cookies": {"attempts": 1, "finding_count": 0, "empty_runs": 1},
            }
        }
        chosen = choose_next_focus(
            ["headers", "cookies"], [],
            history=history, signals=["cookie_present"],
        )
        self.assertEqual(chosen, "cookies")

    def test_completed_checks_are_deferred_until_round_resets(self):
        self.assertEqual(
            choose_next_focus(["headers", "cookies"], ["headers"], history={}),
            "cookies",
        )


if __name__ == "__main__":
    unittest.main()
