import unittest
from types import SimpleNamespace

from darthscanner.adaptive import choose_next_case


class FeedbackGuidedSchedulerTests(unittest.TestCase):
    def test_reflection_signal_prioritizes_encoding_family(self):
        cases = [
            ("boundary", "x", "boundary"),
            ("encoded", "%2f", "encoding"),
        ]
        observations = [
            SimpleNamespace(case_family="boundary", signal_types=["input-reflection"])
        ]
        self.assertEqual(choose_next_case(cases, observations), 2)

    def test_diagnostic_signal_prioritizes_structured_inputs(self):
        cases = [
            ("space", " x ", "whitespace"),
            ("json", '{"k":"v"}', "structured-type"),
            ("bool", "true", "boolean"),
        ]
        observations = [
            SimpleNamespace(case_family="boundary", signal_types=["new-diagnostic-signature"])
        ]
        self.assertEqual(choose_next_case(cases, observations), 1)

    def test_exploration_prefers_untried_family_after_no_signal(self):
        cases = [
            ("boundary-2", "y", "boundary"),
            ("unicode", "é", "unicode"),
        ]
        observations = [
            SimpleNamespace(case_family="boundary", signal_types=[])
        ]
        self.assertEqual(choose_next_case(cases, observations), 1)

    def test_empty_case_list_is_rejected(self):
        with self.assertRaises(ValueError):
            choose_next_case([], [])

    def test_tie_break_is_deterministic(self):
        cases = [("first", "a", "new"), ("second", "b", "new")]
        self.assertEqual(choose_next_case(cases, []), 0)


if __name__ == "__main__":
    unittest.main()
