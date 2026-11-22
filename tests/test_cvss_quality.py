import unittest

from darthscanner.cvss_quality import calculate_cvss31, validate_cvss_metric


class CvssQualityTests(unittest.TestCase):
    def test_known_critical_vector(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self.assertEqual(calculate_cvss31(vector), 9.8)

    def test_known_scope_changed_vector(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        self.assertEqual(calculate_cvss31(vector), 10.0)

    def test_published_score_vector_consistency(self):
        result = validate_cvss_metric(9.8, "3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(result["status"], "consistent")

    def test_mismatch_is_reported_not_silently_rewritten(self):
        result = validate_cvss_metric(8.8, "3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(result["status"], "score-vector-mismatch")
        self.assertEqual(result["published_score"], 8.8)
        self.assertEqual(result["calculated_score"], 9.8)

    def test_cvss_4_is_preserved_without_fake_recalculation(self):
        result = validate_cvss_metric(9.3, "4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
        self.assertEqual(result["status"], "published-cvss-4.0")
        self.assertIsNone(result["calculated_score"])

    def test_incomplete_vector_rejected(self):
        with self.assertRaises(ValueError):
            calculate_cvss31("CVSS:3.1/AV:N/AC:L")


if __name__ == "__main__":
    unittest.main()
