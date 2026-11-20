import unittest

from darthscanner.watch import PROFILES, profile_for_cycle


class WatchProfileTests(unittest.TestCase):
    def test_profiles_rotate_without_repeating_adjacent_categories(self):
        observed = [profile_for_cycle(index) for index in range(8)]
        self.assertEqual(observed, list(PROFILES) * 2)
        self.assertTrue(all(observed[index] != observed[index + 1] for index in range(len(observed) - 1)))

    def test_cycle_must_be_non_negative(self):
        with self.assertRaises(ValueError):
            profile_for_cycle(-1)


if __name__ == "__main__":
    unittest.main()
