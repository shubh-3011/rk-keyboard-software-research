from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from rk_lighting_tree_guard import validate_tree


class LightingTreeGuardTests(unittest.TestCase):
    def test_observed_tree_shapes(self):
        for count in (19, 20):
            validate_tree(list(range(1, count + 1)), 19, 0, 36)

    def test_profile_tree_never_passes(self):
        with self.assertRaises(ValueError):
            validate_tree([10, 20, 30], 30, 0, 36)

    def test_wrong_selection_never_passes(self):
        with self.assertRaises(ValueError):
            validate_tree(list(range(1, 20)), 1, 0, 36)

    def test_unbounded_or_corrupt_tree_never_passes(self):
        for count in (0, 1, 18, 21, 25):
            with self.assertRaises(ValueError):
                validate_tree(list(range(1, count + 1)), 19, 0, 36)
        for items, tail, height in (([1] * 19, 0, 36), (list(range(19)), 0, 36), (list(range(1, 20)), 20, 36), (list(range(1, 20)), 0, 0)):
            with self.assertRaises(ValueError):
                validate_tree(items, 19, tail, height)


if __name__ == '__main__':
    unittest.main()
