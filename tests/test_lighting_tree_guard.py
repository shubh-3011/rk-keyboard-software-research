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

    def test_optional_capture_is_inside_restoration_scope(self):
        source = (Path(__file__).resolve().parents[1] / 'scripts' / 'run_rk406_lighting_roundtrip.py').read_text(encoding='utf-8')
        self.assertIn('(args.capture_first_effect is not None or args.inspect_brightness_hit) and args.main_hwnd is None', source)
        self.assertIn('args.capture_first_effect.exists()', source)
        capture = source.index("capture = Path(__file__).with_name('capture_rk_window.ps1')")
        changed = source.index('changed = True')
        restoration = source.index('finally:\n        if changed:', changed)
        self.assertLess(changed, capture)
        self.assertLess(capture, restoration)
        self.assertIn('check=True, timeout=15', source[capture:restoration])
        self.assertIn('select(original)', source[restoration:])

    def test_hit_probe_is_passive_and_inside_restoration_scope(self):
        source = (Path(__file__).resolve().parents[1] / 'scripts' / 'run_rk406_lighting_roundtrip.py').read_text(encoding='utf-8')
        preflight = source.index('    if args.inspect_brightness_hit:')
        selection = source.index('        if not select(first):')
        self.assertLess(preflight, selection)
        self.assertIn('user.IsWindowVisible(main)', source[preflight:selection])
        self.assertIn('user.GetAncestor(hwnd, 2) != main.value', source[preflight:selection])
        start = source.index('        if args.inspect_brightness_hit:')
        end = source.index('    except Exception as error:', start)
        probe = source[start:end]
        self.assertIn('WindowFromPoint', probe)
        self.assertIn('hit_owner.value != args.pid', probe)
        self.assertIn('user.GetAncestor(hit, 2) != main.value', probe)
        self.assertIn('(1500, 900)', probe)
        self.assertIn("'click_sent': False", probe)
        self.assertNotIn('PostMessageW', probe)
        self.assertIn('select(original)', source[end:])


if __name__ == '__main__':
    unittest.main()
