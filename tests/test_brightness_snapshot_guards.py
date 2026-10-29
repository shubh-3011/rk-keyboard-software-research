"""Offline guard contracts for the installed 4.06 scalar observer."""
import pathlib
import unittest


class BrightnessSnapshotGuards(unittest.TestCase):
    def test_loaded_and_constructor_scalars_remain_distinct(self):
        source = (pathlib.Path(__file__).resolve().parents[1] /
                  'scripts/snapshot_rk406_brightness_mapping.js').read_text(encoding='utf-8')
        self.assertIn("[0x4513fb, '893d5c176100', [2]]", source)
        self.assertIn("[0x424aea, '8b0d5c176100', [2]]", source)
        self.assertIn('const loaded = imageSource(0x61175c, 4).readU32()', source)
        self.assertIn('const scan = imageSource(0x61158e, 2).readU16()', source)
        self.assertIn('loaded === 0 || loaded > 0xffff', source)
        self.assertLess(source.index('loaded === 0 || loaded > 0xffff'), source.index('const config ='))
        self.assertIn('imageSource(0x61175c, 4).readU32() !== loaded', source)
        self.assertIn('imageSource(0x61158e, 2).readU16() !== scan', source)
        self.assertIn('loaded_profile_code_hex:', source)
        self.assertIn('constructor_scan_code_hex:', source)
        self.assertNotIn('\n            profile_code:', source)
        self.assertIn('does not prove physical model, INI contents or endpoint binding', source)


if __name__ == '__main__':
    unittest.main()
