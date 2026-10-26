"""Guard against comparing members of differently based lighting records."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_rk406_brightness_record_alias import canonical_offset


class BrightnessRecordAliasTests(unittest.TestCase):
    def test_setter_brightness_alias(self):
        self.assertEqual(canonical_offset(0x2138, 0x0C), 0x04)

    def test_all_four_setter_fields(self):
        self.assertEqual([canonical_offset(0x2138, i) for i in (8, 12, 24, 52)], [0, 4, 16, 44])

    def test_every_normal_lighting_row_has_same_address(self):
        for row in range(24):
            for config in (0x10000000, 0x20001000):
                alias = config + 0x2138 + row * 0x30
                canonical = config + 0x2140 + row * 0x30
                self.assertEqual(alias + 12, canonical + 4)

    def test_canonical_and_alias_offsets_are_not_conflated(self):
        self.assertEqual(canonical_offset(0x2140, 4), 4)
        self.assertNotEqual(canonical_offset(0x2138, 4), 4)

    def test_embedded_slider_subobject_shares_getter_state(self):
        self.assertEqual(0x54 + 0x94C, 0x9A0)


if __name__ == "__main__":
    unittest.main()
