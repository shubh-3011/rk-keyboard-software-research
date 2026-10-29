import unittest

from scripts.rk406_brightness_candidate import ordinary_candidate_offset, compare_candidate


class BrightnessCandidateTests(unittest.TestCase):
    def inputs(self, **overrides):
        values = dict(row=0, row_count=19, led_mask=0, mapping_gate_sum=0, special_row=17, selected_row=0)
        values.update(overrides)
        return values

    def test_ordinary_row_offsets_and_special_row(self):
        for row in range(19):
            if row == 17:
                with self.assertRaises(ValueError): ordinary_candidate_offset(**self.inputs(row=row))
            else:
                self.assertEqual(0x3a + row * 2, ordinary_candidate_offset(**self.inputs(row=row)))

    def test_unobserved_branches_rejected(self):
        for changes in ({'row': 19}, {'row': -1}, {'row_count': 25}, {'row_count': 0},
                        {'led_mask': 1}, {'led_mask': -1}, {'mapping_gate_sum': 1},
                        {'mapping_gate_sum': -1}, {'special_row': 24}, {'selected_row': 17},
                        {'selected_row': 19}, {'row': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                ordinary_candidate_offset(**self.inputs(**changes))

    def test_differences_and_restoration_are_independent(self):
        baseline = bytes(126) + b'\x5a\xa5'
        changed = bytearray(baseline)
        changed[0x3a] = 4
        result = compare_candidate(baseline, bytes(changed), baseline, **self.inputs())
        self.assertTrue(result['only_candidate_changed'])
        self.assertTrue(result['exact_block_restored'])
        self.assertFalse(result['hardware_write_authorized'])
        changed[3] = 2
        result = compare_candidate(baseline, bytes(changed), bytes(changed), **self.inputs())
        self.assertFalse(result['only_candidate_changed'])
        self.assertFalse(result['exact_block_restored'])
        self.assertFalse(result['hardware_write_authorized'])

    def test_noop_and_bad_blocks_rejected_or_not_evidence(self):
        baseline = bytes(126) + b'\x5a\xa5'
        self.assertFalse(compare_candidate(baseline, baseline, baseline, **self.inputs())['only_candidate_changed'])
        for bad in (b'', bytes(128), bytearray(baseline)):
            with self.assertRaises(ValueError): compare_candidate(baseline, bad, baseline, **self.inputs())


if __name__ == '__main__':
    unittest.main()
