import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from verify_native_lighting_roundtrip import validate


class NativeLightingRoundtripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads((ROOT / 'docs/runtime-evidence/native-verified-lighting-mode-roundtrip-2026-10-26.json').read_text(encoding='utf-8'))

    def reject(self, mutate):
        record = copy.deepcopy(self.record)
        mutate(record)
        with self.assertRaises(ValueError):
            validate(record)

    def test_retained_native_roundtrip_validates(self):
        self.assertTrue(validate(self.record))

    def test_failed_transaction_is_not_independent_success(self):
        self.reject(lambda r: r['On']['summary'].update(ApplyExit=1))

    def test_failed_verification_is_rejected(self):
        self.reject(lambda r: r['Off']['apply'].update(VerifiedByQuery=False))

    def test_noop_is_not_counted_as_write_test(self):
        self.reject(lambda r: r['On']['apply'].update(NoOp=True))

    def test_changed_unrelated_byte_is_rejected(self):
        def mutate(r):
            block = bytearray.fromhex(r['Off']['after']['LightingBlockHex'])
            block[31] ^= 1
            r['Off']['after']['LightingBlockHex'] = block.hex().upper()
        self.reject(mutate)

    def test_mixed_builds_are_rejected(self):
        self.reject(lambda r: r['Off']['summary'].update(AppAssemblySha256='0' * 64))


if __name__ == '__main__':
    unittest.main()
