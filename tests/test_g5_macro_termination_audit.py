import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import audit_rk406_g5_macro_termination as audit


class FakePe:
    def __init__(self, data, fast_load):
        self.OPTIONAL_HEADER = type('Header', (), {'ImageBase': 0x400000})()

    def get_offset_from_rva(self, rva):
        return rva


class MacroTerminationAuditTests(unittest.TestCase):
    def test_all_witnesses_checked_even_if_digest_is_replaced(self):
        data = bytearray(0x11200)
        for address, expected in audit.WITNESSES.items():
            raw = bytes.fromhex(expected)
            offset = address - 0x400000
            data[offset:offset + len(raw)] = raw
        with patch.object(audit.pefile, 'PE', FakePe):
            with patch.object(audit, 'SHA', hashlib.sha256(data).hexdigest()):
                self.assertEqual(audit.verify(data), 91)
            for address in audit.WITNESSES:
                changed = bytearray(data)
                changed[address - 0x400000] ^= 1
                with patch.object(audit, 'SHA', hashlib.sha256(changed).hexdigest()):
                    with self.assertRaisesRegex(ValueError, 'Instruction witness mismatch'):
                        audit.verify(changed)

    def test_unknown_binary_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            audit.verify(b'not the target')


if __name__ == '__main__':
    unittest.main()
