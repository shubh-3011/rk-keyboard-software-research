import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


def payload(name, kind):
    record = json.loads((ROOT / 'docs/runtime-evidence' / name).read_text(encoding='utf-8-sig'))
    if record['cleanup_error'] is not None:
        raise ValueError('Observation cleanup failed')
    messages = record['evidence']['normalized_result']['messages']
    if any(message.get('type') == 'error' for message in messages):
        raise ValueError('Observation script failed')
    matches = [message['payload'] for message in messages
               if message.get('type') == 'send' and message.get('payload', {}).get('kind') == kind]
    if len(matches) != 1:
        raise ValueError('Expected one bounded scalar observation')
    return matches[0]


class LoadedProfileScalarTests(unittest.TestCase):
    def test_separate_scalars_not_interchangeable(self):
        result = payload('rk406-loaded-profile-2026-10-27.json', 'bounded_loaded_profile_scalars')
        self.assertEqual(result['loaded_profile_code_hex'], '01AF')
        self.assertEqual(result['constructor_scan_code_hex'], '023D')
        self.assertEqual(result['instruction_witnesses_checked'], 6)
        self.assertEqual(result['device_commands_issued_by_script'], 0)
        self.assertEqual(result['vendor_functions_called_by_script'], 0)

    def test_old_mapping_field_keeps_historical_meaning(self):
        result = payload('rk406-wired-brightness-mapping-2026-10-27.json', 'bounded_brightness_mapping')
        self.assertEqual(result['profile_code'], '023D')
        self.assertEqual(result['mapping_dwords_24'], [0] * 24)
        self.assertEqual(result['selected_brightness']['index'], 5)
        self.assertEqual(result['selected_brightness']['light_hw_byte'], 20)
        self.assertEqual(result['selected_ordinal'], result['rgb_off_index'])
        self.assertEqual(result['device_commands_issued_by_script'], 0)

    def test_scalar_probe_has_no_mutation_or_transport_api(self):
        script = (ROOT / 'scripts/snapshot_rk406_loaded_profile.js').read_text()
        for pattern in (r'Interceptor\.', r'NativeFunction\(', r'\.write(?:U\d+|Pointer|ByteArray)\(', r'Memory\.write', r'HidD_'):
            self.assertIsNone(re.search(pattern, script))
        self.assertIn('source(0x61175c, 4).readU32()', script)
        self.assertIn('source(0x61158e, 2).readU16()', script)
        self.assertIn('hostSha !== expected', script)


if __name__ == '__main__':
    unittest.main()
