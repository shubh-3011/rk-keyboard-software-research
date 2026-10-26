import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from extract_rk406_lighting_fixture import extract


class LightingFixtureExtractorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = ROOT / 'docs/runtime-evidence/rk406-wireless-lighting-roundtrip-frida-2026-10-26.json'
        cls.source = json.loads(cls.path.read_text(encoding='utf-8'))

    def reject(self, mutate):
        source = copy.deepcopy(self.source)
        mutate(source)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'trace.json'
            path.write_text(json.dumps(source), encoding='utf-8')
            with self.assertRaises(ValueError):
                extract(path)

    def test_committed_fixture_is_exactly_reproducible(self):
        expected = json.loads((ROOT / 'rebuild/windows/tests/fixtures/rk406-wireless-lighting-roundtrip.json').read_text(encoding='utf-8'))
        self.assertEqual(extract(self.path), expected)

    def test_wrong_executable_is_not_attributed(self):
        self.reject(lambda source: source.update(binary_sha256='0' * 64))

    def test_failed_ui_restoration_is_rejected(self):
        self.reject(lambda source: source.update(restored_tree_selection=False))

    def test_dropped_records_are_rejected(self):
        self.reject(lambda source: source['observation_summary'].update(dropped=1))

    def test_script_errors_are_rejected(self):
        self.reject(lambda source: source['events'].append({'type': 'error', 'description': 'synthetic'}))

    def test_frame_mutation_is_rejected(self):
        def mutate(source):
            report = next(event['payload'] for event in source['events'] if event.get('payload', {}).get('kind') == 'lighting_report' and event['payload']['command'] == 4)
            report['bytes'][5] ^= 1
        self.reject(mutate)


if __name__ == '__main__':
    unittest.main()
