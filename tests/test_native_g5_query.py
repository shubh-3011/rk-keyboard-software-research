import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from run_native_g5_lighting_check import validate_query_report


class NativeG5QueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = ROOT / 'docs/runtime-evidence/native-g5-published-query-2026-10-27.json'
        cls.report = json.loads(cls.path.read_text(encoding='utf-8'))

    def reject(self, **fields):
        report = copy.deepcopy(self.report)
        report.update(fields)
        with self.assertRaises(ValueError):
            validate_query_report(report)

    def test_live_query_record_and_source_digest(self):
        self.assertEqual(len(validate_query_report(self.report)), 128)
        summary = json.loads((ROOT / 'docs/runtime-evidence/native-g5-published-query-check-2026-10-27.json').read_text())
        self.assertTrue(summary['ValidatedQueryResult'])
        self.assertEqual(summary['ExitCode'], 0)
        self.assertEqual(summary['QueryReportSha256'], hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_query_scope_cannot_be_relabelled(self):
        for fields in ({'SettingsWritesPerformed': True}, {'SetFeatureCalls': 2}, {'GetFeatureCalls': 2},
                       {'FeatureReportBytes': 1032}, {'QueryCommand': '04'}, {'UsagePage': '0001'}, {'ReportIdHex': '00'}):
            self.reject(**fields)

    def test_signature_and_report_header_required(self):
        self.reject(LightingBlockHex='00' * 128)
        self.reject(ResponseHeaderHex='0904000001008000')
        self.reject(ResponseHeaderHex='0984')


if __name__ == '__main__':
    unittest.main()
