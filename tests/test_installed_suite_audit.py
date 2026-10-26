"""Offline audit regression tests; synthetic bytes only, no installed files."""
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_installed_suite import group_for, indexed, resource_summary, safe_relative, xml_shape


class InstalledSuiteAuditTests(unittest.TestCase):
    def test_windows_paths_are_bounded(self):
        for path in ("../secret", "Dev/../../secret", "C:/file", "C:file", "\\root", "//host/share", "file:stream", ""):
            with self.subTest(path=path), self.assertRaises(ValueError):
                safe_relative(path)
        self.assertEqual(safe_relative("Dev\\01AF\\KB.ini"), "Dev/01AF/KB.ini")

    def test_duplicate_ledger_keys_are_not_lost(self):
        with self.assertRaises(ValueError):
            indexed([{"path": "A"}, {"path": "a"}], ("path",))

    def test_reject_unclassified_paths(self):
        with self.assertRaises(ValueError):
            group_for("new-component/new-file.txt")

    def test_resource_roles_remain_distinct(self):
        self.assertEqual(group_for("Dev/en/led.xml"), "Generic localized LED dictionaries")
        self.assertEqual(group_for("Dev/01AF/en/led.xml"), "Profile-localized LED dictionaries")
        self.assertEqual(group_for("Dev/01AF/Update.exe"), "Per-profile updater executable")
        self.assertEqual(group_for("Dev/01AF/ET/1.txt"), "Per-profile ET/Cartoon pattern files")

    def test_only_known_japanese_defect_is_normalized(self):
        raw = b"<root><tc_screen1>test/tc_screen1></root>"
        shape = xml_shape(raw, "Text/Japanese/text.xml")
        self.assertIn("malformed", shape["raw_status"])
        self.assertEqual(shape["unique_leaf_count"], 1)
        self.assertEqual(raw, b"<root><tc_screen1>test/tc_screen1></root>")
        for path in ("Text/en/text.xml", "Dev/Japanese/led.xml"):
            with self.assertRaises(ValueError):
                xml_shape(raw, path)
        with self.assertRaises(ValueError):
            xml_shape(b"<root><broken></root>", "Text/Japanese/text.xml")

    def evidence(self):
        data = b"synthetic-only"
        digest = hashlib.sha256(data).hexdigest()
        return data, {"operation": "inspect_pe_resources", "evidence_id": "synthetic",
                      "subject": {"digest": {"sha256": digest}}, "provider": {"id": "test"},
                      "limitations": ["synthetic test only"], "normalized_result": {
                          "artifact": {"sha256": digest, "bytes": len(data)},
                          "coverage": {"status": "complete", "resources": 1},
                          "resources": [{"type": {"id": 10}, "payload": {
                              "location": {"offset": 0, "bytes": len(data)}, "sha256": digest}}]}}

    def test_resource_hash_is_verified(self):
        data, record = self.evidence()
        self.assertEqual(resource_summary(record, data)["resource_count"], 1)
        record["normalized_result"]["resources"][0]["payload"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            resource_summary(record, data)

    def test_resource_range_is_verified(self):
        for offset, size in ((-1, 2), (0, -1), (0, 100), (100, 0)):
            data, record = self.evidence()
            record["normalized_result"]["resources"][0]["payload"]["location"] = {"offset": offset, "bytes": size}
            with self.subTest(offset=offset, size=size), self.assertRaises(ValueError):
                resource_summary(record, data)

    def test_subject_operation_coverage_and_count_fail_closed(self):
        for target, key, value in (("subject", "sha256", "bad"), ("operation", "operation", "other"),
                                   ("coverage", "status", "partial"), ("coverage", "resources", 2)):
            data, record = self.evidence()
            if target == "subject":
                record["subject"]["digest"][key] = value
            elif target == "operation":
                record[key] = value
            else:
                record["normalized_result"]["coverage"][key] = value
            with self.subTest(target=target, key=key), self.assertRaises(ValueError):
                resource_summary(record, data)


if __name__ == "__main__":
    unittest.main()
