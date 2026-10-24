#!/usr/bin/env python3
"""Reconcile committed RK model catalogs with their package snapshots.

This offline audit checks both complete package trees against their pinned
manifests, reruns the existing static catalog extractor into a temporary
directory, and compares the generated catalogs with the committed JSON. It
does not launch RK software or access a keyboard.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
EVIDENCE = {
    "installed_4_06": {
        "label": "installed 4.06",
        "catalog": REPO / "models.json",
        "manifest": REPO / "docs" / "rk-installed-package-manifest.csv",
        "catalog_sha256": "d7b877dbeef81432ec9914c19bc86af0583497b095f18558575e983e31b8fcf7",
        "manifest_sha256": "4f83d002d840f4dd8ed03823ce48ea7af1ccb5c1b3bdb092d5b861385a7d7ea0",
        "manifest_path_column": "relative_path",
        "package_subdir": Path("."),
        "catalog_subdir": Path("."),
    },
    "package_4_6": {
        "label": "4.6-labeled package (Cfg.ini Ver=0x406)",
        "catalog": REPO / "models-4.6.json",
        "manifest": REPO / "docs" / "rk-4.6-package-manifest.csv",
        "catalog_sha256": "2035aa6013a559770eac41fdfbbe7cc87472d8e8b30a3f736a88eebfadc6e91e",
        "manifest_sha256": "e84f8a55daade06fcbba6330790da2ba78c2ba1c1cf3098d25fc0a6d8a08c87c",
        "manifest_path_column": "path",
        "package_subdir": Path("."),
        "catalog_subdir": Path("app"),
    },
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stable_hash(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_manifest(spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    with spec["manifest"].open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    manifest: dict[str, dict[str, Any]] = {}
    for row in rows:
        path = row[spec["manifest_path_column"]].replace("\\", "/")
        if path in manifest:
            raise ValueError(f"duplicate manifest path: {path}")
        size_column = "size_bytes"
        manifest[path] = {
            "size": int(row[size_column]),
            "sha256": row["sha256"].strip().lower(),
        }
    return manifest


def verify_package_tree(root: Path, manifest: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if not root.is_dir():
        raise FileNotFoundError(f"package snapshot directory not found: {root}")
    actual = {
        path.relative_to(root).as_posix(): path
        for path in root.rglob("*")
        if path.is_file()
    }
    missing = sorted(set(manifest) - set(actual))
    extra = sorted(set(actual) - set(manifest))
    size_mismatches: list[str] = []
    hash_mismatches: list[str] = []
    for rel_path in sorted(set(manifest) & set(actual)):
        path = actual[rel_path]
        item = manifest[rel_path]
        if path.stat().st_size != item["size"]:
            size_mismatches.append(rel_path)
        if sha256_file(path) != item["sha256"]:
            hash_mismatches.append(rel_path)
    return {
        "file_count": len(actual),
        "manifest_count": len(manifest),
        "missing": missing,
        "extra": extra,
        "size_mismatches": size_mismatches,
        "hash_mismatches": hash_mismatches,
        "ok": not (missing or extra or size_mismatches or hash_mismatches),
    }


def verify_pinned_file(path: Path, expected: str) -> str:
    actual = sha256_file(path)
    if actual != expected:
        raise ValueError(f"pinned evidence hash mismatch for {path}: expected {expected}, got {actual}")
    return actual


def recursive_diff(left: Any, right: Any, prefix: str = "") -> list[str]:
    if isinstance(left, dict) and isinstance(right, dict):
        paths: list[str] = []
        for key in sorted(set(left) | set(right)):
            child = f"{prefix}.{key}" if prefix else str(key)
            if key not in left or key not in right:
                paths.append(child)
            else:
                paths.extend(recursive_diff(left[key], right[key], child))
        return paths
    if left != right:
        return [prefix or "value"]
    return []


def profile_options(model: dict[str, Any]) -> dict[str, Any]:
    return model.get("profileData", {}).get("options", {})


def catalog_records(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for model in catalog.get("models", []):
        code = str(model["code"]).upper()
        if code in records:
            raise ValueError(f"duplicate profile code in models: {code}")
        records[code] = {"record_type": "model", **model}
    for orphan in catalog.get("unregisteredProfiles", []):
        code = str(orphan["code"]).upper()
        if code in records:
            raise ValueError(f"profile code is both named and unregistered: {code}")
        records[code] = {"record_type": "unregistered", **orphan}
    return records


def regenerate_catalog(rk_root: Path, expected: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rk-model-catalog-audit-") as temp_dir:
        temp = Path(temp_dir)
        output = temp / "catalog.json"
        driver_map = temp / "driver-map.csv"
        subprocess.run(
            [
                sys.executable,
                str(REPO / "scripts" / "extract_rk_catalog.py"),
                "--rk-root",
                str(rk_root),
                "--output",
                str(output),
                "--driver-map-output",
                str(driver_map),
            ],
            check=True,
            cwd=REPO,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        generated = load_json(output)
    # The extractor has a fixed 4.06 source label; the 4.6 catalog records the
    # package's release label and embedded Cfg.ini version separately.
    generated["source"] = expected.get("source")
    if generated != expected:
        diff = recursive_diff(generated, expected)
        preview = ", ".join(diff[:20])
        raise ValueError(f"regenerated catalog differs at {len(diff)} path(s): {preview}")
    return generated


def model_rows(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = {str(model["code"]).upper(): model for model in catalog["models"]}
    if len(rows) != len(catalog["models"]):
        raise ValueError("duplicate model profile codes")
    return rows


def family_summary(catalogs: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for version_key, catalog in catalogs.items():
        by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for model in catalog["models"]:
            by_family[str(model.get("family", ""))].append(model)
        for family, rows in sorted(by_family.items()):
            output.append({
                "version": EVIDENCE[version_key]["label"],
                "family_label_from_catalog": family,
                "named_profile_count": len(rows),
                "direct_pid_profile_count": sum(bool(row.get("isDirectPid")) for row in rows),
                "distinct_display_name_count": len({row.get("name", "") for row in rows}),
                "distinct_layout_count": len({row.get("layoutId", "") for row in rows}),
                "rgb_profile_count": sum(bool(row.get("features", {}).get("rgb")) for row in rows),
                "screen_profile_count": sum(row.get("features", {}).get("screen") is not None for row in rows),
                "wireless_profile_count": sum(bool(row.get("features", {}).get("wirelessProductId")) for row in rows),
            })
    return output


def compare_profiles(catalogs: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    old_rows = model_rows(catalogs["installed_4_06"])
    new_rows = model_rows(catalogs["package_4_6"])
    output: list[dict[str, Any]] = []
    for code in sorted(set(old_rows) | set(new_rows)):
        old = old_rows.get(code)
        new = new_rows.get(code)
        if old is None:
            status = "added_in_4.6_labeled_catalog"
            diff_paths = []
            option_diff = []
        elif new is None:
            status = "removed_from_4.6_labeled_catalog"
            diff_paths = []
            option_diff = []
        else:
            diff_paths = recursive_diff(old, new)
            old_options, new_options = profile_options(old), profile_options(new)
            option_diff = sorted(
                key for key in set(old_options) | set(new_options)
                if old_options.get(key) != new_options.get(key)
            )
            status = "unchanged" if not diff_paths else "changed"
        output.append({
            "profile_code": code,
            "status": status,
            "name_4_06": old.get("name", "") if old else "",
            "name_4_6_labeled": new.get("name", "") if new else "",
            "family_4_06": old.get("family", "") if old else "",
            "family_4_6_labeled": new.get("family", "") if new else "",
            "region_4_06": old.get("region", "") if old else "",
            "region_4_6_labeled": new.get("region", "") if new else "",
            "direct_pid_4_06": str(bool(old.get("isDirectPid"))).lower() if old else "",
            "direct_pid_4_6_labeled": str(bool(new.get("isDirectPid"))).lower() if new else "",
            "key_count_4_06": old.get("keyCount", "") if old else "",
            "key_count_4_6_labeled": new.get("keyCount", "") if new else "",
            "drawable_key_count_4_06": old.get("drawableKeyCount", "") if old else "",
            "drawable_key_count_4_6_labeled": new.get("drawableKeyCount", "") if new else "",
            "layout_id_4_06": old.get("layoutId", "") if old else "",
            "layout_id_4_6_labeled": new.get("layoutId", "") if new else "",
            "changed_model_field_paths": ";".join(diff_paths),
            "changed_profile_option_keys": ";".join(option_diff),
            "model_sha256_4_06": stable_hash(old) if old else "",
            "model_sha256_4_6_labeled": stable_hash(new) if new else "",
        })
    return output


def duplicate_groups(catalogs: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for version_key, catalog in catalogs.items():
        models = catalog["models"]
        label = EVIDENCE[version_key]["label"]
        name_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        layout_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        metadata_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for model in models:
            if model.get("name"):
                name_groups[str(model["name"])].append(model)
            if model.get("layoutId"):
                layout_groups[str(model["layoutId"])].append(model)
            metadata = {key: value for key, value in model.items() if key not in {"code", "name"}}
            metadata_groups[stable_hash(metadata)].append(model)
        groups = [
            ("repeated_display_name", name, rows, "" )
            for name, rows in name_groups.items() if len(rows) > 1
        ]
        groups.extend(
            ("shared_layout_id", layout_id, rows, "")
            for layout_id, rows in layout_groups.items() if len(rows) > 1
        )
        groups.extend(
            ("identical_profile_metadata_excluding_code_and_name", "sha256:" + signature, rows, signature)
            for signature, rows in metadata_groups.items() if len(rows) > 1
        )
        for group_type, group_value, rows, signature in sorted(groups, key=lambda item: (item[0], item[1])):
            output.append({
                "version": label,
                "group_type": group_type,
                "group_value": group_value,
                "profile_count": len(rows),
                "profile_codes": ";".join(sorted(str(row["code"]).upper() for row in rows)),
                "display_names": ";".join(sorted({str(row.get("name", "")) for row in rows})),
                "metadata_signature_sha256": signature,
                "interpretation_limit": (
                    "Repeated labels, geometry, or stored metadata do not establish a physical SKU alias or compatibility."
                ),
            })
    return output


def source_integrity_rows(
    catalogs: dict[str, dict[str, Any]],
    manifests: dict[str, dict[str, dict[str, Any]]],
    roots: dict[str, Path],
    package_results: dict[str, dict[str, Any]],
    regenerated: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for version_key, catalog in catalogs.items():
        spec = EVIDENCE[version_key]
        package_root = roots[version_key] / spec["package_subdir"]
        catalog_root = roots[version_key] / spec["catalog_subdir"]
        source_manifest = manifests[version_key]
        expected_rows = catalog_records(catalog)
        regenerated_rows = catalog_records(regenerated[version_key])
        source_paths = {
            path.parent.name.upper(): path
            for path in (catalog_root / "Dev").glob("*/KB.ini")
        }
        source_codes: set[str] = set()
        for code, record in sorted(expected_rows.items()):
            source_file = source_paths.get(code)
            rel = source_file.relative_to(package_root).as_posix() if source_file else ""
            source_codes.add(code)
            manifest_item = source_manifest.get(rel)
            exists = bool(source_file and source_file.is_file())
            actual_hash = sha256_file(source_file) if exists else ""
            model_reproduced = regenerated_rows.get(code) == record
            output.append({
                "version": spec["label"],
                "record_type": record["record_type"],
                "profile_code": code,
                "display_name": record.get("name", ""),
                "source_manifest_path": rel,
                "source_manifest_sha256": manifest_item["sha256"] if manifest_item else "",
                "source_file_sha256": actual_hash,
                "source_file_bytes": source_file.stat().st_size if exists else "",
                "manifest_row_present": str(manifest_item is not None).lower(),
                "source_file_matches_manifest": str(bool(manifest_item and exists and actual_hash == manifest_item["sha256"] and source_file.stat().st_size == manifest_item["size"])).lower(),
                "package_manifest_tree_complete": str(package_results[version_key]["ok"]).lower(),
                "catalog_record_reproduced": str(model_reproduced).lower(),
                "catalog_record_sha256": stable_hash(record),
            })
        actual_codes = {
            path.parent.name.upper()
            for path in (catalog_root / "Dev").glob("*/KB.ini")
        }
        unexpected = actual_codes - source_codes
        if unexpected:
            raise ValueError(f"{spec['label']}: source profiles missing from catalog records: {', '.join(sorted(unexpected))}")
        if actual_codes != source_codes:
            raise ValueError(f"{spec['label']}: catalog/source profile code set mismatch")
    return output


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError(f"refusing to write empty evidence table: {path}")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def markdown_report(
    catalogs: dict[str, dict[str, Any]],
    package_results: dict[str, dict[str, Any]],
    comparison: list[dict[str, Any]],
    duplicates: list[dict[str, Any]],
    integrity_rows: list[dict[str, Any]],
) -> str:
    old = catalogs["installed_4_06"]
    new = catalogs["package_4_6"]
    statuses: dict[str, int] = defaultdict(int)
    for row in comparison:
        statuses[row["status"]] += 1
    shared = set(model_rows(old)) & set(model_rows(new))
    changed_paths = defaultdict(int)
    changed_options = defaultdict(int)
    for row in comparison:
        for key in row["changed_model_field_paths"].split(";"):
            if key:
                changed_paths[key] += 1
        for key in row["changed_profile_option_keys"].split(";"):
            if key:
                changed_options[key] += 1
    dup_summary = defaultdict(lambda: {"groups": 0, "profiles": 0})
    for row in duplicates:
        stats = dup_summary[row["group_type"]]
        stats["groups"] += 1
        stats["profiles"] += int(row["profile_count"])
    duplicate_lines = "\n".join(
        f"- `{kind}`: {stats['groups']} groups containing {stats['profiles']} profile rows across the two catalogs."
        for kind, stats in sorted(dup_summary.items())
    )
    changed_line = ", ".join(f"`{field}` ({count})" for field, count in sorted(changed_paths.items())) or "none"
    option_line = ", ".join(f"`{field}` ({count})" for field, count in sorted(changed_options.items())) or "none"
    source_ok = sum(row["source_file_matches_manifest"] == "true" for row in integrity_rows)
    regenerated_ok = sum(row["catalog_record_reproduced"] == "true" for row in integrity_rows)
    return f"""# Versioned model catalog audit

Generated by `scripts/audit_versioned_model_catalogs.py` from the checked-in catalogs and local package snapshots. This is a static package/configuration audit; it performs no device I/O and does not launch Royal Kludge software.

## Scope and pinned evidence

| Snapshot | Package root argument | Catalog | Package manifest |
|---|---|---|---|
| Installed 4.06 | `--installed-root` (default: `C:\\Program Files (x86)\\RK Keyboard Software`) | [`models.json`](../models.json) | [`rk-installed-package-manifest.csv`](rk-installed-package-manifest.csv) |
| 4.6-labeled package (`Cfg.ini Ver=0x406`) | `--package-4-6-root` (default: `.research\\rk46-extract-full`) | [`models-4.6.json`](../models-4.6.json) | [`rk-4.6-package-manifest.csv`](rk-4.6-package-manifest.csv) |

The script pins SHA-256 for both catalogs and manifests. Each run checks every package file path, byte length, and SHA-256 against its manifest, then runs the repository's static extractor into a temporary directory and requires exact catalog regeneration (normalizing only the top-level `source` label, which the extractor fixes to 4.06).

| Snapshot | Manifest files | Files found | Missing / extra / size mismatch / hash mismatch | Result |
|---|---:|---:|---|---|
| Installed 4.06 | {package_results['installed_4_06']['manifest_count']} | {package_results['installed_4_06']['file_count']} | {len(package_results['installed_4_06']['missing'])} / {len(package_results['installed_4_06']['extra'])} / {len(package_results['installed_4_06']['size_mismatches'])} / {len(package_results['installed_4_06']['hash_mismatches'])} | {'PASS' if package_results['installed_4_06']['ok'] else 'FAIL'} |
| 4.6-labeled | {package_results['package_4_6']['manifest_count']} | {package_results['package_4_6']['file_count']} | {len(package_results['package_4_6']['missing'])} / {len(package_results['package_4_6']['extra'])} / {len(package_results['package_4_6']['size_mismatches'])} / {len(package_results['package_4_6']['hash_mismatches'])} | {'PASS' if package_results['package_4_6']['ok'] else 'FAIL'} |

## Profile coverage and comparison

| Snapshot | Named models | Unregistered `KB.ini` profiles | Total `Dev/*/KB.ini` count | Family labels |
|---|---:|---:|---:|---:|
| Installed 4.06 | {len(old['models'])} | {len(old['unregisteredProfiles'])} | {old['profileCount']} | {len({row.get('family') for row in old['models']})} |
| 4.6-labeled | {len(new['models'])} | {len(new['unregisteredProfiles'])} | {new['profileCount']} | {len({row.get('family') for row in new['models']})} |

Across named profile codes: {len(shared)} are shared, {statuses['added_in_4.6_labeled_catalog']} are added in the 4.6-labeled catalog, and {statuses['removed_from_4.6_labeled_catalog']} are absent there. Among shared codes, {statuses['unchanged']} model rows are identical as parsed JSON objects and {statuses['changed']} differ. Changed top-level/nested field paths occur in {changed_line}. Changed `profileData.options` keys occur in {option_line}. The only shared-code name/region changes are `0201`, `0202`, and `0203`, whose display names drop `ISO Return` and whose inferred region changes from ISO to ANSI.

Full per-family counts and per-code field comparisons are in [`rk-versioned-profile-family-summary.csv`](rk-versioned-profile-family-summary.csv) and [`rk-versioned-profile-comparison.csv`](rk-versioned-profile-comparison.csv). The comparison includes each version's name, derived family/region labels, direct-PID flag, key counts, layout ID, per-row field paths, option-key differences, and canonical model hashes.

## Repeated labels, layouts, and profile payloads

{duplicate_lines}

Rows are enumerated in [`rk-versioned-profile-duplicates.csv`](rk-versioned-profile-duplicates.csv). Family and region labels are derived by the existing catalog extractor from display-name text; they are not vendor-authenticated taxonomy. Repeated display names, layout IDs, or identical profile metadata after omitting code/name are evidence of repeated configuration data only. They do not prove that different product codes are physical SKU aliases.

## Source integrity

The audit emitted {len(integrity_rows)} one-per-record source rows. `{source_ok}/{len(integrity_rows)}` profile `KB.ini` files match their exact package-manifest path, size, and SHA-256, and `{regenerated_ok}/{len(integrity_rows)}` catalog records reproduce from the package sources. The output is [`rk-versioned-profile-source-integrity.csv`](rk-versioned-profile-source-integrity.csv). This covers named models and the one unregistered profile in the installed 4.06 catalog.

`isDirectPid` records static membership in the package's configured PID list. It does not represent live device discovery. Catalog model names, region labels, layouts, feature flags, and profile files cannot identify the user's physical revision, verify a pictured enclosure/color, establish firmware equivalence, or establish compatibility with a particular retail SKU. Those claims require independently sourced SKU/revision evidence and, where appropriate, safe physical-device observation; this report makes no physical compatibility claim.

## Reproduction

From the repository root, run:

```powershell
python scripts/audit_versioned_model_catalogs.py
```

The default source roots are the installed 4.06 software directory `C:\\Program Files (x86)\\RK Keyboard Software` and ignored local extraction `.research\\rk46-extract-full`. Override them when the snapshots are stored elsewhere:

```powershell
python scripts/audit_versioned_model_catalogs.py --installed-root "C:\\Program Files (x86)\\RK Keyboard Software" --package-4-6-root ".research\\rk46-extract-full"
```

The 4.6-labeled catalog was extracted from the package's `app/` directory. Snapshot files are not included by this script; their manifests and pinned hashes provide the integrity reference.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--installed-root",
        type=Path,
        default=Path(r"C:\Program Files (x86)\RK Keyboard Software"),
        help="complete installed 4.06 package tree matching rk-installed-package-manifest.csv",
    )
    parser.add_argument(
        "--package-4-6-root",
        type=Path,
        default=REPO / ".research" / "rk46-extract-full",
        help="complete extracted 4.6-labeled package tree matching rk-4.6-package-manifest.csv",
    )
    args = parser.parse_args()
    roots = {
        "installed_4_06": args.installed_root.resolve(),
        "package_4_6": args.package_4_6_root.resolve(),
    }

    catalogs: dict[str, dict[str, Any]] = {}
    manifests: dict[str, dict[str, dict[str, Any]]] = {}
    package_results: dict[str, dict[str, Any]] = {}
    regenerated: dict[str, dict[str, Any]] = {}
    for version_key, spec in EVIDENCE.items():
        verify_pinned_file(spec["catalog"], spec["catalog_sha256"])
        verify_pinned_file(spec["manifest"], spec["manifest_sha256"])
        catalog = load_json(spec["catalog"])
        manifest = read_manifest(spec)
        package_root = roots[version_key] / spec["package_subdir"]
        source_root = roots[version_key] / spec["catalog_subdir"]
        package_result = verify_package_tree(package_root, manifest)
        if not package_result["ok"]:
            raise ValueError(
                f"{spec['label']} package tree failed manifest integrity: "
                f"missing={len(package_result['missing'])}, extra={len(package_result['extra'])}, "
                f"size={len(package_result['size_mismatches'])}, sha256={len(package_result['hash_mismatches'])}"
            )
        generated = regenerate_catalog(source_root, catalog)
        catalogs[version_key] = catalog
        manifests[version_key] = manifest
        package_results[version_key] = package_result
        regenerated[version_key] = generated

    families = family_summary(catalogs)
    comparison = compare_profiles(catalogs)
    duplicates = duplicate_groups(catalogs)
    integrity = source_integrity_rows(catalogs, manifests, roots, package_results, regenerated)
    for name, rows in (
        ("rk-versioned-profile-family-summary.csv", families),
        ("rk-versioned-profile-comparison.csv", comparison),
        ("rk-versioned-profile-duplicates.csv", duplicates),
        ("rk-versioned-profile-source-integrity.csv", integrity),
    ):
        write_csv(REPO / "docs" / name, rows)
    report = markdown_report(catalogs, package_results, comparison, duplicates, integrity)
    (REPO / "docs" / "rk-versioned-profile-catalog-audit.md").write_text(report, encoding="utf-8", newline="\n")
    print(
        "PASS: package manifests and extracted catalogs verified; "
        f"{len(catalogs['installed_4_06']['models'])} / {len(catalogs['package_4_6']['models'])} named models, "
        f"{len(comparison)} comparison rows, {len(integrity)} source-integrity rows."
    )


if __name__ == "__main__":
    main()
