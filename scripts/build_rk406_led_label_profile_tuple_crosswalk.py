#!/usr/bin/env python3
"""Join RK 4.06 localized LED label candidates to profile LedOpt tuples.

This uses only the repository's hash-pinned profile catalog and generated
label-candidate CSVs. It does not run RK software or access a device.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODELS_JSON = ROOT / "models.json"
CANDIDATES_CSV = ROOT / "docs/rk-led-control-candidates-4.06-en.csv"
OUTPUT_CSV = ROOT / "docs/rk-406-led-label-profile-tuple-crosswalk-4.06-en.csv"

EXPECTED_MODELS_SHA256 = "d7b877dbeef81432ec9914c19bc86af0583497b095f18558575e983e31b8fcf7"
EXPECTED_CANDIDATE_HASHES = {
    "rk-led-control-candidates-4.06-en.csv": "88af1cc45462b00bcef0905a325783dba673ffe161d312ec5306c0c22133ccd2",
    "rk-led-control-candidates-4.06-Japanese.csv": "43b4488c3983db7f9d6d4aa53261cfecef7822c3eb75509b7c5d8cdd928133da",
    "rk-led-control-candidates-4.06-Korean.csv": "79951ff0205e1641ef0426b745d0737e31bea86e60b3796199a201cb167aba09",
    "rk-led-control-candidates-4.06-sc.csv": "215534fd7aa9a9a8f559f8dd602382499192b27f33b155e59e899dc38ba87945",
    "rk-led-control-candidates-4.06-tw.csv": "d09ab5a3fbd30f365725e0a5919e8482ce314971408828b80e7c57a2ddc3d284",
}
EXPECTED_DRIVER_SHA256 = "c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def verify_model_input() -> None:
    actual = sha256(MODELS_JSON)
    if actual != EXPECTED_MODELS_SHA256:
        raise SystemExit(
            f"Input hash mismatch for {MODELS_JSON.relative_to(ROOT)}: "
            f"expected {EXPECTED_MODELS_SHA256}, got {actual}"
        )


def load_profiles() -> dict[str, dict[str, object]]:
    data = json.loads(MODELS_JSON.read_text(encoding="utf-8"))
    rows = list(data.get("models", [])) + list(data.get("unregisteredProfiles", []))
    profiles: dict[str, dict[str, object]] = {}
    for row in rows:
        code = str(row["code"]).upper()
        if code in profiles:
            raise SystemExit(f"Duplicate profile code in models.json: {code}")
        profiles[code] = row
    return profiles


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--candidates",
        type=Path,
        action="append",
        default=None,
        help="hash-pinned candidate CSV; repeat to combine multiple installed locales",
    )
    parser.add_argument("--output", type=Path, default=OUTPUT_CSV)
    args = parser.parse_args()

    candidate_paths = args.candidates or [CANDIDATES_CSV]
    for path in candidate_paths:
        expected = EXPECTED_CANDIDATE_HASHES.get(path.name)
        if expected is None:
            raise SystemExit(f"No pinned candidate hash registered for {path.name}")
        actual = sha256(path)
        if actual != expected:
            raise SystemExit(
                f"Input hash mismatch for {path}: expected {expected}, got {actual}"
            )
    verify_model_input()
    profiles = load_profiles()
    source_rows: list[dict[str, str]] = []
    input_fields: list[str] | None = None
    for path in candidate_paths:
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            rows = list(reader)
            if not rows:
                raise SystemExit(f"The LED candidate input has no rows: {path}")
            fields = list(rows[0])
            if input_fields is None:
                input_fields = fields
            elif input_fields != fields:
                raise SystemExit(f"Candidate CSV schema differs: {path}")
            source_rows.extend(rows)
    if input_fields is None:
        raise SystemExit("No LED candidate inputs")

    driver_hashes = {row["driver_sha256"].lower() for row in source_rows}
    if driver_hashes != {EXPECTED_DRIVER_SHA256}:
        raise SystemExit(f"Unexpected driver hashes in candidate file: {sorted(driver_hashes)}")
    expected_per_locale = 189 * 24
    locale_counts: dict[str, int] = {}
    for row in source_rows:
        locale = row["locale"]
        locale_counts[locale] = locale_counts.get(locale, 0) + 1
    bad_locales = {locale: count for locale, count in locale_counts.items() if count != expected_per_locale}
    if bad_locales:
        raise SystemExit(f"Unexpected candidate row count by locale: {bad_locales}")

    output_fields = input_fields + [
        "profile_ledopt_key",
        "profile_ledopt_raw",
        "profile_ledopt_cell_count",
        "profile_ledopt_present",
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    joined = missing_profiles = missing_options = 0
    locale_keys: set[tuple[str, str, str]] = set()
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=output_fields, lineterminator="\n")
        writer.writeheader()
        for source in source_rows:
            profile_code = source["profile_code"].upper()
            locale = source["locale"]
            row_key = (locale, profile_code, source["slot_suffix"])
            if row_key in locale_keys:
                raise SystemExit(f"Duplicate locale/profile/slot row: {row_key}")
            locale_keys.add(row_key)
            profile = profiles.get(profile_code)
            if profile is None:
                missing_profiles += 1
            options = (profile or {}).get("profileData", {}).get("options", {})
            key = f"LedOpt{int(source['slot_suffix'])}"
            raw_value = options.get(key) if isinstance(options, dict) else None
            if raw_value is None:
                missing_options += 1
            else:
                joined += 1
            cells = str(raw_value).split(",") if raw_value is not None else []
            writer.writerow(
                {
                    **source,
                    "profile_ledopt_key": key,
                    "profile_ledopt_raw": "" if raw_value is None else str(raw_value),
                    "profile_ledopt_cell_count": len(cells),
                    "profile_ledopt_present": str(raw_value is not None).lower(),
                }
            )

    if missing_profiles:
        raise SystemExit(f"Missing profile records: {missing_profiles}")

    print(f"Wrote {len(source_rows)} rows to {args.output}")
    print(f"Rows with profile LedOpt data: {joined}; rows without that key: {missing_options}")
    print(f"models.json SHA-256: {sha256(MODELS_JSON)}")
    print(f"candidate locales: {locale_counts}")
    for path in candidate_paths:
        print(f"{path.name} SHA-256: {sha256(path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
