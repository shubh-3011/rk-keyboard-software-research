#!/usr/bin/env python3
"""Generate the S98-only detail table for the hash-pinned 4.6 catalog.

This reads the version-scoped JSON catalog and the package file manifest only.
It does not run RK software or access a keyboard. The manifest supplies path
and SHA-256 references for profile-local image and updater artifacts; it does
not copy those files into the repository.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any


EXPECTED_CATALOG_SHA256 = "2035aa6013a559770eac41fdfbbe7cc87472d8e8b30a3f736a88eebfadc6e91e"
EXPECTED_MANIFEST_SHA256 = "e84f8a55daade06fcbba6330790da2ba78c2ba1c1cf3098d25fc0a6d8a08c87c"
EXPECTED_CODES = {
    "0174", "01AF", "01BF", "021E", "0223", "0224",
    "022B", "022F", "0230", "023F", "0240", "0241",
}
EXPECTED_ROW_COUNT = 12
IMAGE_SUFFIXES = {".bmp", ".gif", ".jpeg", ".jpg", ".png", ".webp"}
ARTIFACT_SUFFIXES = {".bin", ".exe", ".firmware", ".hex", ".upf"}
FIELDNAMES = [
    "catalog_version",
    "catalog_sha256",
    "asset_manifest_sha256",
    "profile_code",
    "model_name",
    "family",
    "region",
    "is_direct_pid",
    "layout_id",
    "key_count",
    "drawable_key_count",
    "features_json",
    "image_refs_json",
    "artifact_refs_json",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def profile_asset_refs(
    code: str, manifest_rows: list[dict[str, str]], suffixes: set[str]
) -> list[dict[str, str]]:
    prefix = f"app/Dev/{code}/".casefold()
    refs = [
        {"path": row["path"], "sha256": row["sha256"].lower()}
        for row in manifest_rows
        if row["path"].casefold().startswith(prefix)
        and Path(row["path"]).suffix.casefold() in suffixes
    ]
    return sorted(refs, key=lambda item: item["path"].casefold())


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=root / "models-4.6.json")
    parser.add_argument(
        "--manifest", type=Path, default=root / "docs" / "rk-4.6-package-manifest.csv"
    )
    parser.add_argument(
        "--output", type=Path, default=root / "docs" / "rk-v4.6-s98-profile-details.csv"
    )
    args = parser.parse_args()

    catalog_hash = sha256_file(args.catalog)
    if catalog_hash != EXPECTED_CATALOG_SHA256:
        raise SystemExit(
            f"models-4.6.json SHA-256 mismatch: {catalog_hash}; "
            "review the source/version change before updating the pin"
        )
    manifest_hash = sha256_file(args.manifest)
    if manifest_hash != EXPECTED_MANIFEST_SHA256:
        raise SystemExit(
            f"4.6 package manifest SHA-256 mismatch: {manifest_hash}; "
            "review the source/version change before updating the pin"
        )

    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    if catalog.get("profileCount") != len(catalog.get("models", [])):
        raise SystemExit("catalog profileCount does not match its models array")
    profiles = [
        row for row in catalog["models"] if "S98" in row.get("name", "").upper()
    ]
    profiles.sort(key=lambda row: row["code"].upper())
    codes = {row["code"].upper() for row in profiles}
    if len(profiles) != EXPECTED_ROW_COUNT or codes != EXPECTED_CODES:
        raise SystemExit(
            "S98 profile scope changed: "
            f"rows={len(profiles)}, codes={','.join(sorted(codes))}"
        )

    with args.manifest.open("r", encoding="utf-8-sig", newline="") as stream:
        manifest_rows = list(csv.DictReader(stream))
    required = {"path", "size_bytes", "sha256"}
    if not manifest_rows or not required.issubset(manifest_rows[0]):
        raise SystemExit("package manifest lacks path, size_bytes, or sha256")

    output_rows: list[dict[str, str]] = []
    for profile in profiles:
        code = profile["code"].upper()
        features = profile.get("features") or {}
        output_rows.append(
            {
                "catalog_version": "V4.6-labeled package; embedded Cfg.ini Ver=0x406",
                "catalog_sha256": catalog_hash,
                "asset_manifest_sha256": manifest_hash,
                "profile_code": code,
                "model_name": profile["name"],
                "family": profile.get("family", ""),
                "region": profile.get("region", ""),
                "is_direct_pid": str(bool(profile.get("isDirectPid"))).lower(),
                "layout_id": profile.get("layoutId", ""),
                "key_count": str(profile.get("keyCount", "")),
                "drawable_key_count": str(profile.get("drawableKeyCount", "")),
                "features_json": compact_json(features),
                "image_refs_json": compact_json(
                    profile_asset_refs(code, manifest_rows, IMAGE_SUFFIXES)
                ),
                "artifact_refs_json": compact_json(
                    profile_asset_refs(code, manifest_rows, ARTIFACT_SUFFIXES)
                ),
            }
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDNAMES, lineterminator="\n")
        writer.writeheader()
        writer.writerows(output_rows)

    image_ref_count = sum(json.loads(row["image_refs_json"]) != [] for row in output_rows)
    artifact_ref_count = sum(
        json.loads(row["artifact_refs_json"]) != [] for row in output_rows
    )
    print(
        f"Wrote {len(output_rows)} 4.6 S98 profiles to {args.output}; "
        f"codes={','.join(row['profile_code'] for row in output_rows)}; "
        f"profiles_with_images={image_ref_count}; "
        f"profiles_with_updater_or_firmware_artifacts={artifact_ref_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
