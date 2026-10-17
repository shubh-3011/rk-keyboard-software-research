#!/usr/bin/env python3
"""Compare a local RK installation with the repository's file manifest."""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from pathlib import Path, PurePosixPath


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rk-root", required=True, type=Path, help="installed RK package directory")
    parser.add_argument("--manifest", required=True, type=Path, help="package manifest CSV")
    args = parser.parse_args()

    root = args.rk_root.resolve()
    if not root.is_dir():
        parser.error(f"RK package directory does not exist: {root}")

    with args.manifest.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    required = {"relative_path", "size_bytes", "sha256"}
    if not rows or not required.issubset(rows[0]):
        parser.error(f"manifest must contain columns: {', '.join(sorted(required))}")

    expected: dict[str, dict[str, str]] = {}
    unsafe_rows: list[str] = []
    for row in rows:
        relative = row["relative_path"].replace("\\", "/")
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or not relative:
            unsafe_rows.append(relative)
            continue
        key = relative.casefold()
        if key in expected:
            parser.error(f"duplicate manifest path (case-insensitive): {relative}")
        expected[key] = row

    actual: dict[str, Path] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        key = relative.casefold()
        if key in actual:
            parser.error(f"duplicate installed path (case-insensitive): {relative}")
        actual[key] = path

    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    mismatches: list[tuple[str, str]] = []
    for key in sorted(set(expected) & set(actual)):
        row = expected[key]
        path = actual[key]
        relative = row["relative_path"].replace("\\", "/")
        problems: list[str] = []
        if path.relative_to(root).as_posix() != relative:
            problems.append("path case differs")
        size = path.stat().st_size
        if size != int(row["size_bytes"]):
            problems.append(f"size {size} != {row['size_bytes']}")
        digest = file_sha256(path)
        if digest.casefold() != row["sha256"].casefold():
            problems.append("SHA-256 differs")
        if problems:
            mismatches.append((relative, ", ".join(problems)))

    print(
        f"manifest={len(rows)} installed={len(actual)} missing={len(missing)} "
        f"extra={len(extra)} mismatches={len(mismatches)} unsafe_manifest_rows={len(unsafe_rows)}"
    )
    for label, items in (
        ("missing", missing),
        ("extra", extra),
        ("mismatch", mismatches),
        ("unsafe manifest row", unsafe_rows),
    ):
        for item in items:
            print(f"{label}: {item}")

    if missing or extra or mismatches or unsafe_rows:
        return 1
    print("All installed file paths, sizes, and SHA-256 hashes match the manifest.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, csv.Error, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
