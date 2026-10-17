#!/usr/bin/env python3
"""Write a deterministic path/size/SHA-256 inventory for a package tree."""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="extracted package root")
    parser.add_argument("output", type=Path, help="CSV file to create")
    args = parser.parse_args()

    root = args.root.resolve(strict=True)
    if not root.is_dir():
        parser.error(f"not a directory: {root}")

    paths = sorted(
        (path for path in root.rglob("*") if path.is_file()),
        key=lambda path: (
            path.relative_to(root).as_posix().casefold(),
            path.relative_to(root).as_posix(),
        ),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(("path", "size_bytes", "sha256"))
        for path in paths:
            writer.writerow(
                (
                    path.relative_to(root).as_posix(),
                    path.stat().st_size,
                    sha256(path),
                )
            )

    print(f"Wrote {len(paths)} file rows to {args.output}")


if __name__ == "__main__":
    main()
