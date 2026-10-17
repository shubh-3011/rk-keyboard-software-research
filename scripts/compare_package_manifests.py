#!/usr/bin/env python3
"""Compare two path/size/SHA-256 manifests without reading package files."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def read_manifest(
    path: Path, path_mappings: list[tuple[str, str]] | None = None
) -> dict[str, dict[str, str]]:
    mappings = [
        (source.strip("/\\").casefold(), target.strip("/\\"))
        for source, target in (path_mappings or [])
    ]
    rows: dict[str, dict[str, str]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            path_field = "path" if "path" in row else "relative_path"
            original = row[path_field].replace("\\", "/").strip("/")
            if mappings:
                for source, target in mappings:
                    folded = original.casefold()
                    if folded == source:
                        original = target
                        break
                    if folded.startswith(source + "/"):
                        suffix = original[len(source) + 1 :]
                        original = f"{target}/{suffix}" if target else suffix
                        break
                else:
                    continue
            key = original.casefold()
            if key in rows:
                raise ValueError(f"duplicate case-insensitive path in {path}: {original}")
            rows[key] = {
                "path": original,
                "size_bytes": row["size_bytes"],
                "sha256": row["sha256"].upper(),
            }
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path, help="baseline manifest CSV")
    parser.add_argument("candidate", type=Path, help="candidate manifest CSV")
    parser.add_argument("output", type=Path, help="delta CSV to create")
    parser.add_argument(
        "--candidate-map-prefix",
        action="append",
        default=[],
        metavar="SOURCE=TARGET",
        help=(
            "include paths under SOURCE and replace that leading prefix with "
            "TARGET; repeat to combine package subtrees, and use an empty "
            "TARGET to map to the baseline root"
        ),
    )
    args = parser.parse_args()

    mappings = []
    for value in args.candidate_map_prefix:
        if "=" not in value:
            parser.error(f"invalid --candidate-map-prefix value: {value}")
        mappings.append(tuple(value.split("=", 1)))
    baseline = read_manifest(args.baseline)
    candidate = read_manifest(args.candidate, mappings)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    totals = {"unchanged": 0, "changed": 0, "added": 0, "removed": 0}
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(
            (
                "status",
                "path",
                "baseline_size_bytes",
                "baseline_sha256",
                "candidate_size_bytes",
                "candidate_sha256",
            )
        )
        for key in sorted(set(baseline) | set(candidate)):
            before = baseline.get(key)
            after = candidate.get(key)
            if before is None:
                status = "added"
            elif after is None:
                status = "removed"
            elif (
                before["size_bytes"] == after["size_bytes"]
                and before["sha256"] == after["sha256"]
            ):
                status = "unchanged"
            else:
                status = "changed"
            totals[status] += 1
            row = after or before
            writer.writerow(
                (
                    status,
                    row["path"],
                    before["size_bytes"] if before else "",
                    before["sha256"] if before else "",
                    after["size_bytes"] if after else "",
                    after["sha256"] if after else "",
                )
            )

    print(
        "Wrote "
        f"{sum(totals.values())} paths to {args.output}: "
        + ", ".join(f"{key}={value}" for key, value in totals.items())
    )


if __name__ == "__main__":
    main()
