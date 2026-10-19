#!/usr/bin/env python3
"""Validate and compare the official RK QMK Intel HEX selector artifacts.

Static-only: this reads downloaded text files, verifies Intel HEX checksums,
builds address maps, and writes source-free CSV/Markdown summaries. It does
not execute, flash, transform, or communicate with a keyboard.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "rk-qmk-hex-firmware-artifact-inventory-2026-10-19.csv"
OUT_CSV = ROOT / "docs" / "rk-qmk-hex-record-validation-2026-10-20.csv"
PAIR_CSV = ROOT / "docs" / "rk-qmk-hex-image-overlap-2026-10-20.csv"
REPORT = ROOT / "docs" / "rk-qmk-hex-static-comparison-2026-10-20.md"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ranges(addresses: set[int]) -> list[tuple[int, int]]:
    ordered = sorted(addresses)
    if not ordered:
        return []
    result: list[tuple[int, int]] = []
    start = previous = ordered[0]
    for address in ordered[1:]:
        if address != previous + 1:
            result.append((start, previous + 1))
            start = address
        previous = address
    result.append((start, previous + 1))
    return result


def hx(value: int | None) -> str:
    return "" if value is None else f"0x{value:08X}"


def parse_hex(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    mapped: dict[int, int] = {}
    errors: list[str] = []
    type_counts = {i: 0 for i in range(6)}
    base = 0
    eof_count = 0
    start_addresses: list[int] = []
    record_count = 0
    data_record_count = 0
    data_bytes_declared = 0
    duplicate_addresses = 0
    conflicting_addresses = 0

    for line_no, line in enumerate(raw.decode("ascii", "replace").splitlines(), 1):
        if not line:
            errors.append(f"line {line_no}: empty line")
            continue
        if not line.startswith(":"):
            errors.append(f"line {line_no}: missing colon")
            continue
        try:
            record = bytes.fromhex(line[1:])
        except ValueError:
            errors.append(f"line {line_no}: invalid hexadecimal text")
            continue
        if len(record) < 5:
            errors.append(f"line {line_no}: shorter than record header")
            continue
        length = record[0]
        address = (record[1] << 8) | record[2]
        kind = record[3]
        data = record[4:-1]
        checksum = record[-1]
        record_count += 1
        if len(record) != length + 5:
            errors.append(f"line {line_no}: byte count says {length}, record carries {len(data)}")
            continue
        if sum(record) & 0xFF:
            errors.append(f"line {line_no}: checksum mismatch")
        if kind not in type_counts:
            errors.append(f"line {line_no}: unsupported record type 0x{kind:02X}")
            continue
        type_counts[kind] += 1
        if kind == 0x00:
            data_record_count += 1
            data_bytes_declared += length
            absolute = base + address
            for offset, value in enumerate(data):
                at = absolute + offset
                if at in mapped:
                    duplicate_addresses += 1
                    if mapped[at] != value:
                        conflicting_addresses += 1
                        errors.append(f"line {line_no}: conflicting byte at {at:#x}")
                mapped[at] = value
        elif kind == 0x01:
            eof_count += 1
            if length != 0 or address != 0:
                errors.append(f"line {line_no}: malformed EOF record")
        elif kind == 0x02:
            if length != 2 or address != 0:
                errors.append(f"line {line_no}: malformed extended segment record")
            elif len(data) == 2:
                base = int.from_bytes(data, "big") << 4
        elif kind == 0x03:
            if length != 4:
                errors.append(f"line {line_no}: malformed start segment record")
            elif len(data) == 4:
                start_addresses.append((int.from_bytes(data[:2], "big") << 4) + int.from_bytes(data[2:], "big"))
        elif kind == 0x04:
            if length != 2 or address != 0:
                errors.append(f"line {line_no}: malformed extended linear record")
            elif len(data) == 2:
                base = int.from_bytes(data, "big") << 16
        elif kind == 0x05:
            if length != 4:
                errors.append(f"line {line_no}: malformed start linear record")
            elif len(data) == 4:
                start_addresses.append(int.from_bytes(data, "big"))

    address_ranges = ranges(set(mapped))
    return {
        "path": path,
        "sha256": sha256(raw),
        "file_bytes": len(raw),
        "record_count": record_count,
        "data_record_count": data_record_count,
        "data_bytes_declared": data_bytes_declared,
        "mapped_bytes": len(mapped),
        "duplicate_addresses": duplicate_addresses,
        "conflicting_addresses": conflicting_addresses,
        "eof_count": eof_count,
        "type_counts": type_counts,
        "start_addresses": start_addresses,
        "address_ranges": address_ranges,
        "mapped": mapped,
        "errors": errors,
    }


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--out-csv", type=Path, default=OUT_CSV)
    parser.add_argument("--pair-csv", type=Path, default=PAIR_CSV)
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args()

    with args.source.open("r", encoding="utf-8-sig", newline="") as f:
        source_rows = list(csv.DictReader(f))
    artifacts: list[dict[str, object]] = []
    for row in source_rows:
        if row.get("acquisition_status") not in {"cached_local_artifact", "preexisting_research_artifact"}:
            raise SystemExit(f"Artifact is not acquired: {row.get('filename')}")
        local = (ROOT.parent / row["local_path"]).resolve()
        artifact = parse_hex(local)
        if artifact["sha256"] != row["sha256"]:
            raise SystemExit(f"SHA-256 mismatch for {row['filename']}: {artifact['sha256']}")
        artifact.update({"filename": row["filename"], "model": row["selector_models"], "mode": row["modes"], "pid": row["pids"]})
        artifacts.append(artifact)

    summary_rows: list[dict[str, object]] = []
    for a in artifacts:
        mapped = a["mapped"]
        spans = a["address_ranges"]
        first = min(mapped) if mapped else None
        last = max(mapped) if mapped else None
        err = a["errors"]
        types = a["type_counts"]
        summary_rows.append({
            "filename": a["filename"], "model": a["model"], "mode": a["mode"], "pid": a["pid"],
            "sha256": a["sha256"], "file_bytes": a["file_bytes"], "record_count": a["record_count"],
            "data_record_count": a["data_record_count"], "data_bytes_declared": a["data_bytes_declared"],
            "mapped_bytes": a["mapped_bytes"], "record_type_00_data": types[0], "record_type_01_eof": types[1],
            "record_type_02_segment": types[2], "record_type_03_start_segment": types[3],
            "record_type_04_linear": types[4], "record_type_05_start_linear": types[5],
            "eof_count": a["eof_count"], "duplicate_addresses": a["duplicate_addresses"],
            "conflicting_addresses": a["conflicting_addresses"], "address_start": hx(first), "address_end_exclusive": hx(None if last is None else last + 1),
            "contiguous_ranges": "|".join(f"{hx(lo)}-{hx(hi)}" for lo, hi in spans),
            "start_address_records": "|".join(hx(x) for x in a["start_addresses"]),
            "validation": "valid" if not err and a["eof_count"] == 1 else "invalid_or_incomplete",
            "error_count": len(err), "error_samples": " | ".join(err[:4]),
        })
    write_csv(args.out_csv, summary_rows, list(summary_rows[0]))

    pair_rows: list[dict[str, object]] = []
    for left, right in itertools.combinations(artifacts, 2):
        lm: dict[int, int] = left["mapped"]
        rm: dict[int, int] = right["mapped"]
        common = lm.keys() & rm.keys()
        equal = sum(lm[address] == rm[address] for address in common)
        pair_rows.append({
            "left_filename": left["filename"], "left_sha256": left["sha256"],
            "right_filename": right["filename"], "right_sha256": right["sha256"],
            "left_mapped_bytes": len(lm), "right_mapped_bytes": len(rm), "common_addresses": len(common),
            "identical_common_bytes": equal, "different_common_bytes": len(common) - equal,
            "identical_fraction_of_common": f"{equal / len(common):.8f}" if common else "",
            "same_address_map": "yes" if lm.keys() == rm.keys() else "no",
            "whole_image_equal": "yes" if lm == rm else "no",
        })
    write_csv(args.pair_csv, pair_rows, list(pair_rows[0]))

    invalid = [a for a in artifacts if a["errors"] or a["eof_count"] != 1]
    models = sorted({str(a["model"]) for a in artifacts})
    total_bytes = sum(int(a["mapped_bytes"]) for a in artifacts)
    total_records = sum(int(a["record_count"]) for a in artifacts)
    report = [
        "# RK QMK HEX static validation and comparison",
        "",
        "This report parses the seven official QMK Intel HEX downloads recorded in the adjacent artifact ledger. It verifies file SHA-256 against that ledger, validates record framing/checksums and EOF records, builds sparse address maps, and compares bytes at shared addresses. No firmware was executed, disassembled, flashed, or sent to a keyboard.",
        "",
        "## Aggregate results",
        "",
        f"- Artifacts: {len(artifacts)}; model labels: {', '.join(models)}.",
        f"- Parsed Intel HEX records: {total_records}; mapped data bytes summed across images: {total_bytes}.",
        f"- Files with record/checksum/EOF errors: {len(invalid)}.",
        f"- Pairwise image comparisons: {len(pair_rows)}.",
        f"- Row-level results: [`{args.out_csv.name}`]({args.out_csv.name}) and [`{args.pair_csv.name}`]({args.pair_csv.name}).",
        "",
        "## Per-image layout",
        "",
        "| Model | Mode / PID | File | Records | Mapped bytes | Address ranges | Validation |",
        "|---|---|---|---:|---:|---|---|",
    ]
    for row in summary_rows:
        report.append(
            f"| {row['model']} | {row['mode']} / `{row['pid']}` | `{row['filename']}` | {row['record_count']} | {row['mapped_bytes']} | `{row['contiguous_ranges']}` | {row['validation']} ({row['error_count']} errors) |"
        )
    report += [
        "",
        "## Comparison limits",
        "",
        "Address overlap and byte equality are structural comparisons only. They do not identify code/data boundaries, CPU instruction semantics, a boot protocol, model compatibility, or keyboard acceptance. The selector labels and adjacent QMK source package declarations are not hardware verification. Detailed pairwise shared-address counts are preserved in the CSV.",
        "",
        "## Reproduction",
        "",
        "Run from the repository root after the seven official HEX artifacts are present in the ignored sibling research cache:",
        "",
        "```powershell",
        "python scripts/audit_qmk_hex_records.py",
        "```",
        "",
    ]
    args.report.write_text("\n".join(report), encoding="utf-8")
    print(f"validated={len(artifacts)} invalid={len(invalid)} records={total_records} mapped_bytes={total_bytes} pairs={len(pair_rows)}")
    return 1 if invalid else 0


if __name__ == "__main__":
    raise SystemExit(main())
