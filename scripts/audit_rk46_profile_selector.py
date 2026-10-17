#!/usr/bin/env python3
"""Reconcile extracted RK 4.6 profile rows with the statically recovered selector.

This script reads the repository's models-4.6.json catalog, whose profileData
was extracted from the V4.6-labeled package's Dev/*/KB.ini files. It does not
launch the vendor program or access a keyboard. The selector/factory branch
labels are manually recovered from the hash-pinned DeviceDriver.exe and are
included as evidence, not inferred from profile names.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def branch(fw_raw: str | None) -> tuple[str, str, str]:
    if fw_raw is None or fw_raw == "0":
        return (
            "Fw zero (omitted value loads as zero)" if fw_raw is None else "Fw zero (explicit)",
            "Selector: FF00 usage 1 with record marker 0x41, OR consumer page 0x000C usage 1 with field -0x0C=3 (PID 0x49 excluded)",
            "0x0040D640",
        )
    try:
        fw = int(fw_raw, 0)
    except ValueError:
        return ("Unparsed Fw value", "Unresolved: value is not a numeric Fw", "unresolved")
    if fw == 3:
        return (
            "Fw 3 dedicated branch",
            "Selector: usage page 0xFF02, usage 2, and capability-record fields -0x0C and -0x08 both equal 0x14",
            "0x0040DAD0",
        )
    return (
        "Fw nonzero other than 3",
        "Selector: general nonzero gate; FF00/FF02 vendor-defined usage/report pattern with marker 0x208, OR consumer page 0x000C usage 1 with field -0x0C=3",
        "0x0040F490",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--models",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "models-4.6.json",
        help="Extracted 4.6 catalog JSON (default: repository models-4.6.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "docs" / "rk-v4.6-profile-selector-map.csv",
    )
    args = parser.parse_args()

    catalog = json.loads(args.models.read_text(encoding="utf-8"))
    vendor_id = str(catalog["vendorId"]).upper().zfill(4)
    rows: list[dict[str, str]] = []
    for model in sorted(catalog["models"], key=lambda item: item["code"]):
        options = model.get("profileData", {}).get("options", {})
        fw_raw = options.get("Fw")
        selector_branch, descriptor_gate, constructor = branch(fw_raw)
        pid = model["code"].upper().zfill(4) if model.get("isDirectPid") else ""
        rows.append(
            {
                "profile_code": model["code"].upper(),
                "model_name": model["name"],
                "usb_vid": vendor_id if pid else "",
                "usb_pid": pid,
                "direct_pid_profile": str(bool(model.get("isDirectPid"))).lower(),
                "fw_raw_kb_ini": "(omitted)" if fw_raw is None else str(fw_raw),
                "selector_branch": selector_branch,
                "descriptor_gate": descriptor_gate,
                "implementation_constructor_va": constructor,
                "psd_raw_kb_ini": str(options.get("Psd", "")),
                "physical_model_support_validated": "no",
            }
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0]) if rows else []
    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} profile rows to {args.output}")


if __name__ == "__main__":
    main()
