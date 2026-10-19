#!/usr/bin/env python3
"""Merge reviewed branch-spanning 4.6 API calls into the raw callsite CSV.

This script preserves the original conservative scan and writes a separate
reconciled CSV. It only reads repository CSV files; it never opens a device or
runs a vendor executable.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
REGISTER_CALL_OPCODE = {
    "EAX": "FF D0",
    "ECX": "FF D1",
    "EDX": "FF D2",
    "EBX": "FF D3",
    "ESP": "FF D4",
    "EBP": "FF D5",
    "ESI": "FF D6",
    "EDI": "FF D7",
}
EXTRA_FIELDS = ["iat_load_va", "iat_load_instruction"]


def normalize_dll(value: str) -> str:
    dll = value
    if not dll.upper().endswith(".DLL"):
        dll += ".dll"
    return dll.upper()


def normalize_address(value: str) -> str:
    address = value.strip()
    if address.lower().startswith("0x"):
        return "0x" + address[2:].upper()
    return address.upper()


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, default=root / "docs/rk-v4.6-native-api-call-sites.csv")
    parser.add_argument("--followup", type=Path, default=root / "docs/rk-v4.6-unresolved-api-references.csv")
    parser.add_argument("--output", type=Path, default=root / "docs/rk-v4.6-native-api-call-sites-reconciled.csv")
    args = parser.parse_args()

    with args.raw.open(newline="", encoding="utf-8-sig") as stream:
        raw_reader = csv.DictReader(stream)
        raw_fields = list(raw_reader.fieldnames or [])
        raw_rows = list(raw_reader)
    with args.followup.open(newline="", encoding="utf-8-sig") as stream:
        followup_rows = list(csv.DictReader(stream))

    required_raw_fields = {"site_kind", "iat_va", "dll", "symbol"}
    if not required_raw_fields.issubset(raw_fields):
        parser.error("raw CSV does not have the expected callsite schema")
    if not followup_rows:
        parser.error("follow-up CSV has no rows")

    required_followup_fields = {
        "binary_sha256",
        "dll",
        "symbol",
        "iat_va",
        "iat_load_va",
        "register",
        "register_load_instruction",
        "indirect_call_sites",
        "limitations",
    }
    missing_fields = required_followup_fields - set(followup_rows[0])
    if missing_fields:
        parser.error("follow-up CSV is missing fields: " + ", ".join(sorted(missing_fields)))

    by_iat: dict[str, dict[str, object]] = {}
    for followup in followup_rows:
        digest = str(followup.get("binary_sha256", "")).lower()
        if digest != EXPECTED_SHA256:
            parser.error(f"follow-up row is not pinned to expected binary: {digest}")
        import_key = (normalize_dll(str(followup["dll"])), str(followup["symbol"]))
        register = str(followup["register"]).upper()
        if register not in REGISTER_CALL_OPCODE:
            parser.error(f"unsupported register {register} in {followup['symbol']}")
        iat_va = normalize_address(str(followup["iat_va"])).upper()
        call_sites = [
            normalize_address(part)
            for part in str(followup["indirect_call_sites"]).split(";")
            if part.strip()
        ]
        if not call_sites:
            parser.error(f"no recovered call sites for IAT {iat_va}")
        if len(call_sites) != len(set(call_sites)):
            parser.error(f"duplicate callsite in follow-up row for IAT {iat_va}")
        if iat_va in by_iat:
            parser.error(f"duplicate follow-up IAT VA: {iat_va}")
        by_iat[iat_va] = {
            "import_key": import_key,
            "register": register,
            "load_va": normalize_address(str(followup["iat_load_va"])),
            "load_instruction": str(followup["register_load_instruction"]),
            "call_sites": call_sites,
            "limitations": str(followup["limitations"]),
        }

    out_fields = raw_fields + [field for field in EXTRA_FIELDS if field not in raw_fields]
    reconciled_rows: list[dict[str, str]] = []
    consumed: set[str] = set()
    replaced_placeholders = 0

    for raw in raw_rows:
        iat_va = str(raw["iat_va"]).upper()
        evidence = by_iat.get(iat_va)
        if evidence is None:
            row = dict(raw)
            row.update({field: "" for field in EXTRA_FIELDS})
            reconciled_rows.append(row)
            continue

        raw_key = (str(raw["dll"]).upper(), str(raw["symbol"]))
        if raw_key != evidence["import_key"]:
            parser.error(f"follow-up IAT {iat_va} import name does not match raw CSV")
        consumed.add(iat_va)
        if raw["site_kind"] == "none_decoded":
            replaced_placeholders += 1
            register = str(evidence["register"]).lower()
            for site_va in evidence["call_sites"]:
                row = dict(raw)
                row.update(
                    {
                        "site_kind": "call_iat_register",
                        "site_va": site_va,
                        "matching_thunk_va": "",
                        "instruction_bytes": REGISTER_CALL_OPCODE[str(evidence["register"])],
                        "objdump_decoded_instruction": f"call   *%{register}",
                        "validation_scope": (
                            "Manual static follow-up: hash-pinned IAT load and register call; branch-spanning candidates checked in objdump; "
                            + str(evidence["limitations"])
                        ),
                        "iat_load_va": str(evidence["load_va"]),
                        "iat_load_instruction": str(evidence["load_instruction"]),
                    }
                )
                reconciled_rows.append(row)
        else:
            row = dict(raw)
            row.update({field: "" for field in EXTRA_FIELDS})
            reconciled_rows.append(row)

    missing = sorted(set(by_iat) - consumed)
    if missing:
        parser.error("follow-up imports were not reconciled to raw CSV rows: " + ", ".join(missing))
    if replaced_placeholders != len(by_iat):
        parser.error(f"expected {len(by_iat)} none_decoded rows to replace, found {replaced_placeholders}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=out_fields)
        writer.writeheader()
        writer.writerows(reconciled_rows)

    added_calls = sum(len(value["call_sites"]) for value in by_iat.values())
    remaining_none = sum(row["site_kind"] == "none_decoded" for row in reconciled_rows)
    print(f"followup_imports={len(by_iat)}")
    print(f"replaced_none_decoded_rows={replaced_placeholders}")
    print(f"added_register_call_sites={added_calls}")
    print(f"remaining_none_decoded_rows={remaining_none}")
    print(f"output={args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
