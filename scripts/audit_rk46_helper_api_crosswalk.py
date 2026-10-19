#!/usr/bin/env python3
"""Crosswalk unchanged RK 4.6 helper PEs to their hash-pinned 4.06 API audit.

This reads the extracted package files, verifies both package manifests, checks
their PE import rows against the existing 4.06 IAT cross-reference, and emits a
4.6-labelled API/callsite CSV. It never launches a vendor binary and performs
no device I/O.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path

import pefile


EXPECTED = {
    "Update.exe": {
        "package_path": "app/Dev/01AF/Update.exe",
        "baseline_path": "Dev/01AF/Update.exe",
        "size": 2_109_952,
        "sha256": "27894463B0DFE5BC3F5DC19D4D3351D9DFB692C402BF277BDE3889D37E4A206C",
    },
    "InitSetup.dll": {
        "package_path": "app/InitSetup.dll",
        "baseline_path": "InitSetup.dll",
        "size": 69_000,
        "sha256": "59DB7BFD9A92CC9A0998260807F17C536EC71159B727DF10D08B998BC94DE301",
    },
    "uninstall.dll": {
        "package_path": "app/uninstall.dll",
        "baseline_path": "uninstall.dll",
        "size": 146_944,
        "sha256": "9CA1EBC49998B8B2971DEBC1776E7AFF6086AEB86ADCCA6CFB95E9FB399EB03C",
    },
}

# Instruction addresses reported by the existing hash-pinned 4.06
# rk-native-api-indirect-call-audit.md. The 4.6 files below are byte-identical
# to those 4.06 files, so the addresses and instruction bytes transfer exactly.
REGISTER_CALLS = {
    ("Update.exe", "VerSetConditionMask"): "0x0045190F;0x00451913",
    ("Update.exe", "SetErrorMode"): "0x00437581;0x00437589",
    ("Update.exe", "EnumFontFamiliesW"): "0x00451D9C;0x00451DC5",
    ("Update.exe", "LPtoDP"): "0x005318A8;0x005318C3;0x005318DE",
    ("Update.exe", "RegEnumValueW"): "0x00426E16",
    ("Update.exe", "SHAppBarMessage"): "0x004C5BED;0x004C5C07;0x004C5C1D;0x004C5C36",
    ("Update.exe", "PlaySoundW"): "0x004D28F5;0x004D2934",
    ("InitSetup.dll", "DeleteFileW"): "0x10001273",
    ("InitSetup.dll", "GetEnvironmentStringsW"): "0x10003A28;0x10003A63",
    ("uninstall.dll", "_decode_pointer"): "0x100011D9;0x100011ED;0x10001214;0x1000122A;0x10001235;0x100014EF;0x10001518;0x10001523",
    ("uninstall.dll", "InterlockedCompareExchange"): "0x100010D2;0x100011A7",
}

# Direct `jmp [IAT]` instructions documented in the same 4.06 audit. These
# are distinct from relative tail-jumps to import thunks in the xref CSV.
IAT_TAIL_JUMPS = {
    ("Update.exe", "PostQuitMessage"): "0x00413601",
    ("Update.exe", "GetThemeSysColor"): "0x004E92CF",
    ("Update.exe", "OleFlushClipboard"): "0x00427FE1",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_manifest(path: Path, path_field: str) -> dict[str, dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = {}
        for row in csv.DictReader(stream):
            key = row[path_field].replace("\\", "/").casefold()
            if key in rows:
                raise ValueError(f"duplicate manifest path: {row[path_field]}")
            rows[key] = row
    return rows


def verify_hash(path: Path, expected_size: int, expected_sha256: str) -> bytes:
    data = path.read_bytes()
    actual = sha256_bytes(data)
    if len(data) != expected_size or actual != expected_sha256:
        raise ValueError(
            f"hash/size mismatch for {path}: {len(data)} bytes, {actual}"
        )
    return data


def imported_rows(pe: pefile.PE) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    base = int(pe.OPTIONAL_HEADER.ImageBase)
    for kind, attr in (("ordinary", "DIRECTORY_ENTRY_IMPORT"), ("delay", "DIRECTORY_ENTRY_DELAY_IMPORT")):
        for descriptor in getattr(pe, attr, []):
            dll = descriptor.dll.decode("ascii", errors="replace")
            for item in descriptor.imports:
                api = item.name.decode("ascii", errors="replace") if item.name else f"ordinal:{item.ordinal}"
                out.append(
                    {
                        "import_kind": kind,
                        "dll": dll,
                        "api": api,
                        "iat_rva": f"0x{int(item.address) - base:08X}",
                    }
                )
    return out


def xref_key(row: dict[str, str]) -> tuple[str, str, str, str]:
    return (
        row["binary"].casefold(),
        row["dll"].casefold(),
        row["api"].casefold(),
        f"0x{int(row['iat_rva'], 16):08x}",
    )


def main() -> None:
    repo = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rk-root",
        type=Path,
        default=repo.parent / ".research" / "rk4_6_official_extract_20261015",
        help="root of the extracted 4.6-labeled package snapshot",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=repo / "docs" / "rk-v4.6-helper-api-callsite-crosswalk.csv",
    )
    args = parser.parse_args()

    package_manifest = read_manifest(repo / "docs/rk-4.6-package-manifest.csv", "path")
    baseline_manifest = read_manifest(repo / "docs/rk-installed-package-manifest.csv", "relative_path")
    with (repo / "docs/rk-native-api-xrefs.csv").open(
        "r", encoding="utf-8-sig", newline=""
    ) as stream:
        xrefs = list(csv.DictReader(stream))
    xref_by_key = {xref_key(row): row for row in xrefs}

    output_rows: list[dict[str, str]] = []
    for binary, identity in EXPECTED.items():
        package_rel = identity["package_path"]
        baseline_rel = identity["baseline_path"]
        package_entry = package_manifest.get(package_rel.casefold())
        baseline_entry = baseline_manifest.get(baseline_rel.casefold())
        if package_entry is None or baseline_entry is None:
            raise ValueError(f"missing manifest entry for {binary}")
        if int(package_entry["size_bytes"]) != identity["size"] or package_entry["sha256"].upper() != identity["sha256"]:
            raise ValueError(f"4.6 manifest identity differs for {binary}")
        if int(baseline_entry["size_bytes"]) != identity["size"] or baseline_entry["sha256"].upper() != identity["sha256"]:
            raise ValueError(f"4.06 installed-manifest identity differs for {binary}")

        data = verify_hash(args.rk_root / package_rel, identity["size"], identity["sha256"])
        pe = pefile.PE(data=data, fast_load=False)
        imports = imported_rows(pe)
        pe_keys = {
            (binary.casefold(), item["dll"].casefold(), item["api"].casefold(), item["iat_rva"].lower())
            for item in imports
        }
        binary_xrefs = [row for row in xrefs if row["binary"] == binary]
        xref_keys = {xref_key(row) for row in binary_xrefs}
        if pe_keys != xref_keys:
            missing = sorted(pe_keys - xref_keys)[:5]
            extra = sorted(xref_keys - pe_keys)[:5]
            raise ValueError(f"import/xref mismatch for {binary}: missing={missing}, extra={extra}")

        for item in imports:
            key = (binary.casefold(), item["dll"].casefold(), item["api"].casefold(), item["iat_rva"].lower())
            xref = xref_by_key[key]
            register_sites = REGISTER_CALLS.get((binary, item["api"]), "")
            iat_tail_jumps = IAT_TAIL_JUMPS.get((binary, item["api"]), "")
            transfer_fields = (
                xref["direct_call_iat_sites"],
                xref["direct_calls_to_iat_thunk"],
                xref["tail_jumps_to_iat_thunk"],
                register_sites,
                iat_tail_jumps,
            )
            has_transfer = any(value.strip() for value in transfer_fields)
            if binary == "uninstall.dll" and item["api"] == "_adjust_fdiv":
                status = "imported data value; no call recovered"
            elif (binary, item["api"]) == ("Update.exe", "LoadLibraryA") or (binary, item["api"]) == ("Update.exe", "GetModuleHandleA"):
                status = "unresolved ANSI loader row; see named audit"
            elif has_transfer:
                status = "static transfer site mapped"
            elif xref["other_iat_reference_sites"]:
                status = "IAT reference found; call/callback target unresolved"
            else:
                status = "no call route listed; not evidence of runtime non-use"
            output_rows.append(
                {
                    "package_binary": binary,
                    "package_path": package_rel,
                    "package_sha256": identity["sha256"],
                    "baseline_path": baseline_rel,
                    "baseline_sha256": identity["sha256"],
                    "byte_identical_to_4_06": "true",
                    "import_kind": item["import_kind"],
                    "dll": item["dll"],
                    "api": item["api"],
                    "iat_rva": item["iat_rva"],
                    "direct_call_iat_sites": xref["direct_call_iat_sites"],
                    "direct_calls_to_iat_thunk": xref["direct_calls_to_iat_thunk"],
                    "tail_jumps_to_iat_thunk": xref["tail_jumps_to_iat_thunk"],
                    "direct_jmp_iat_sites": iat_tail_jumps,
                    "register_indirect_call_sites": register_sites,
                    "other_iat_reference_sites": xref["other_iat_reference_sites"],
                    "static_coverage_status": status,
                }
            )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(output_rows[0])
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)
    print(f"Wrote {len(output_rows)} imported API rows to {args.output}")
    for binary in EXPECTED:
        count = sum(row["package_binary"] == binary for row in output_rows)
        register_count = sum(
            len(row["register_indirect_call_sites"].split(";"))
            for row in output_rows
            if row["package_binary"] == binary and row["register_indirect_call_sites"]
        )
        print(f"{binary}: {count} import rows, {register_count} reviewed register-indirect callsites")


if __name__ == "__main__":
    main()
