#!/usr/bin/env python3
"""Reconcile the 4.6 DeviceDriver global callback cell across two static scans.

The linear sweep inventories absolute references to one callback cell in every
raw executable section. The separate rooted CFG edge ledger provides selected
recursive-path references; its instruction starts can differ from the linear
sweep where decoders begin at different boundaries. This audit preserves those
sources instead of treating either one as a complete code map.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import capstone
import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, CS_GRP_CALL, CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM, X86_OP_MEM


EXPECTED_DRIVER_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
EXPECTED_DRIVER_SIZE = 2_418_176
EXPECTED_ROOT_EDGES_SHA256 = "e0aa66be6a217ed04674457af9e5520ff5e8ff0645301810c2defa244b00ac6c"
IMAGE_BASE = 0x00400000
CALLBACK_CELL = 0x0063BE2C
SELECTOR_CELL = 0x0063BE28
TARGET_DEBUG = 0x0040D000
TARGET_FILE_LOG = 0x0040D090
INITIALIZER = 0x0040D140


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hx(value: int) -> str:
    return f"0x{value:08X}"


def parse_va(value: str) -> int:
    return int(value, 16)


def absolute_mem_operand(operand: Any) -> int | None:
    if operand.type != X86_OP_MEM:
        return None
    mem = operand.mem
    if mem.base != 0 or mem.index != 0:
        return None
    return int(mem.disp) & 0xFFFFFFFF


def section_at(pe: pefile.PE, va: int):
    base = int(pe.OPTIONAL_HEADER.ImageBase)
    for section in pe.sections:
        start = base + int(section.VirtualAddress)
        raw = section.get_data()
        if start <= va < start + len(raw):
            return section, start, raw
    return None


def decode_at(pe: pefile.PE, decoder: capstone.Cs, va: int):
    found = section_at(pe, va)
    if found is None:
        raise ValueError(f"No raw section byte at {hx(va)}")
    _, start, raw = found
    offset = va - start
    return next(decoder.disasm(raw[offset : offset + 15], va, count=1), None)


def import_map(pe: pefile.PE) -> dict[int, str]:
    found: dict[int, str] = {}
    for directory_name in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for descriptor in getattr(pe, directory_name, []):
            dll = descriptor.dll.decode("ascii", "replace")
            for entry in descriptor.imports:
                name = entry.name.decode("ascii", "replace") if entry.name else f"ordinal_{entry.ordinal}"
                found[int(entry.address)] = f"{dll}!{name}"
    return found


def read_utf16z(pe: pefile.PE, va: int) -> str:
    found = section_at(pe, va)
    if found is None:
        raise ValueError(f"No raw section byte for UTF-16 string at {hx(va)}")
    _, start, raw = found
    offset = va - start
    end = offset
    while end + 1 < len(raw) and raw[end : end + 2] != b"\x00\x00":
        end += 2
    return raw[offset:end].decode("utf-16le", "replace")


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "driver",
        nargs="?",
        type=Path,
        default=repo / ".research" / "rk46-extract-full" / "app" / "DeviceDriver.exe",
        help="local hash-matching 4.6 DeviceDriver.exe (kept outside the public repo)",
    )
    parser.add_argument(
        "--edges",
        type=Path,
        default=repo / "docs" / "rk-v4.6-rooted-cfg-edges.csv",
        help="generated rooted-CFG edge ledger for the same binary",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=repo / "docs" / "rk-v4.6-global-log-callback-callsite-ledger-2026-10-25.csv",
    )
    args = parser.parse_args()

    blob = args.driver.read_bytes()
    driver_hash = digest(blob)
    if len(blob) != EXPECTED_DRIVER_SIZE or driver_hash != EXPECTED_DRIVER_SHA256:
        raise SystemExit(
            f"Refusing unexpected driver: size={len(blob)}, sha256={driver_hash}"
        )
    edge_blob = args.edges.read_bytes()
    edge_hash = digest(edge_blob)
    if edge_hash != EXPECTED_ROOT_EDGES_SHA256:
        raise SystemExit(f"Refusing unexpected edge ledger: sha256={edge_hash}")

    pe = pefile.PE(data=blob, fast_load=False)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    if image_base != IMAGE_BASE:
        raise SystemExit(f"Refusing unexpected image base: {hx(image_base)}")
    decoder = capstone.Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True

    linear_references: list[dict[str, Any]] = []
    selector_references: list[Any] = []
    control_references_to_init: list[tuple[int, str]] = []
    immediate_references_to_init: list[tuple[int, str, str]] = []
    section_counts: Counter[str] = Counter()

    for section in pe.sections:
        if not (int(section.Characteristics) & 0x20000000):
            continue
        section_name = section.Name.rstrip(b"\0").decode("ascii", "replace")
        start = image_base + int(section.VirtualAddress)
        for instruction in decoder.disasm(section.get_data(), start):
            for operand in instruction.operands:
                if operand.type == X86_OP_IMM and (int(operand.imm) & 0xFFFFFFFF) == INITIALIZER:
                    immediate_references_to_init.append(
                        (int(instruction.address), instruction.mnemonic, instruction.op_str)
                    )
            if instruction.group(CS_GRP_CALL) or instruction.group(CS_GRP_JUMP):
                if instruction.operands and instruction.operands[0].type == X86_OP_IMM:
                    if (int(instruction.operands[0].imm) & 0xFFFFFFFF) == INITIALIZER:
                        control_references_to_init.append((instruction.address, instruction.mnemonic))
            for operand_index, operand in enumerate(instruction.operands):
                address = absolute_mem_operand(operand)
                if address == SELECTOR_CELL:
                    selector_references.append(instruction)
                if address != CALLBACK_CELL:
                    continue
                row = {
                    "site": int(instruction.address),
                    "section": section_name,
                    "instruction": instruction,
                    "operand_index": operand_index,
                    "kind": "call" if instruction.group(CS_GRP_CALL) else "reference",
                }
                linear_references.append(row)
                section_counts[section_name] += 1

    raw_va_pattern = struct.pack("<I", INITIALIZER)
    raw_rva_pattern = struct.pack("<I", INITIALIZER - IMAGE_BASE)
    raw_va_hits: list[str] = []
    raw_rva_hits: list[str] = []
    for section in pe.sections:
        section_name = section.Name.rstrip(b"\0").decode("ascii", "replace")
        start = image_base + int(section.VirtualAddress)
        raw = section.get_data()
        for pattern, hits in ((raw_va_pattern, raw_va_hits), (raw_rva_pattern, raw_rva_hits)):
            offset = 0
            while True:
                offset = raw.find(pattern, offset)
                if offset < 0:
                    break
                hits.append(f"{section_name}:{hx(start + offset)}")
                offset += 1
    if immediate_references_to_init or raw_va_hits or raw_rva_hits:
        raise SystemExit(
            "Unexpected static initializer references: "
            f"immediates={immediate_references_to_init!r}, "
            f"VA_hits={raw_va_hits!r}, RVA_hits={raw_rva_hits!r}"
        )
    export_count = len(getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []))
    has_tls_callbacks = hasattr(pe, "DIRECTORY_ENTRY_TLS") and bool(
        int(pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks)
    )
    if export_count != 0 or has_tls_callbacks:
        raise SystemExit(
            f"Unexpected PE entry-reference surface: exports={export_count}, tls={has_tls_callbacks}"
        )

    linear_calls: dict[int, Any] = {}
    linear_stores: list[tuple[int, int, Any]] = []
    for row in linear_references:
        instruction = row["instruction"]
        if instruction.mnemonic.lower() == "call" and row["operand_index"] == 0:
            linear_calls[int(instruction.address)] = instruction
        if (
            instruction.mnemonic.lower() == "mov"
            and row["operand_index"] == 0
            and len(instruction.operands) >= 2
            and instruction.operands[1].type == X86_OP_IMM
        ):
            linear_stores.append(
                (int(instruction.address), int(instruction.operands[1].imm) & 0xFFFFFFFF, instruction)
            )

    expected_stores = [(0x0040D18D, TARGET_DEBUG), (0x0040D23F, TARGET_FILE_LOG)]
    observed_stores = sorted((site, target) for site, target, _ in linear_stores)
    if len(linear_references) != 260 or len(linear_calls) != 258:
        raise SystemExit(
            f"Unexpected linear reference census: {len(linear_references)} refs, "
            f"{len(linear_calls)} call sites"
        )
    if observed_stores != expected_stores:
        raise SystemExit(f"Unexpected callback-cell stores: {observed_stores!r}")
    if Counter(row["instruction"].mnemonic.lower() for row in linear_references) != Counter(
        {"call": 258, "mov": 2}
    ):
        raise SystemExit("Unexpected instruction kinds reference the callback cell")
    if len(selector_references) != 14 or any(
        instruction.mnemonic.lower() != "cmp" for instruction in selector_references
    ):
        raise SystemExit("Unexpected direct-reference census for the selector cell")

    with args.edges.open("r", encoding="utf-8", newline="") as stream:
        edge_rows = list(csv.DictReader(stream))
    rooted_rows = [
        row
        for row in edge_rows
        if row.get("edge_kind") == "unresolved_indirect_call"
        and "63be2c" in (row.get("note") or "").lower()
    ]
    rooted_by_site: dict[int, list[dict[str, str]]] = defaultdict(list)
    for row in rooted_rows:
        rooted_by_site[parse_va(row["site_va"])].append(row)
    if len(rooted_rows) != 234 or len(rooted_by_site) != 234:
        raise SystemExit(
            f"Unexpected rooted pointer-edge census: {len(rooted_rows)} contexts, "
            f"{len(rooted_by_site)} distinct sites"
        )

    # The CFG uses recursive path boundaries; verify every site it labels as a
    # call through the cell from the instruction start recorded in its ledger.
    for site, rows in rooted_by_site.items():
        instruction = decode_at(pe, decoder, site)
        if instruction is None or instruction.mnemonic.lower() != "call":
            raise SystemExit(f"Rooted edge site does not decode as a call: {hx(site)}")
        if not instruction.operands or absolute_mem_operand(instruction.operands[0]) != CALLBACK_CELL:
            raise SystemExit(f"Rooted edge operand mismatch at {hx(site)}")

    linear_sites = set(linear_calls)
    rooted_sites = set(rooted_by_site)
    overlap = linear_sites & rooted_sites
    rooted_only = rooted_sites - linear_sites
    linear_only = linear_sites - rooted_sites
    if (len(overlap), len(rooted_only), len(linear_only)) != (203, 31, 55):
        raise SystemExit(
            "Unexpected decoder-boundary reconciliation: "
            f"overlap={len(overlap)}, rooted-only={len(rooted_only)}, "
            f"linear-only={len(linear_only)}"
        )

    imports = import_map(pe)
    expected_imports = {
        0x005A6458: "KERNEL32.dll!GetLocalTime",
        0x005A645C: "KERNEL32.dll!OutputDebugStringW",
        0x005A6534: "SHELL32.dll!SHGetSpecialFolderPathW",
    }
    for address, expected in expected_imports.items():
        if imports.get(address, "").lower() != expected.lower():
            raise SystemExit(f"Unexpected IAT mapping at {hx(address)}: {imports.get(address)!r}")
    expected_import_calls = {
        0x0040D068: 0x005A645C,
        0x0040D0C8: 0x005A645C,
        0x0040D0D7: 0x005A6458,
        0x0040D15F: 0x005A6534,
    }
    for site, iat in expected_import_calls.items():
        instruction = decode_at(pe, decoder, site)
        if (
            instruction is None
            or instruction.mnemonic.lower() != "call"
            or not instruction.operands
            or absolute_mem_operand(instruction.operands[0]) != iat
        ):
            raise SystemExit(f"Unexpected imported call at {hx(site)}")
    expected_strings = {
        0x005D16A4: "a",
        0x005D16A8: "Open Log failed",
        0x005D16C8: "\n",
        0x005D16CC: "%02u:%02u.%03u   ",
        0x005D16F0: "%s\\Log.txt",
        0x005D1708: "w",
    }
    for address, expected in expected_strings.items():
        if read_utf16z(pe, address) != expected:
            raise SystemExit(f"Unexpected string at {hx(address)}: {read_utf16z(pe, address)!r}")

    sites = sorted(linear_sites | rooted_sites)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "site_va",
        "evidence_sources",
        "rooted_context_count",
        "root_caller_vas",
        "instruction",
        "bytes_hex",
        "target_candidate_vas",
        "classification",
        "limitation",
    ]
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for site in sites:
            sources = []
            if site in linear_sites:
                sources.append("full-executable-section-linear-sweep")
            if site in rooted_sites:
                sources.append("rooted-CFG-edge-ledger")
            instruction = linear_calls.get(site)
            if instruction is None:
                instruction = decode_at(pe, decoder, site)
            rows = rooted_by_site.get(site, [])
            writer.writerow(
                {
                    "site_va": hx(site),
                    "evidence_sources": ";".join(sources),
                    "rooted_context_count": len(rows),
                    "root_caller_vas": ";".join(sorted({row["caller_root_va"] for row in rows})),
                    "instruction": f"{instruction.mnemonic} {instruction.op_str}".strip(),
                    "bytes_hex": bytes(instruction.bytes).hex(" ").upper(),
                    "target_candidate_vas": f"{hx(TARGET_DEBUG)};{hx(TARGET_FILE_LOG)}",
                    "classification": "shared-global-callback; conditional-log-target-set",
                    "limitation": (
                        "Targets are assigned by 0x0040D140 in the linear sweep; "
                        "initializer execution, selector value, aliases/writes outside the scan, "
                        "and runtime target are unproven."
                    ),
                }
            )

    print(f"driver_sha256={driver_hash}")
    print(f"root_edges_sha256={edge_hash}")
    print(f"linear_absolute_refs={len(linear_references)} calls={len(linear_calls)} stores={len(linear_stores)}")
    print(f"linear_sections={dict(section_counts)}")
    print(f"rooted_contexts={len(rooted_rows)} rooted_sites={len(rooted_sites)}")
    print(f"linear_rooted_overlap={len(overlap)} rooted_only={len(rooted_only)} linear_only={len(linear_only)}")
    print(f"selector_absolute_refs={len(selector_references)} selector_ref_mnemonics=cmp-only")
    print(f"initializer_direct_control_refs_in_linear_sweep={len(control_references_to_init)}")
    print("initializer_code_immediates=0 raw_va_pointers=0 raw_rva_pointers=0 exports=0 tls_callbacks=0")
    print(f"candidate_stores={[(hx(site), hx(target)) for site, target, _ in linear_stores]}")
    print(f"ledger_rows={len(sites)} output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
