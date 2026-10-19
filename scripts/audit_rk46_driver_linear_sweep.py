#!/usr/bin/env python3
"""Hash-pinned, static linear-sweep inventory for RK DeviceDriver.exe 4.6.

This intentionally does not claim function boundaries, a complete CFG, or
runtime reachability. See docs/rk-v4.6-driver-linear-sweep-inventory.md.
Requires pefile and Capstone 5.x. It never loads or executes the input image.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import capstone
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG


EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
EXPECTED_SIZE = 2_418_176


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hx(value: int | None) -> str:
    return "" if value is None else f"0x{value:08x}"


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def section_label(section: Any) -> str:
    return section.Name.rstrip(b"\0").decode("ascii", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Path to the extracted DeviceDriver.exe")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(".research/rk46_driver_linear_sweep"),
        help="Directory for deterministic JSON and CSV ledgers (default: %(default)s)",
    )
    args = parser.parse_args()

    image_path = args.image.resolve()
    image = image_path.read_bytes()
    actual_hash = sha256(image)
    if len(image) != EXPECTED_SIZE or actual_hash != EXPECTED_SHA256:
        print(
            f"Refusing unexpected input: size={len(image)} sha256={actual_hash}; "
            f"expected size={EXPECTED_SIZE} sha256={EXPECTED_SHA256}",
            file=sys.stderr,
        )
        return 2

    pe = pefile.PE(data=image, fast_load=False)
    if pe.FILE_HEADER.Machine != 0x014C or pe.OPTIONAL_HEADER.Magic != 0x010B:
        print("Refusing unexpected PE architecture (expected x86 PE32)", file=sys.stderr)
        return 2

    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    entry_va = image_base + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    md.skipdata = True

    executable_sections: list[dict[str, Any]] = []
    instructions: list[dict[str, Any]] = []
    direct_transfers: list[dict[str, Any]] = []
    indirect_transfers: list[dict[str, Any]] = []
    returns: list[dict[str, Any]] = []
    undecoded_runs: list[dict[str, Any]] = []
    decoded_va: set[int] = set()
    code_sections = [
        section
        for section in pe.sections
        if int(section.Characteristics) & 0x20000000  # IMAGE_SCN_MEM_EXECUTE
    ]
    executable_ranges = [
        (
            image_base + int(section.VirtualAddress),
            image_base + int(section.VirtualAddress) + len(section.get_data()),
            section_label(section),
        )
        for section in code_sections
    ]

    for section in code_sections:
        name = section_label(section)
        raw = bytes(section.get_data())
        start_va = image_base + int(section.VirtualAddress)

        section_instructions = 0
        section_decoded_bytes = 0
        section_invalid_bytes = 0
        pending_gap_start: int | None = None
        pending_gap = bytearray()

        def close_gap() -> None:
            nonlocal pending_gap_start, pending_gap
            if pending_gap_start is None:
                return
            file_off = int(section.PointerToRawData) + pending_gap_start
            gap = bytes(pending_gap)
            undecoded_runs.append(
                {
                    "section": name,
                    "start_va": hx(start_va + pending_gap_start),
                    "start_rva": hx(int(section.VirtualAddress) + pending_gap_start),
                    "file_offset": hx(file_off),
                    "length_bytes": len(gap),
                    "sha256": sha256(gap),
                    "hex_bytes": gap.hex(),
                }
            )
            pending_gap_start = None
            pending_gap = bytearray()

        for decoded in md.disasm(raw, start_va):
            offset = int(decoded.address) - start_va
            if decoded.mnemonic == ".byte":
                if pending_gap_start is None:
                    pending_gap_start = offset
                pending_gap.extend(decoded.bytes)
                section_invalid_bytes += int(decoded.size)
                continue

            close_gap()
            va = int(decoded.address)
            size = int(decoded.size)
            encoded = bytes(decoded.bytes)
            decoded_va.add(va)
            section_instructions += 1
            section_decoded_bytes += size
            is_call = decoded.mnemonic.lower().startswith("call") or decoded.group(capstone.CS_GRP_CALL)
            is_jump = decoded.group(capstone.CS_GRP_JUMP)
            is_ret = decoded.group(capstone.CS_GRP_RET) or decoded.mnemonic.lower().startswith(("ret", "iret"))
            target: int | None = None
            transfer_kind = ""

            if decoded.operands and decoded.operands[0].type == X86_OP_IMM and (is_call or is_jump):
                target = int(decoded.operands[0].imm) & 0xFFFFFFFF
                transfer_kind = "direct_call" if is_call else (
                    "direct_jump_unconditional" if decoded.mnemonic.lower() == "jmp" else "direct_jump_conditional"
                )
                target_is_exec = any(lo <= target < hi for lo, hi, _ in executable_ranges)
                direct_transfers.append(
                    {
                        "site_va": hx(va),
                        "site_rva": hx(va - image_base),
                        "section": name,
                        "kind": transfer_kind,
                        "target_va": hx(target),
                        "target_rva": hx(target - image_base),
                        "target_in_executable_section": str(target_is_exec).lower(),
                        "bytes": encoded.hex(),
                        "mnemonic": decoded.mnemonic,
                        "operands": decoded.op_str,
                    }
                )
            elif is_call or is_jump:
                transfer_kind = "indirect_call" if is_call else "indirect_jump"
                operand = decoded.operands[0] if decoded.operands else None
                if operand is None:
                    operand_kind, operand_text = "unknown", decoded.op_str
                elif operand.type == X86_OP_REG:
                    operand_kind, operand_text = "register", decoded.reg_name(operand.reg)
                elif operand.type == X86_OP_MEM:
                    operand_kind = "memory"
                    mem = operand.mem
                    pieces = []
                    if mem.segment:
                        pieces.append(decoded.reg_name(mem.segment) + ":")
                    if mem.base:
                        pieces.append(decoded.reg_name(mem.base))
                    if mem.index:
                        pieces.append("+" + decoded.reg_name(mem.index) + "*" + str(mem.scale))
                    if mem.disp:
                        pieces.append(f"{mem.disp:+#x}")
                    operand_text = "".join(pieces) or decoded.op_str
                else:
                    operand_kind, operand_text = "other", decoded.op_str
                indirect_transfers.append(
                    {
                        "site_va": hx(va),
                        "site_rva": hx(va - image_base),
                        "section": name,
                        "kind": transfer_kind,
                        "operand_kind": operand_kind,
                        "operand": operand_text,
                        "bytes": encoded.hex(),
                        "mnemonic": decoded.mnemonic,
                        "operands": decoded.op_str,
                    }
                )

            if is_ret:
                returns.append(
                    {
                        "site_va": hx(va),
                        "site_rva": hx(va - image_base),
                        "section": name,
                        "bytes": encoded.hex(),
                        "mnemonic": decoded.mnemonic,
                        "operands": decoded.op_str,
                    }
                )

            instructions.append(
                {
                    "address_va": hx(va),
                    "address_rva": hx(va - image_base),
                    "file_offset": hx(int(section.PointerToRawData) + offset),
                    "size_bytes": size,
                    "bytes": encoded.hex(),
                    "section": name,
                    "mnemonic": decoded.mnemonic,
                    "operands": decoded.op_str,
                    "transfer_kind": transfer_kind,
                    "direct_target_va": hx(target),
                }
            )
        close_gap()

        executable_sections.append(
            {
                "name": name,
                "rva": hx(int(section.VirtualAddress)),
                "va_start": hx(start_va),
                "raw_file_offset": hx(int(section.PointerToRawData)),
                "raw_size_bytes": len(raw),
                "raw_sha256": sha256(raw),
                "linear_decoded_instruction_count": section_instructions,
                "linear_decoded_bytes": section_decoded_bytes,
                "undecoded_bytes": section_invalid_bytes,
            }
        )

    # Roots are metadata roots only. The scan itself remains a full linear sweep;
    # this ledger merely records what the PE advertises as explicit entry roots.
    roots: list[dict[str, str]] = [
        {
            "kind": "pe_entrypoint",
            "va": hx(entry_va),
            "rva": hx(entry_va - image_base),
            "has_linear_instruction_boundary": str(entry_va in decoded_va).lower(),
        }
    ]
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if symbol.address and not symbol.forwarder:
                va = image_base + int(symbol.address)
                roots.append(
                    {
                        "kind": "export",
                        "va": hx(va),
                        "rva": hx(int(symbol.address)),
                        "has_linear_instruction_boundary": str(va in decoded_va).lower(),
                    }
                )
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls is not None:
        for callback in tls.struct.AddressOfCallBacks_array or []:
            va = int(callback.address)
            roots.append(
                {
                    "kind": "tls_callback",
                    "va": hx(va),
                    "rva": hx(va - image_base),
                    "has_linear_instruction_boundary": str(va in decoded_va).lower(),
                }
            )

    target_counts = Counter(row["target_va"] for row in direct_transfers if row["target_in_executable_section"] == "true")
    section_total = sum(row["raw_size_bytes"] for row in executable_sections)
    decoded_total = sum(row["linear_decoded_bytes"] for row in executable_sections)
    invalid_total = sum(row["undecoded_bytes"] for row in executable_sections)
    summary = {
        "analysis": "linear sweep of PE executable sections",
        "completeness_label": "not a complete CFG or function map",
        "input": {
            "filename": image_path.name,
            "file_size_bytes": len(image),
            "sha256": actual_hash,
            "machine": f"0x{pe.FILE_HEADER.Machine:04x}",
            "pe32_magic": f"0x{pe.OPTIONAL_HEADER.Magic:04x}",
            "image_base": hx(image_base),
            "entrypoint_va": hx(entry_va),
            "entrypoint_rva": hx(entry_va - image_base),
        },
        "tooling": {
            "python": sys.version.split()[0],
            "pefile": getattr(pefile, "__version__", "unknown"),
            "capstone": capstone.__version__,
            "decoder": "Capstone x86 32-bit; sequential linear sweep; skipdata advances one byte on undecodable input",
        },
        "executable_sections": executable_sections,
        "totals": {
            "executable_raw_bytes": section_total,
            "linear_decoded_instruction_boundaries": len(instructions),
            "linear_decoded_bytes": decoded_total,
            "undecoded_bytes": invalid_total,
            "undecoded_runs": len(undecoded_runs),
            "direct_call_or_jump_sites": len(direct_transfers),
            "direct_targets_inside_executable_sections": sum(1 for row in direct_transfers if row["target_in_executable_section"] == "true"),
            "unique_direct_targets_inside_executable_sections": len(target_counts),
            "indirect_call_or_jump_candidates": len(indirect_transfers),
            "return_sites": len(returns),
            "explicit_roots": len(roots),
        },
        "limits": [
            "Linear sweep can decode embedded constants, jump tables, resource-like bytes, alignment padding, or other non-code as instructions.",
            "An undecoded byte is not proof of data; it can also be an unsupported encoding or truncation.",
            "Direct branch targets are syntactic candidates and do not prove reachability or function entry.",
            "Indirect call/jump rows do not resolve vtables, callbacks, COM targets, computed dispatch, or dynamically loaded code.",
            "A return-site count is a decoded mnemonic count and does not establish function boundaries or balanced call/return behavior.",
            "No vendor program was launched and no HID, serial, Bluetooth, or other device I/O was performed.",
        ],
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_csv(
        args.output_dir / "linear-instructions.csv",
        ["address_va", "address_rva", "file_offset", "size_bytes", "bytes", "section", "mnemonic", "operands", "transfer_kind", "direct_target_va"],
        instructions,
    )
    write_csv(
        args.output_dir / "direct-transfers.csv",
        ["site_va", "site_rva", "section", "kind", "target_va", "target_rva", "target_in_executable_section", "bytes", "mnemonic", "operands"],
        direct_transfers,
    )
    write_csv(
        args.output_dir / "indirect-transfers.csv",
        ["site_va", "site_rva", "section", "kind", "operand_kind", "operand", "bytes", "mnemonic", "operands"],
        indirect_transfers,
    )
    write_csv(
        args.output_dir / "returns.csv",
        ["site_va", "site_rva", "section", "bytes", "mnemonic", "operands"],
        returns,
    )
    write_csv(
        args.output_dir / "undecoded-runs.csv",
        ["section", "start_va", "start_rva", "file_offset", "length_bytes", "sha256", "hex_bytes"],
        undecoded_runs,
    )
    write_csv(
        args.output_dir / "explicit-roots.csv",
        ["kind", "va", "rva", "has_linear_instruction_boundary"],
        roots,
    )
    print(json.dumps(summary["totals"], indent=2, sort_keys=True))
    print(f"Wrote deterministic inventory to {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
