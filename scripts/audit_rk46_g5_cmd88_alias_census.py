#!/usr/bin/env python3
"""Reproduce a hash-pinned static caller/alias census for the V4.6 G5 read.

This reads but never executes the supplied DeviceDriver.exe. It does not open
HID, call the updater, or interact with a keyboard. The census is bounded to
the decoded executable PE sections, exact direct transfers, exact virtual-slot
displacements, and a linear register-taint pattern described in the report.
It is not a complete call graph or proof that an indirect target is unreachable.

Requires Python 3, pefile, and Capstone 5.x. Example:
  python scripts/audit_rk46_g5_cmd88_alias_census.py \
    .research/rk4_6_official_extract_20261015/app/DeviceDriver.exe
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

import capstone
import pefile
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG


EXPECTED_SIZE = 2_418_176
EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
IMAGE_BASE = 0x00400000
WRAPPER_VA = 0x00411030
HELPER_VA = 0x00410890
VTABLE_VA = 0x005D3D0C
SLOT_DISP = 0x70
TAIL_CONTEXTS = {
    0x0047FFA0: 0x0047FF7A,
    0x004EDD9E: 0x004EDD8D,
    0x0051B04E: 0x0051B02B,
}


def hx(value: int) -> str:
    return f"0x{value:08X}"


def parent_register(md: capstone.Cs, register_id: int) -> str:
    name = md.reg_name(register_id).lower()
    groups = {
        "eax": {"eax", "ax", "al", "ah"},
        "ebx": {"ebx", "bx", "bl", "bh"},
        "ecx": {"ecx", "cx", "cl", "ch"},
        "edx": {"edx", "dx", "dl", "dh"},
        "esi": {"esi", "si"},
        "edi": {"edi", "di"},
        "ebp": {"ebp", "bp"},
        "esp": {"esp", "sp"},
    }
    for parent, aliases in groups.items():
        if name in aliases:
            return parent
    return name


def raw_occurrences(data: bytes, va: int, pe: pefile.PE) -> list[dict[str, Any]]:
    needle = struct.pack("<I", va)
    output: list[dict[str, Any]] = []
    cursor = 0
    while True:
        offset = data.find(needle, cursor)
        if offset < 0:
            return output
        section_name = None
        occurrence_va = None
        for section in pe.sections:
            raw_start = int(section.PointerToRawData)
            raw_end = raw_start + len(section.get_data())
            if raw_start <= offset < raw_end:
                section_name = section.Name.rstrip(b"\0").decode("ascii", errors="replace")
                occurrence_va = (
                    int(pe.OPTIONAL_HEADER.ImageBase)
                    + int(section.VirtualAddress)
                    + offset
                    - raw_start
                )
                break
        output.append(
            {
                "file_offset": hx(offset),
                "va": hx(occurrence_va) if occurrence_va is not None else None,
                "section": section_name,
                "aligned_dword": offset % 4 == 0,
            }
        )
        cursor = offset + 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Hash-pinned extracted V4.6 DeviceDriver.exe")
    args = parser.parse_args()

    path = args.image.resolve()
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        print(
            f"Refusing unexpected image: size={len(data)} sha256={digest}; "
            f"expected size={EXPECTED_SIZE} sha256={EXPECTED_SHA256}",
            file=sys.stderr,
        )
        return 2

    pe = pefile.PE(data=data, fast_load=False)
    if int(pe.FILE_HEADER.Machine) != 0x014C or int(pe.OPTIONAL_HEADER.Magic) != 0x010B:
        print("Refusing unexpected PE architecture; expected x86 PE32", file=sys.stderr)
        return 2
    if int(pe.OPTIONAL_HEADER.ImageBase) != IMAGE_BASE:
        print("Refusing unexpected image base", file=sys.stderr)
        return 2

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    md.skipdata = True

    instructions = []
    executable_sections = []
    for section in pe.sections:
        if not int(section.Characteristics) & 0x20000000:
            continue
        start = IMAGE_BASE + int(section.VirtualAddress)
        raw = bytes(section.get_data())
        executable_sections.append(
            {"name": section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
             "start_va": hx(start), "raw_size": len(raw)}
        )
        instructions.extend(md.disasm(raw, start))

    direct_transfers: dict[str, list[dict[str, str]]] = {
        "wrapper": [], "helper": []
    }
    slot_transfers: list[dict[str, str]] = []
    slot_register_loads: list[tuple[int, str]] = []
    for ins in instructions:
        if ins.mnemonic in ("call", "jmp") and ins.operands:
            operand = ins.operands[0]
            if operand.type == X86_OP_IMM and operand.imm in (WRAPPER_VA, HELPER_VA):
                key = "wrapper" if operand.imm == WRAPPER_VA else "helper"
                direct_transfers[key].append(
                    {"site": hx(ins.address), "mnemonic": ins.mnemonic,
                     "target": hx(operand.imm), "bytes": ins.bytes.hex(" ").upper()}
                )
            elif operand.type == X86_OP_MEM and operand.mem.disp == SLOT_DISP:
                base = parent_register(md, operand.mem.base) if operand.mem.base else ""
                if base not in ("esp", "ebp"):
                    slot_transfers.append(
                        {"site": hx(ins.address), "mnemonic": ins.mnemonic,
                         "operand": ins.op_str, "bytes": ins.bytes.hex(" ").upper()}
                    )
        if (
            ins.mnemonic == "mov"
            and len(ins.operands) >= 2
            and ins.operands[0].type == X86_OP_REG
            and ins.operands[1].type == X86_OP_MEM
            and ins.operands[1].mem.disp == SLOT_DISP
        ):
            mem = ins.operands[1].mem
            base = parent_register(md, mem.base) if mem.base else ""
            if base not in ("esp", "ebp"):
                slot_register_loads.append((ins.address, parent_register(md, ins.operands[0].reg)))

    # Taint a register after a vtable-slot load, propagate plain register MOVs,
    # and look for an indirect call/jump through the same value. Conditional
    # branch fall-through is retained; unconditional JMP/RET ends the linear
    # path. This is deliberately a bounded byte-order check, not path exploration.
    aliases: list[dict[str, str]] = []
    taint: dict[str, int] = {}
    for ins in instructions:
        if ins.mnemonic in ("call", "jmp") and ins.operands and ins.operands[0].type == X86_OP_REG:
            target_reg = parent_register(md, ins.operands[0].reg)
            if target_reg in taint:
                aliases.append(
                    {"load_site": hx(taint[target_reg]), "transfer_site": hx(ins.address),
                     "mnemonic": ins.mnemonic, "register": target_reg}
                )

        try:
            _, written_ids = ins.regs_access()
            written = {parent_register(md, reg) for reg in written_ids}
        except Exception:
            written = set()

        if (
            ins.mnemonic == "mov"
            and len(ins.operands) >= 2
            and ins.operands[0].type == X86_OP_REG
            and ins.operands[1].type == X86_OP_REG
        ):
            dst = parent_register(md, ins.operands[0].reg)
            src = parent_register(md, ins.operands[1].reg)
            source_site = taint.get(src)
            for reg in written:
                taint.pop(reg, None)
            if source_site is not None:
                taint[dst] = source_site
        else:
            for reg in written:
                taint.pop(reg, None)
            if (
                ins.mnemonic == "mov"
                and len(ins.operands) >= 2
                and ins.operands[0].type == X86_OP_REG
                and ins.operands[1].type == X86_OP_MEM
            ):
                mem = ins.operands[1].mem
                base = parent_register(md, mem.base) if mem.base else ""
                if mem.disp == SLOT_DISP and base not in ("esp", "ebp"):
                    taint[parent_register(md, ins.operands[0].reg)] = ins.address

        if ins.mnemonic == "jmp" or ins.mnemonic.startswith("ret"):
            taint.clear()

    entry_transfers: dict[str, dict[str, list[str]]] = {}
    entries = set(TAIL_CONTEXTS.values())
    for ins in instructions:
        if ins.mnemonic in ("call", "jmp") and ins.operands and ins.operands[0].type == X86_OP_IMM:
            target = ins.operands[0].imm
            if target in entries:
                row = entry_transfers.setdefault(hx(target), {"calls": [], "jumps": []})
                row["calls" if ins.mnemonic == "call" else "jumps"].append(hx(ins.address))

    result = {
        "image": str(path),
        "size": len(data),
        "sha256": digest,
        "image_base": hx(IMAGE_BASE),
        "executable_sections": executable_sections,
        "decoded_instruction_records_including_skipdata": len(instructions),
        "wrapper_va": hx(WRAPPER_VA),
        "helper_va": hx(HELPER_VA),
        "g5_vtable_address_point": hx(VTABLE_VA),
        "g5_slot_va": hx(VTABLE_VA + SLOT_DISP),
        "raw_pointer_occurrences": {
            hx(WRAPPER_VA): raw_occurrences(data, WRAPPER_VA, pe),
            hx(HELPER_VA): raw_occurrences(data, HELPER_VA, pe),
            hx(VTABLE_VA): raw_occurrences(data, VTABLE_VA, pe),
        },
        "direct_relative_transfers": direct_transfers,
        "slot_transfer_count_by_mnemonic": {
            mnemonic: sum(row["mnemonic"] == mnemonic for row in slot_transfers)
            for mnemonic in ("call", "jmp")
        },
        "slot_transfer_sites": slot_transfers,
        "register_slot_load_count": len(slot_register_loads),
        "slot_load_to_register_call_or_jump_alias_count": len(aliases),
        "slot_load_to_register_call_or_jump_aliases": aliases,
        "tail_relay_sites_and_context_entries": {
            hx(site): hx(entry) for site, entry in TAIL_CONTEXTS.items()
        },
        "tail_context_entry_xrefs": {
            hx(entry): {
                "direct_call_sites": entry_transfers.get(hx(entry), {}).get("calls", []),
                "direct_jump_sites": entry_transfers.get(hx(entry), {}).get("jumps", []),
                "raw_pointer_occurrences": raw_occurrences(data, entry, pe),
            }
            for entry in sorted(entries)
        },
        "limits": [
            "Linear sweep decodes executable sections without proving code/data boundaries or runtime reachability.",
            "Slot census matches exact memory displacement +0x70; differently computed offsets are outside it.",
            "Register alias pass follows byte-order fall-through across conditional branches and stops at unconditional JMP/RET; it does not traverse a complete CFG, track stack spills, callbacks, COM, runtime-generated dispatch, or external callers.",
            "The 77 call sites were screened in the cited attribution audit; the three tail relays remain unresolved unless receiver type is statically proved.",
            "No device response, firmware meaning, requested full-image range, caller buffer consumer, or file sink is established by this census."
        ],
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
