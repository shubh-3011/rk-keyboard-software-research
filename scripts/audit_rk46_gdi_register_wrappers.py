#!/usr/bin/env python3
"""Verify the 13 documented GDI register-call wrappers in the pinned RK 4.6 PE."""

from __future__ import annotations

import argparse
import csv
import hashlib
import struct
from pathlib import Path

import capstone
import pefile


EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
EXPECTED_SIZE = 2_418_176
EXPECTED_EDGE_SHA256 = "e0aa66be6a217ed04674457af9e5520ff5e8ff0645301810c2defa244b00ac6c"
IMAGE_BASE = 0x00400000

# symbol: (IAT VA, wrapper entry VA, IAT-load VA, register, call sites)
WRAPPERS: dict[str, tuple[int, int, int, str, tuple[int, ...]]] = {
    "SaveDC": (0x005A60D4, 0x0047838C, 0x00478398, "edi", (0x004783A3, 0x004783B0)),
    "RestoreDC": (0x005A6050, 0x004783BF, 0x004783CE, "edi", (0x004783DD, 0x004783EE)),
    "SetBkMode": (0x005A6058, 0x00478434, 0x00478442, "edi", (0x00478451, 0x0047845E)),
    "SetPolyFillMode": (0x005A605C, 0x00478466, 0x00478474, "edi", (0x00478483, 0x00478490)),
    "SetROP2": (0x005A6060, 0x00478498, 0x004784A6, "edi", (0x004784B5, 0x004784C2)),
    "ExcludeClipRect": (0x005A6070, 0x00478544, 0x0047854A, "ebx", (0x0047856D, 0x00478582)),
    "SetTextAlign": (0x005A6080, 0x00478609, 0x00478619, "edi", (0x00478628, 0x00478635)),
    "SelectClipRgn": (0x005A6084, 0x00478B68, 0x00478B7A, "edi", (0x00478B8E, 0x00478BA4)),
    "OffsetViewportOrgEx": (0x005A60A8, 0x00478997, 0x004789A3, "edi", (0x004789B8, 0x004789CB)),
    "ScaleViewportExtEx": (0x005A60B0, 0x00478A15, 0x00478A21, "edi", (0x00478A3C, 0x00478A55)),
    "OffsetWindowOrgEx": (0x005A60B8, 0x00478A9F, 0x00478AAB, "edi", (0x00478AC0, 0x00478AD3)),
    "ScaleWindowExtEx": (0x005A60C0, 0x00478B1D, 0x00478B29, "edi", (0x00478B44, 0x00478B5D)),
    "ExtSelectClipRgn": (0x005A60C4, 0x00478C6E, 0x00478C80, "edi", (0x00478C97, 0x00478CB0)),
}

# Direct callers found in the selected rooted-CFG edge ledger. These lists
# intentionally describe that bounded input, not an exhaustive program census.
DIRECT_CALLERS: dict[str, tuple[int, ...]] = {
    "SaveDC": (),
    "RestoreDC": (),
    "SetBkMode": (
        0x004021C9, 0x00407256, 0x004090EC, 0x0041D7AC, 0x0041FBBC,
        0x0042398F, 0x0042895F, 0x00435E16, 0x00437272, 0x0045B09E,
        0x0045D840, 0x004616C0, 0x004627D1, 0x0046412A, 0x0046AEEA,
        0x0046D058, 0x00470164, 0x00470DC8, 0x00472414, 0x00475FFB,
        0x004E0A40, 0x004E1B0F, 0x004E8642, 0x004FBC1F, 0x0052D44E,
        0x0052D5DA, 0x005425B0, 0x00554F22, 0x0055B742, 0x00570D6C,
    ),
    "SetPolyFillMode": (),
    "SetROP2": (0x0055FE55, 0x00560030),
    "ExcludeClipRect": (
        0x0048FD21, 0x004E08C4, 0x004FB64A, 0x004FC058,
        0x005005A0, 0x00503B58, 0x0052D669,
    ),
    "SetTextAlign": (),
    "SelectClipRgn": (
        0x00485F4E, 0x00485FA3, 0x00485FF2, 0x0048FED8, 0x004E08F8,
        0x004E0AD9, 0x004FBCD4, 0x004FBD59, 0x004FBEAA, 0x005005D4,
        0x00500745, 0x0052D6DC, 0x00560050, 0x005721CD, 0x005721F7,
    ),
    "OffsetViewportOrgEx": (),
    "ScaleViewportExtEx": (),
    "OffsetWindowOrgEx": (),
    "ScaleWindowExtEx": (),
    "ExtSelectClipRgn": (0x0048FDBD, 0x0048FDF2),
}

VFTABLES = (
    (0x005A739C, "CDC", 0x006075A4),
    (0x005A741C, "CClientDC", 0x006075B8),
    (0x005A749C, "CWindowDC", 0x006075D0),
    (0x005A751C, "CPaintDC", 0x006075E8),
)
VFTABLE_METHODS = {
    "SaveDC": 0x1C,
    "RestoreDC": 0x20,
    "OffsetViewportOrgEx": 0x3C,
    "ScaleViewportExtEx": 0x44,
    "ScaleWindowExtEx": 0x4C,
}
EXPECTED_VFTABLE_REFS = {
    symbol: tuple(address_point + slot for address_point, _, _ in VFTABLES)
    for symbol, slot in VFTABLE_METHODS.items()
}

# Argument-source/result anchors. The import-load and call instructions are
# separately verified from WRAPPERS above.
FACTS: dict[int, tuple[str, str]] = {
    0x00478392: ("mov", "eax, dword ptr [esi + 8]"),
    0x004783A2: ("push", "eax"),
    0x004783A5: ("mov", "ebx, eax"),
    0x004783A7: ("mov", "eax, dword ptr [esi + 4]"),
    0x004783B6: ("or", "ebx, 0xffffffff"),
    0x004783BB: ("mov", "eax, ebx"),
    0x004783C7: ("mov", "ecx, dword ptr [esi + 4]"),
    0x004783CA: ("xor", "eax, eax"),
    0x004783CC: ("inc", "eax"),
    0x004783D9: ("push", "dword ptr [ebp + 8]"),
    0x004783EA: ("push", "dword ptr [ebp + 8]"),
    0x004783DF: ("mov", "esi, dword ptr [esi + 8]"),
    0x004783F4: ("xor", "eax, eax"),
    0x004783F6: ("inc", "eax"),
    0x0047844D: ("push", "dword ptr [ebp + 8]"),
    0x00478450: ("push", "ecx"),
    0x0047845A: ("push", "dword ptr [ebp + 8]"),
    0x0047845D: ("push", "esi"),
    0x0047847F: ("push", "dword ptr [ebp + 8]"),
    0x00478482: ("push", "ecx"),
    0x0047848C: ("push", "dword ptr [ebp + 8]"),
    0x0047848F: ("push", "esi"),
    0x004784B1: ("push", "dword ptr [ebp + 8]"),
    0x004784B4: ("push", "ecx"),
    0x004784BE: ("push", "dword ptr [ebp + 8]"),
    0x004784C1: ("push", "esi"),
    0x00478561: ("push", "dword ptr [esi + 0xc]"),
    0x00478564: ("push", "dword ptr [esi + 8]"),
    0x00478567: ("push", "dword ptr [esi + 4]"),
    0x0047856A: ("push", "dword ptr [esi]"),
    0x0047856C: ("push", "ecx"),
    0x00478576: ("push", "dword ptr [esi + 0xc]"),
    0x00478579: ("push", "dword ptr [esi + 8]"),
    0x0047857C: ("push", "dword ptr [esi + 4]"),
    0x0047857F: ("push", "dword ptr [esi]"),
    0x00478581: ("push", "edi"),
    0x00478615: ("or", "ebx, 0xffffffff"),
    0x00478624: ("push", "dword ptr [ebp + 8]"),
    0x00478627: ("push", "eax"),
    0x00478631: ("push", "dword ptr [ebp + 8]"),
    0x00478634: ("push", "esi"),
    0x00478637: ("mov", "ebx, eax"),
    0x0047863B: ("mov", "eax, ebx"),
    0x00478B85: ("test", "ebx, ebx"),
    0x00478B89: ("mov", "eax, dword ptr [ebx + 4]"),
    0x00478B9F: ("mov", "eax, dword ptr [ebx + 4]"),
    0x004789AE: ("push", "dword ptr [ebp + 8]"),
    0x004789B1: ("push", "dword ptr [ebp + 0x10]"),
    0x004789B4: ("push", "dword ptr [ebp + 0xc]"),
    0x004789CD: ("mov", "eax, dword ptr [ebp + 8]"),
    0x00478A2C: ("push", "dword ptr [ebp + 8]"),
    0x00478A2F: ("push", "dword ptr [ebp + 0x18]"),
    0x00478A32: ("push", "dword ptr [ebp + 0x14]"),
    0x00478A35: ("push", "dword ptr [ebp + 0x10]"),
    0x00478A38: ("push", "dword ptr [ebp + 0xc]"),
    0x00478A57: ("mov", "eax, dword ptr [ebp + 8]"),
    0x00478AB6: ("push", "dword ptr [ebp + 8]"),
    0x00478AB9: ("push", "dword ptr [ebp + 0x10]"),
    0x00478ABC: ("push", "dword ptr [ebp + 0xc]"),
    0x00478AD5: ("mov", "eax, dword ptr [ebp + 8]"),
    0x00478B34: ("push", "dword ptr [ebp + 8]"),
    0x00478B37: ("push", "dword ptr [ebp + 0x18]"),
    0x00478B3A: ("push", "dword ptr [ebp + 0x14]"),
    0x00478B3D: ("push", "dword ptr [ebp + 0x10]"),
    0x00478B40: ("push", "dword ptr [ebp + 0xc]"),
    0x00478B5F: ("mov", "eax, dword ptr [ebp + 8]"),
    0x00478C8B: ("test", "ebx, ebx"),
    0x00478C8F: ("mov", "eax, dword ptr [ebx + 4]"),
    0x00478C92: ("push", "dword ptr [ebp + 0xc]"),
    0x00478CAB: ("push", "dword ptr [ebp + 0xc]"),
}


def read_va(pe: pefile.PE, data: bytes, va: int, size: int) -> bytes:
    return data[pe.get_offset_from_rva(va - IMAGE_BASE):][:size]


def decode_at(pe: pefile.PE, data: bytes, decoder: capstone.Cs, va: int):
    raw = read_va(pe, data, va, 15)
    return next(decoder.disasm(raw, va, count=1), None)


def csv_sites(value: str) -> tuple[int, ...]:
    return tuple(int(part, 16) for part in value.split(";") if part)


def c_string(pe: pefile.PE, data: bytes, va: int) -> str:
    start = pe.get_offset_from_rva(va - IMAGE_BASE)
    end = data.find(b"\0", start, start + 256)
    if end < 0:
        raise SystemExit(f"unterminated RTTI name at 0x{va:08X}")
    return data[start:end].decode("ascii", errors="strict")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--edges", type=Path, required=True)
    args = parser.parse_args()

    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        raise SystemExit("input size/SHA-256 mismatch")
    if hashlib.sha256(args.edges.read_bytes()).hexdigest() != EXPECTED_EDGE_SHA256:
        raise SystemExit("rooted-CFG edge ledger SHA-256 mismatch")

    pe = pefile.PE(data=data)
    if pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE or pe.FILE_HEADER.Machine != 0x14C:
        raise SystemExit("expected x86 PE at preferred base")
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True

    imports = {
        entry.address: (
            library.dll.decode(errors="replace"),
            entry.name.decode(errors="replace") if entry.name else "",
        )
        for library in pe.DIRECTORY_ENTRY_IMPORT
        for entry in library.imports
    }

    with args.evidence.open(newline="", encoding="utf-8-sig") as stream:
        evidence = list(csv.DictReader(stream))
    rows_by_symbol = {row["symbol"]: row for row in evidence}
    if len(evidence) != 13 or set(rows_by_symbol) != set(WRAPPERS):
        raise SystemExit("evidence CSV must contain exactly the 13 expected GDI wrapper rows")

    # Keep the per-row evidence synchronized with the hash-pinned disassembly.
    for symbol, (iat, wrapper, load, register, calls) in WRAPPERS.items():
        row = rows_by_symbol[symbol]
        if row["binary_sha256"] != digest or int(row["binary_size"]) != EXPECTED_SIZE:
            raise SystemExit(f"{symbol}: CSV artifact identity mismatch")
        if imports.get(iat) != ("GDI32.dll", symbol):
            raise SystemExit(f"{symbol}: unexpected import mapping {imports.get(iat)!r}")
        if (int(row["iat_va"], 16), int(row["wrapper_va"], 16),
                int(row["iat_load_va"], 16), row["register"].lower(),
                csv_sites(row["indirect_api_calls"])) != (iat, wrapper, load, register, calls):
            raise SystemExit(f"{symbol}: CSV wrapper/import/callsite fields mismatch")

        loaded = decode_at(pe, data, decoder, load)
        if (loaded is None or loaded.mnemonic != "mov"
                or loaded.reg_name(loaded.operands[0].reg) != register
                or loaded.operands[1].type != capstone.x86.X86_OP_MEM
                or loaded.operands[1].mem.disp & 0xFFFFFFFF != iat):
            raise SystemExit(f"{symbol}: unexpected IAT load at 0x{load:08X}")
        for call_va in calls:
            call = decode_at(pe, data, decoder, call_va)
            if (call is None or call.mnemonic != "call"
                    or len(call.operands) != 1
                    or call.operands[0].type != capstone.x86.X86_OP_REG
                    or call.reg_name(call.operands[0].reg) != register):
                raise SystemExit(f"{symbol}: unexpected register call at 0x{call_va:08X}")

    # Validate instruction-level argument and result observations.
    for va, (mnemonic, op_str) in FACTS.items():
        insn = decode_at(pe, data, decoder, va)
        if insn is None or insn.mnemonic != mnemonic or insn.op_str != op_str:
            actual = "undecodable" if insn is None else f"{insn.mnemonic} {insn.op_str}"
            raise SystemExit(f"0x{va:08X}: expected {mnemonic} {op_str}, got {actual}")

    # Direct caller claims are exact only relative to the hash-pinned,
    # bounded-rooted edge ledger; independently decode each listed call too.
    with args.edges.open(newline="", encoding="utf-8-sig") as stream:
        edges = list(csv.DictReader(stream))
    edge_sites: dict[str, set[int]] = {symbol: set() for symbol in WRAPPERS}
    for symbol, (_, wrapper, _, _, _) in WRAPPERS.items():
        edge_sites[symbol] = {
            int(edge["site_va"], 16)
            for edge in edges
            if edge["edge_kind"] == "direct_call" and edge["target_va"]
            and int(edge["target_va"], 16) == wrapper
        }
        expected_sites = set(DIRECT_CALLERS[symbol])
        if edge_sites[symbol] != expected_sites:
            raise SystemExit(f"{symbol}: direct-caller set differs from rooted CFG ledger")
        row_sites = set(csv_sites(rows_by_symbol[symbol]["bounded_rooted_direct_callers"]))
        if row_sites != expected_sites:
            raise SystemExit(f"{symbol}: CSV caller sites differ from verifier expectations")
        for site in expected_sites:
            insn = decode_at(pe, data, decoder, site)
            if (insn is None or insn.mnemonic != "call"
                    or len(insn.operands) != 1
                    or insn.operands[0].type != capstone.x86.X86_OP_IMM
                    or (insn.operands[0].imm & 0xFFFFFFFF) != wrapper):
                raise SystemExit(f"{symbol}: direct call target mismatch at 0x{site:08X}")

    # Confirm RTTI-bearing address points and their common CDC-family slots.
    vtable_entries: dict[str, list[str]] = {symbol: [] for symbol in WRAPPERS}
    for address_point, class_name, type_descriptor in VFTABLES:
        col_va = struct.unpack("<I", read_va(pe, data, address_point - 4, 4))[0]
        actual_type_descriptor = struct.unpack("<I", read_va(pe, data, col_va + 0x0C, 4))[0]
        actual_name = c_string(pe, data, actual_type_descriptor + 8)
        if actual_type_descriptor != type_descriptor or actual_name != f".?AV{class_name}@@":
            raise SystemExit(f"0x{address_point:08X}: RTTI mismatch: {actual_name!r}")
        for symbol, slot in VFTABLE_METHODS.items():
            _, wrapper, _, _, _ = WRAPPERS[symbol]
            actual = struct.unpack("<I", read_va(pe, data, address_point + slot, 4))[0]
            if actual != wrapper:
                raise SystemExit(
                    f"{class_name} +0x{slot:X}: expected {symbol} at 0x{wrapper:08X}, "
                    f"got 0x{actual:08X}"
                )
            vtable_entries[symbol].append(f"{class_name}@0x{address_point:08X}+0x{slot:X}")

    for symbol, row in rows_by_symbol.items():
        actual_vtable_list = row["vftable_evidence"].split(";") if row["vftable_evidence"] else []
        if actual_vtable_list != vtable_entries[symbol]:
            raise SystemExit(f"{symbol}: CSV vftable evidence mismatch")

    # Scan non-code raw sections for absolute pointers to these wrapper
    # entries. This verifies positive vftable claims and keeps the negative
    # "no exact vftable pointer found" statements bounded to this scan.
    nontext_pointer_locations: dict[int, list[int]] = {row[1]: [] for row in WRAPPERS.values()}
    for section in pe.sections:
        section_name = section.Name.rstrip(b"\0")
        if section_name == b".text":
            continue
        raw = read_va(pe, data, IMAGE_BASE + section.VirtualAddress, section.SizeOfRawData)
        for _, wrapper, _, _, _ in WRAPPERS.values():
            needle = struct.pack("<I", wrapper)
            offset = 0
            while True:
                offset = raw.find(needle, offset)
                if offset < 0:
                    break
                nontext_pointer_locations[wrapper].append(
                    IMAGE_BASE + section.VirtualAddress + offset
                )
                offset += 1
    for symbol, (_, wrapper, _, _, _) in WRAPPERS.items():
        expected_refs = list(EXPECTED_VFTABLE_REFS.get(symbol, ()))
        if sorted(nontext_pointer_locations[wrapper]) != sorted(expected_refs):
            found = ", ".join(f"0x{va:08X}" for va in nontext_pointer_locations[wrapper]) or "none"
            raise SystemExit(f"{symbol}: non-text absolute pointer scan mismatch ({found})")

    print(
        f"verified {len(WRAPPERS)} GDI wrappers, {sum(map(len, DIRECT_CALLERS.values()))} "
        f"bounded direct caller edges, {sum(map(len, vtable_entries.values()))} vftable slots; "
        f"DeviceDriver SHA-256={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
