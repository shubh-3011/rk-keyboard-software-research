#!/usr/bin/env python3
"""Verify the 4.6 text-macro mapping-list lifecycle from pinned PE bytes only."""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile

EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
EXPECTED_SIZE = 2_418_176
LIST_BASE = 0x00619DBC
LIST_HEAD = LIST_BASE + 0x10
TEXTMACRO_WRITER = 0x0041F540
WRITER_CALLS = {0x004215DE, 0x0045A057}

FACTS: dict[int, tuple[str, str, str]] = {
    0x00440AC0: ("8bc1", "generic-list-constructor", "Moves the list object pointer from ECX to EAX."),
    0x00440AC4: ("c7008cbf5d00", "generic-list-constructor", "Sets list vtable pointer to 0x005DBF8C."),
    0x00440ACA: ("894808", "generic-list-constructor", "Initializes list count at object +0x08 to zero."),
    0x00440ACD: ("89480c", "generic-list-constructor", "Initializes callback at object +0x0C to zero."),
    0x00440AD0: ("894814", "generic-list-constructor", "Initializes tail at object +0x14 to zero."),
    0x00440AD3: ("894810", "generic-list-constructor", "Initializes head at object +0x10 to zero."),
    0x00440AD6: ("c7400411000000", "generic-list-constructor", "Sets payload-ownership mode at object +0x04 to 0x11."),
    0x00440B00: ("5657", "generic-list-clear-and-destroy", "Begins list teardown/clear helper."),
    0x00440B04: ("8b7710", "generic-list-clear-and-destroy", "Starts traversal at list head +0x10."),
    0x00440B4B: ("8b0e", "generic-list-clear-and-destroy", "Loads node payload before optional callback."),
    0x00440B53: ("837f0410", "generic-list-clear-and-destroy", "Frees non-null payload only when owner +0x04 equals 0x10."),
    0x00440B68: ("56", "generic-list-clear-and-destroy", "Frees the list node after optional payload release."),
    0x00440B6E: ("ff4f08", "generic-list-clear-and-destroy", "Decrements list count for removed node."),
    0x00440B80: ("6a0c", "generic-list-append", "Requests a 12-byte node allocation."),
    0x00440B95: ("8b542404", "generic-list-append", "Loads the payload argument for the new node."),
    0x00440B99: ("8910", "generic-list-append", "Stores payload at node +0."),
    0x00440B9B: ("894804", "generic-list-append", "Initializes node next link at +0x04 to null."),
    0x00440BA3: ("894808", "generic-list-append", "Initializes previous link for first node."),
    0x00440BA6: ("894610", "generic-list-append", "Sets list head at owner +0x10 for first node."),
    0x00440BA9: ("894614", "generic-list-append", "Sets list tail at owner +0x14 for first node."),
    0x00440BC3: ("894614", "generic-list-append", "Sets list tail at owner +0x14 for later nodes."),
    0x00440BCB: ("014608", "generic-list-append", "Increments list count at owner +0x08."),
    0x00440C50: ("85f6", "generic-list-remove", "Tests whether the target node pointer is non-null."),
    0x00440C84: ("8b470c", "generic-list-remove", "Loads optional callback from owner +0x0C."),
    0x00440C93: ("837f0410", "generic-list-remove", "Uses owner +0x04 == 0x10 to select payload-freeing mode."),
    0x00440CB1: ("ff4f08", "generic-list-remove", "Decrements owner count after node removal."),
    0x00440CC0: ("56", "generic-list-clear", "Begins list clear loop without resetting the vtable."),
    0x00440CC1: ("8b7710", "generic-list-clear", "Starts clear traversal from owner head +0x10."),
    0x00440D02: ("8b470c", "generic-list-clear", "Loads optional callback from owner +0x0C."),
    0x00440D11: ("837f0410", "generic-list-clear", "Uses owner +0x04 == 0x10 to select payload-freeing mode."),
    0x00440D26: ("56", "generic-list-clear", "Frees each list node after optional payload release."),
    0x00440D2C: ("ff4f08", "generic-list-clear", "Decrements owner count as nodes are cleared."),
    0x00427D80: ("c3", "list-callback", "Initializer-supplied callback is a one-byte RET."),
    0x00448B0D: ("bf10000000", "COemDrvDlg-virtual-initializer", "Sets EDI to payload-freeing mode 0x10."),
    0x00448B15: ("c705c89d6100807d4200", "COemDrvDlg-virtual-initializer", "Stores callback 0x00427D80 at list object +0x0C."),
    0x00448B1F: ("893dc09d6100", "COemDrvDlg-virtual-initializer", "Stores mode 0x10 at list object +0x04."),
    0x00448B25: ("c705b09d6100807d4200", "COemDrvDlg-virtual-initializer", "Stores the same callback at adjacent object field 0x00619DB0."),
    0x00448B2F: ("893da89d6100", "COemDrvDlg-virtual-initializer", "Stores the same mode at adjacent object field 0x00619DA8."),
    0x0044910C: ("be bc 9d 61 00".replace(" ", ""), "mapping-list-append-site", "Loads list owner 0x00619DBC into ESI."),
    0x00449111: ("e86a7affff", "mapping-list-append-site", "Calls generic append helper 0x00440B80."),
    0x00460BA0: ("be bc 9d 61 00".replace(" ", ""), "mapping-list-append-site", "Loads list owner 0x00619DBC into ESI."),
    0x00460BA5: ("e8d6fffdff", "mapping-list-append-site", "Calls generic append helper 0x00440B80."),
    0x00460BE5: ("bfbc9d6100", "mapping-list-remove-site", "Loads list owner 0x00619DBC into EDI."),
    0x00460BEA: ("e86100feff", "mapping-list-remove-site", "Calls generic remove helper 0x00440C50."),
    0x00448788: ("bfbc9d6100", "mapping-list-clear-site", "Loads list owner 0x00619DBC into EDI."),
    0x0044878D: ("e82e85ffff", "mapping-list-clear-site", "Calls generic clear helper 0x00440CC0."),
    0x0044904F: ("bfbc9d6100", "mapping-list-clear-site", "Loads list owner 0x00619DBC into EDI."),
    0x00449054: ("e8677cffff", "mapping-list-clear-site", "Calls generic clear helper 0x00440CC0."),
    0x00460D08: ("bfbc9d6100", "mapping-list-clear-site", "Loads list owner 0x00619DBC into EDI."),
    0x00460D0F: ("e8acfffdff", "mapping-list-clear-site", "Calls generic clear helper 0x00440CC0."),
    0x005A53B0: ("b9bc9d6100", "mapping-list-destructor-thunk", "Loads list owner into ECX."),
    0x005A53B5: ("e946b7e9ff", "mapping-list-destructor-thunk", "Tail-jumps to generic teardown helper 0x00440B00."),
}

HEAD_LOADS = {
    0x00401AE7: "8b3dcc9d6100",
    0x0041AE32: "a1cc9d6100",
    0x0041B00E: "a1cc9d6100",
    0x0041E4C4: "a1cc9d6100",
    0x0044912A: "8b35cc9d6100",
    0x004491E0: "a1cc9d6100",
    0x00460BC1: "8b35cc9d6100",
    0x00460DB4: "a1cc9d6100",
    0x00460E5E: "8b35cc9d6100",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    require(len(data) == EXPECTED_SIZE and digest == EXPECTED_SHA256,
            "input size/SHA-256 mismatch")
    pe = pefile.PE(data=data)
    require(pe.OPTIONAL_HEADER.ImageBase == 0x00400000 and pe.FILE_HEADER.Machine == 0x14C,
            "expected x86 PE at preferred base")

    def raw(va: int, size: int) -> bytes:
        return data[pe.get_offset_from_rva(va - pe.OPTIONAL_HEADER.ImageBase):
                    pe.get_offset_from_rva(va - pe.OPTIONAL_HEADER.ImageBase) + size]

    rows: list[dict[str, str]] = []

    def add(va: int, expected_hex: str, stage: str, note: str) -> None:
        expected = bytes.fromhex(expected_hex)
        actual = raw(va, len(expected))
        require(actual == expected,
                f"0x{va:08X}: expected {expected.hex()}, got {actual.hex()}")
        rows.append({"binary_sha256": digest, "evidence_va": f"0x{va:08X}",
                     "bytes": actual.hex().upper(), "stage": stage, "observation": note,
                     "scope": "static bytes only; execution and runtime list contents unobserved"})

    for va, (hex_bytes, stage, note) in FACTS.items():
        add(va, hex_bytes, stage, note)

    # Check the entire initialized object image, then distinguish it from the
    # runtime fields changed by the COemDrvDlg virtual initializer.
    static = raw(LIST_BASE, 0x18)
    require(static == bytes.fromhex("8cbf5d001100000000000000000000000000000000000000"),
            f"unexpected static list object image: {static.hex()}")
    rows.append({"binary_sha256": digest, "evidence_va": f"0x{LIST_BASE:08X}",
                 "bytes": static.hex().upper(), "stage": "static-list-object",
                 "observation": "Static image has vptr 0x005DBF8C, mode 0x11, and zero count/callback/head/tail.",
                 "scope": "file image only; process startup/runtime state unobserved"})
    adjacent = raw(0x00619DA4, 0x18)
    require(adjacent == static, f"adjacent list-like object image changed: {adjacent.hex()}")
    rows.append({"binary_sha256": digest, "evidence_va": "0x00619DA4",
                 "bytes": adjacent.hex().upper(), "stage": "adjacent-list-like-object",
                 "observation": "Adjacent object has the same static vtable/mode/zero-field image; initializer writes matching mode and callback fields.",
                 "scope": "static bytes only; semantic role and runtime contents unobserved"})

    # Resolve the virtual initializer to its RTTI-identified owner.
    vtable = 0x005DDC6C
    col = struct.unpack("<I", raw(vtable - 4, 4))[0]
    require(col == 0x005ED7A8, f"COemDrvDlg vtable COL changed: 0x{col:08X}")
    col_fields = struct.unpack("<5I", raw(col, 20))
    require(col_fields == (0, 0, 0, 0x0061A420, 0x005ED7BC),
            f"COemDrvDlg COL fields changed: {col_fields!r}")
    type_name = raw(col_fields[3] + 8, len(b".?AVCOemDrvDlg@@\0"))
    require(type_name == b".?AVCOemDrvDlg@@\0", "COemDrvDlg RTTI name changed")
    initializer = struct.unpack("<I", raw(vtable + 84 * 4, 4))[0]
    require(initializer == 0x00448930,
            f"COemDrvDlg vtable slot 84 changed: 0x{initializer:08X}")
    rows.append({"binary_sha256": digest, "evidence_va": f"0x{vtable + 84 * 4:08X}",
                 "bytes": raw(vtable + 84 * 4, 4).hex().upper(),
                 "stage": "owner-rtti-vtable",
                 "observation": "RTTI name .?AVCOemDrvDlg@@; vtable slot 84 points to initializer 0x00448930.",
                 "scope": "static RTTI/vtable linkage; method execution and symbolic name unobserved"})

    # This is a literal absolute-address census, not a whole-program alias proof.
    encoded = struct.pack("<I", LIST_HEAD)
    hits: list[int] = []
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        chunk = section.get_data()
        pos = 0
        while True:
            pos = chunk.find(encoded, pos)
            if pos < 0:
                break
            va = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + pos
            hits.append(va)
            pos += 1
    literal_offsets = [va + (2 if bytes.fromhex(code).startswith((b"\x8b\x3d", b"\x8b\x35")) else 1)
                       for va, code in HEAD_LOADS.items()]
    require(sorted(hits) == sorted(literal_offsets),
            f"head literal census changed: {[hex(x) for x in hits]}")
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    for va, expected_hex in HEAD_LOADS.items():
        add(va, expected_hex, "absolute-head-load", "Decoded instruction loads the head pointer from 0x00619DCC.")
        off = pe.get_offset_from_rva(va - pe.OPTIONAL_HEADER.ImageBase)
        ins = next(decoder.disasm(data[off:off + 15], va, count=1), None)
        require(ins is not None and ins.mnemonic == "mov" and "0x619dcc" in ins.op_str,
                f"0x{va:08X} is not a decoded head-field load")

    # Byte-scan relative-call encodings, then decode each matching instruction
    # at its candidate VA. This bounds the direct-call census to executable PE
    # section bytes and does not claim complete interprocedural reachability.
    writer_calls: set[int] = set()
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        chunk = section.get_data()
        section_va = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
        for offset in range(len(chunk) - 4):
            if chunk[offset] != 0xE8:
                continue
            call_va = section_va + offset
            target = call_va + 5 + struct.unpack_from("<i", chunk, offset + 1)[0]
            if target != TEXTMACRO_WRITER:
                continue
            ins = next(decoder.disasm(chunk[offset:offset + 15], call_va, count=1), None)
            require(ins is not None and ins.mnemonic == "call"
                    and int(ins.op_str, 16) == TEXTMACRO_WRITER,
                    f"relative-call candidate at 0x{call_va:08X} did not decode as expected")
            writer_calls.add(call_va)
            rows.append({"binary_sha256": digest, "evidence_va": f"0x{call_va:08X}",
                         "bytes": ins.bytes.hex().upper(), "stage": "textmacro-writer-direct-call",
                         "observation": f"Direct relative call to 0x{TEXTMACRO_WRITER:08X}.",
                         "scope": "executable-section byte scan plus candidate instruction decode; no transitive-reachability proof"})
    require(writer_calls == WRITER_CALLS,
            f"textmacro writer callsite census changed: {[hex(x) for x in sorted(writer_calls)]}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("binary_sha256", "evidence_va", "bytes", "stage", "observation", "scope"))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Verified {len(FACTS)} exact instruction facts, static object bytes, COemDrvDlg RTTI/vtable linkage, {len(HEAD_LOADS)} absolute head loads, and {len(writer_calls)} direct writer calls.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
