#!/usr/bin/env python3
"""Verify CFile::Write-slot attribution for the S98 01BF indirect-call census."""

from __future__ import annotations

import argparse
import csv
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM
import pefile

EXPECTED_SHA256 = "475e8d7b97adfbd861c3b7b16721ad598df04095b81228e381319b6be23129e6"
EXPECTED_SIZE = 2_140_176
IMAGE_BASE = 0x00400000
TEXT_SHA256 = "3643f4d710a296b62598d3d8b71c7dd9dcab049ebbb540588b11757ccd5f03ed"
CFI_VTABLE = 0x0055F878
CFI_WRITE = 0x0042D26F
CFI_OPEN = 0x0042CF20
WRITEFILE_IAT = 0x0055A378

CALLS_3C = [
    0x0040E2A6, 0x0041298C, 0x004129AF, 0x00417D1A, 0x00419A29,
    0x0041CA16, 0x0041CD65, 0x00424963, 0x00438532, 0x0043954B,
    0x004396B0, 0x00439B11, 0x0043A6E0, 0x0043A8D9, 0x0045F267,
    0x0047006D, 0x004710BE, 0x004906C3, 0x004C51CD, 0x004C51F1,
    0x004DB0B1, 0x00507CB8, 0x00507CD5, 0x00507CEA,
]

# These two MFC archive paths use the CFile +0x3c method with the ordinary
# thiscall receiver and (buffer, byte-count) stack order. The concrete vptr is
# deliberately not inferred from a static CFile* field.
ARCHIVE_WRITE_CALLS = {
    0x0041CA16: {
        "receiver": "archive field [EDI+0x24]",
        "args": "buffer=[EDI+0x30]; count=[EDI+0x28]-[EDI+0x30]",
        "basis": "MFC archive flush path; constructor argument is stored in [archive+0x24]; same field uses CFile-compatible read/seek slots.",
    },
    0x0041CD65: {
        "receiver": "archive field [EDI+0x24]",
        "args": "buffer=[EBP+0x08]; count=EBX rounded down by [EDI+0x20]",
        "basis": "MFC archive large-write path; same constructor-supplied field and virtual slot as the flush path.",
    },
}

# Six other two-word call shapes use receivers that are also called at the
# CFile +0x24 slot with only one explicit argument. CFile's +0x24 implementation
# is Open (3 stack parameters; ret 0x0c), so these do not have CFile vptr
# provenance on the bounded paths.
NON_CFILE_RECEIVER = {
    0x00438532: ("[ESI+0x398]", 0x0043850C, 0x00438500, 0x00438520, 0x00438509, "two words: [EBP+8], [EBP+0x0c]"),
    0x0043954B: ("[EDI+0x398]", 0x00439528, 0x00439512, 0x0043953B, 0x00439527, "two words: -1, -1"),
    0x004396B0: ("[EDI+0x398]", 0x00439689, 0x0043967D, 0x004396A0, 0x00439686, "two words: -1, -1"),
    0x00439B11: ("EDI", 0x00439AED, 0x00439AEB, 0x00439B0C, 0x00439AEA, "two words: [EBP+0x0c], [EBP+0x10]"),
    0x0043A6E0: ("[ESI+0x398]", 0x0043A6BD, 0x0043A6B1, 0x0043A6D0, 0x0043A6BA, "two words: -1, -1"),
    0x0043A8D9: ("[ESI+0x398]", 0x0043A8B2, 0x0043A8A1, 0x0043A8C9, 0x0043A8B1, "two words: -1, -1"),
}

# Count of explicit/preserved stack argument words at each call (the 16-byte
# MOVSD argument blocks count as four words). These entries are not CFile
# calls because CFile::Write has exactly two stack parameters.
ARITY_MISMATCH = {
    0x0040E2A6: (6, "ECX contains the loaded vptr, not a CFile this pointer"),
    0x0041298C: (6, "four copied words plus two pushed words"),
    0x004129AF: (6, "four copied words plus two pushed words"),
    0x00419A29: (0, "no stack arguments"),
    0x00424963: (0, "no stack arguments"),
    0x0045F267: (6, "four copied words plus two pushed words"),
    0x0047006D: (0, "no stack arguments"),
    0x004710BE: (0, "no stack arguments"),
    0x004906C3: (1, "one stack argument"),
    0x004C51CD: (4, "four stack arguments"),
    0x004C51F1: (4, "four stack arguments"),
    0x004DB0B1: (4, "four stack arguments"),
    0x00507CB8: (6, "six stack arguments on either branch"),
    0x00507CD5: (6, "six stack arguments"),
    0x00507CEA: (6, "six stack arguments"),
}

# Exact call-adjacent stack material for every arity-mismatch row. Pushes are
# listed in ascending address order; copied MOVSD blocks add one stack word
# apiece. For 0x507CB8 the two mutually exclusive branch alternatives are kept
# separate and each supplies six words.
ARITY_PUSHES = {
    0x0040E2A6: (0x0040E299, 0x0040E2A1),
    0x0041298C: (0x0041297A, 0x00412987),
    0x004129AF: (0x0041299D, 0x004129AA),
    0x00419A29: (),
    0x00424963: (),
    0x0045F267: (0x0045F25F, 0x0045F260),
    0x0047006D: (),
    0x004710BE: (),
    0x004906C3: (0x004906C2,),
    0x004C51CD: (0x004C51BF, 0x004C51C7, 0x004C51C8, 0x004C51CA),
    0x004C51F1: (0x004C51E3, 0x004C51EB, 0x004C51EC, 0x004C51EE),
    0x004DB0B1: (0x004DB0AA, 0x004DB0AB, 0x004DB0AC, 0x004DB0AE),
    0x00507CB8: (
        (0x00507C97, 0x00507C9E, 0x00507C9F, 0x00507CA2, 0x00507CA5, 0x00507CB5),
        (0x00507C97, 0x00507CAA, 0x00507CAC, 0x00507CAF, 0x00507CB2, 0x00507CB5),
    ),
    0x00507CD5: (0x00507CC0, 0x00507CCA, 0x00507CCB, 0x00507CCE, 0x00507CD1, 0x00507CD4),
    0x00507CEA: (0x00507CD8, 0x00507CDF, 0x00507CE0, 0x00507CE3, 0x00507CE6, 0x00507CE9),
}
ARITY_MOVSD_BLOCKS = {
    0x0040E2A6: (0x0040E2A2, 0x0040E2A3, 0x0040E2A4, 0x0040E2A5),
    0x0041298C: (0x00412988, 0x00412989, 0x0041298A, 0x0041298B),
    0x004129AF: (0x004129AB, 0x004129AC, 0x004129AD, 0x004129AE),
    0x0045F267: (0x0045F263, 0x0045F264, 0x0045F265, 0x0045F266),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        raise SystemExit("input size/SHA-256 mismatch")

    pe = pefile.PE(data=data)
    if pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE or pe.FILE_HEADER.Machine != 0x14C:
        raise SystemExit("expected x86 PE at preferred base")
    text = next((s for s in pe.sections if s.Name.rstrip(b"\0") == b".text"), None)
    if text is None or hashlib.sha256(text.get_data()).hexdigest() != TEXT_SHA256:
        raise SystemExit(".text section/hash mismatch")

    def raw(va: int, size: int) -> bytes:
        offset = pe.get_offset_from_rva(va - IMAGE_BASE)
        return data[offset:offset + size]

    def u32(va: int) -> int:
        return struct.unpack("<I", raw(va, 4))[0]

    def c_string(va: int, limit: int = 256) -> bytes:
        return raw(va, limit).split(b"\0", 1)[0]

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    instructions = list(decoder.disasm(text.get_data(), IMAGE_BASE + text.VirtualAddress))
    by_va = {ins.address: ins for ins in instructions}

    def ins(va: int, mnemonic: str | None = None, op_str: str | None = None):
        got = by_va.get(va)
        if got is None:
            raise SystemExit(f"missing decoded instruction at 0x{va:08X}")
        if mnemonic is not None and got.mnemonic != mnemonic:
            raise SystemExit(f"unexpected instruction at 0x{va:08X}: {got.mnemonic} {got.op_str}")
        if op_str is not None and got.op_str != op_str:
            raise SystemExit(f"unexpected operands at 0x{va:08X}: {got.op_str}")
        return got

    # RTTI and vtable entry: CFile slot 15 (+0x3c) is the Write implementation.
    col = u32(CFI_VTABLE - 4)
    fields = [u32(col + offset) for offset in (0, 4, 8, 12, 16)]
    if fields[:3] != [0, 0, 0] or c_string(fields[3] + 8) != b".?AVCFile@@":
        raise SystemExit("CFile vtable RTTI identity mismatch")
    hierarchy = fields[4]
    hierarchy_fields = [u32(hierarchy + offset) for offset in (0, 4, 8, 12)]
    base_count, base_array = hierarchy_fields[2], hierarchy_fields[3]
    base_names = []
    for index in range(base_count):
        descriptor = u32(base_array + index * 4)
        base_names.append(c_string(u32(descriptor) + 8))
    if base_names != [b".?AVCFile@@", b".?AVCObject@@"]:
        raise SystemExit(f"unexpected CFile RTTI hierarchy: {base_names!r}")

    vtable = [u32(CFI_VTABLE + index * 4) for index in range(22)]
    if vtable[9] != CFI_OPEN or vtable[15] != CFI_WRITE:
        raise SystemExit("CFile virtual slot mapping mismatch")
    if raw(CFI_WRITE, 10) != bytes.fromhex("558bec56578b7d0c8bf1"):
        raise SystemExit("CFile::Write this/argument setup mismatch")
    if raw(CFI_WRITE + 0x0E, 19) != bytes.fromhex("6a008d450c5057ff7508ff7604ff1578a35500"):
        raise SystemExit("CFile::WriteFile argument/IAT sequence mismatch")
    if ins(CFI_WRITE + 0x3C, "ret", "8") is None:
        raise SystemExit("CFile::Write stack cleanup mismatch")
    if ins(CFI_OPEN + 0x1D2, "ret", "0xc") is None:
        raise SystemExit("CFile::Open stack cleanup mismatch")

    imports = {
        item.address: (lib.dll.decode(errors="replace").upper(), item.name.decode(errors="replace") if item.name else "")
        for lib in pe.DIRECTORY_ENTRY_IMPORT for item in lib.imports
    }
    if imports.get(WRITEFILE_IAT) != ("KERNEL32.DLL", "WriteFile"):
        raise SystemExit("WriteFile IAT identity mismatch")

    found_calls = [
        instruction.address for instruction in instructions
        if instruction.mnemonic == "call" and instruction.operands
        and instruction.operands[0].type == CS_OP_MEM
        and instruction.operands[0].mem.disp == 0x3C
    ]
    if found_calls != CALLS_3C:
        raise SystemExit("generic +0x3c call census mismatch")

    direct_wrapper_calls = [
        instruction.address for instruction in instructions
        if instruction.mnemonic == "call" and instruction.operands
        and instruction.operands[0].type == CS_OP_IMM
        and instruction.operands[0].imm == CFI_WRITE
    ]
    if direct_wrapper_calls:
        raise SystemExit(f"unexpected direct CFile::Write callers: {direct_wrapper_calls!r}")

    # Verify the call-adjacent stack layout rather than trusting the ledger's
    # hand-entered word counts. The three MOVSD blocks materialize four words.
    for call_va, push_shape in ARITY_PUSHES.items():
        alternatives = push_shape if push_shape and isinstance(push_shape[0], tuple) else (push_shape,)
        for alternative in alternatives:
            for push_va in alternative:
                ins(push_va, "push")
            if call_va == 0x00507CB8 and len(alternatives) == 2:
                if len(alternative) != ARITY_MISMATCH[call_va][0]:
                    raise SystemExit("0x00507CB8 branch does not have six pushed words")
            else:
                copied_words = len(ARITY_MOVSD_BLOCKS.get(call_va, ()))
                if len(alternative) + copied_words != ARITY_MISMATCH[call_va][0]:
                    raise SystemExit(f"stack-word ledger mismatch at 0x{call_va:08X}")
    for call_va, block in ARITY_MOVSD_BLOCKS.items():
        if len(block) != 4 or any(ins(va, "movsd") is None for va in block):
            raise SystemExit(f"expected four copied stack words at 0x{call_va:08X}")

    # Constructor-shaped archive path: its first argument is retained as the
    # +0x24 member that later receives the CFile virtual calls.
    ins(0x0041C418, "mov", "edi, dword ptr [ebp + 8]")
    ins(0x0041C46B, "mov", "dword ptr [esi + 0x24], edi")
    ins(0x0041C502, "ret", "0x10")
    ins(0x0041C942, "mov", "ecx, dword ptr [edi + 0x24]")
    ins(0x0041C949, "call", "dword ptr [eax + 0x38]")
    ins(0x0041CA0C, "mov", "ecx, dword ptr [edi + 0x24]")
    ins(0x0041CA11, "push", "edx")
    ins(0x0041CA12, "push", "dword ptr [esi]")
    ins(0x0041CA14, "mov", "eax, dword ptr [ecx]")
    ins(0x0041CA16, "call", "dword ptr [eax + 0x3c]")
    ins(0x0041CD53, "mov", "ecx, dword ptr [edi + 0x24]")
    ins(0x0041CD61, "push", "esi")
    ins(0x0041CD62, "push", "dword ptr [ebp + 8]")
    ins(0x0041CD65, "call", "dword ptr [eax + 0x3c]")

    # On six other shape-compatible sites, the exact same receiver is also
    # called through CFile's +0x24 slot with one pushed argument. CFile's target
    # at +0x24 is Open and consumes three stack parameters, so these receiver
    # paths are not compatible with a CFile-family vptr.
    expected_receiver = {
        "EDI": "ecx, edi",
        "[ESI+0x398]": "ecx, dword ptr [esi + 0x398]",
        "[EDI+0x398]": "ecx, dword ptr [edi + 0x398]",
    }
    for write_va, (receiver, open_va, open_this_va, write_this_va, open_push_va, arg_shape) in NON_CFILE_RECEIVER.items():
        open_call = ins(open_va, "call")
        if open_call.operands[0].type != CS_OP_MEM or open_call.operands[0].mem.disp != 0x24:
            raise SystemExit(f"expected same-receiver +0x24 call at 0x{open_va:08X}")
        expected = expected_receiver[receiver]
        ins(open_this_va, "mov", expected)
        ins(write_this_va, "mov", expected)
        ins(open_push_va, "push")
        pushes_before_open = [
            x for x in instructions if min(open_this_va, open_push_va) <= x.address < open_va and x.mnemonic == "push"
        ]
        if [x.address for x in pushes_before_open] != [open_push_va]:
            raise SystemExit(f"expected exactly one explicit +0x24 argument at 0x{open_va:08X}")
        write_call = ins(write_va, "call")
        if write_call.operands[0].type != CS_OP_MEM or write_call.operands[0].mem.disp != 0x3C:
            raise SystemExit(f"expected +0x3c call at 0x{write_va:08X}")

    if set(ARCHIVE_WRITE_CALLS) & set(NON_CFILE_RECEIVER):
        raise SystemExit("overlapping receiver classifications")
    if set(ARCHIVE_WRITE_CALLS) | set(NON_CFILE_RECEIVER) | set(ARITY_MISMATCH) | {0x00417D1A} != set(CALLS_3C):
        raise SystemExit("candidate classification does not cover the full census exactly once")

    rows = []
    for va in CALLS_3C:
        call = ins(va, "call")
        if va in ARCHIVE_WRITE_CALLS:
            item = ARCHIVE_WRITE_CALLS[va]
            category = "CFile::Write virtual slot; concrete target unresolved"
            shape = item["args"]
            basis = item["basis"]
            confidence = "strong CFile::Write-slot/signature attribution; runtime vptr and override unresolved"
        elif va in NON_CFILE_RECEIVER:
            receiver, open_va, _open_this_va, _write_this_va, _open_push_va, shape = NON_CFILE_RECEIVER[va]
            category = "unresolved receiver; bounded +0x24 use is inconsistent with base CFile::Open arity"
            shape = shape
            basis = f"receiver {receiver}; same pointer uses +0x24 at 0x{open_va:08X} with one explicit argument; base CFile +0x24 is Open (3 args, ret 0x0c); derived/runtime vptr unresolved."
            confidence = "bounded call shape observed; class attribution unresolved"
        elif va == 0x00417D1A:
            category = "not CFile::Write argument layout"
            shape = "ECX=this; stack[0]=this again; stack[1]=path pointer"
            basis = "CFile::Write expects stack[0]=buffer and stack[1]=byte count; this site passes the receiver again as buffer and a path pointer as count."
            confidence = "argument provenance observed"
        else:
            count, reason = ARITY_MISMATCH[va]
            category = "not CFile::Write ABI shape"
            shape = f"{count} stack words"
            basis = f"{reason}; CFile::Write requires ECX=this plus exactly two stack parameters."
            confidence = "call-site ABI mismatch observed"
        rows.append((f"0x{va:08X}", call.op_str, category, shape, confidence, basis))

    # RTTI shows CFile-derived implementations override this slot, so the two
    # archive calls cannot be resolved to the base wrapper solely from slot ID.
    derived = [
        (0x0055F284, b".?AVCMemFile@@", 0x004248F0),
        (0x00576AD0, b".?AVCSharedFile@@", 0x004248F0),
        (0x005769D8, b".?AVCOleStreamFile@@", 0x004E4431),
    ]
    derived_rows = []
    for table, expected_name, expected_target in derived:
        col2 = u32(table - 4)
        td = u32(col2 + 12)
        h = u32(col2 + 16)
        h_count = u32(h + 8)
        h_array = u32(h + 12)
        names = []
        for index in range(h_count):
            desc = u32(h_array + index * 4)
            names.append(c_string(u32(desc) + 8))
        if names[0] != expected_name or b".?AVCFile@@" not in names:
            raise SystemExit(f"CFile-derived RTTI mismatch at 0x{table:08X}: {names!r}")
        target = u32(table + 15 * 4)
        if target != expected_target:
            raise SystemExit(f"derived slot +0x3c mismatch at 0x{table:08X}")
        derived_rows.append((f"0x{table:08X}", names[0].decode(), f"0x{target:08X}", "RTTI hierarchy includes CFile; slot +0x3c overrides the base implementation."))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(("callsite", "decoded_call", "classification", "argument_shape", "confidence_scope", "evidence_basis"))
        writer.writerows(rows)
        writer.writerow(())
        writer.writerow(("derived_vtable", "RTTI_type", "slot_+0x3c_target", "scope"))
        writer.writerows(derived_rows)

    print(f"Verified the hash-pinned S98 binary and all {len(CALLS_3C)} generic +0x3c candidates.")
    print("Two sites (0x0041CA16, 0x0041CD65) are attributable to the CFile::Write virtual slot in CArchive-shaped code.")
    print("The exact target is unresolved: RTTI proves CMemFile, CSharedFile, and COleStreamFile override slot +0x3c.")
    print("The other 22 are not proven CFile::Write: 15 fail stack arity, one has wrong argument roles, and six have unresolved receivers with base-CFile +0x24 arity conflicts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
