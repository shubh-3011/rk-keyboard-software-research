#!/usr/bin/env python3
"""Verify the RK 4.6 text-macro WM_COMMAND and selection-persistence bridge.

Static PE bytes/disassembly only. No target execution or device access.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path
import re
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

from audit_rk406_forwarded_text_receivers import Image, require
from audit_rk406_g5_vcall_resolution import disassemble_range, instruction_map, run_objdump

EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"


def run() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    require(digest == EXPECTED_SHA256, f"binary SHA-256 mismatch: {digest}")
    image = Image(args.binary)
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    rows: list[dict[str, str]] = []

    def block(start: int, stop: int, expected: dict[int, str], stage: str) -> None:
        actual = instruction_map(disassemble_range(args.binary, args.objdump, start, stop))
        for va, asm in expected.items():
            require(actual.get(va) == asm, f"0x{va:08X}: expected {asm!r}, got {actual.get(va)!r}")
            decoded = next(decoder.disasm(image.read(va, 15), va, count=1), None)
            require(decoded is not None, f"could not decode evidence instruction at 0x{va:08X}")
            rows.append({"binary_sha256": digest, "stage": stage, "evidence_va": f"0x{va:08X}",
                         "bytes": image.read(va, decoded.size).hex().upper(), "evidence": asm,
                         "scope": "static instruction; execution and runtime delivery unobserved"})

    for table, col, typename, method in (
        (0x5D530C, 0x5ED020, b".?AVCKeyFunPickDlg@@\0", 0x421350),
        (0x5E2624, 0x5EDBEC, b".?AVCWelcomDlg@@\0", 0x46C050),
    ):
        require(image.words(table - 4, 1) == (col,), "owner RTTI COL changed")
        descriptor = image.words(col + 12, 1)[0]
        require(image.read(descriptor + 8, len(typename)) == typename, "owner RTTI name changed")
        require(image.words(table + 0xF0, 1) == (method,), "owner command virtual changed")
        rows.append({"binary_sha256": digest, "stage": "owner_vtable", "evidence_va": f"0x{table + 0xF0:08X}",
                     "bytes": image.read(table + 0xF0, 4).hex().upper(),
                     "evidence": f"{typename[:-1].decode()} +0xF0 -> 0x{method:08X}",
                     "scope": "static class/slot identity; no runtime object observation"})

    block(0x41F638, 0x41F649, {0x41F63E: "mov dword ptr [esi],0x5d530c"}, "picker_constructor")
    require(image.words(0x5DE068, 1) == (0x5ED8B8,), "button RTTI COL changed")
    button_descriptor = image.words(0x5ED8B8 + 12, 1)[0]
    require(image.read(button_descriptor + 8, len(b".?AVCPngBtn@@\0")) == b".?AVCPngBtn@@\0", "button RTTI type changed")
    require(image.words(0x5DE06C + 0x13C, 1) == (0x482218,), "button creation virtual changed")
    require(image.read(0x5A8618, 14) == "BUTTON\0".encode("utf-16le"), "button class literal changed")
    require(image.read(0x5DC220, len("tc_apply\0".encode("utf-16le"))) == "tc_apply\0".encode("utf-16le"),
            "Apply localization key literal changed")
    block(0x44470C, 0x444753, {
        0x44470C: "push 0x5dc220", 0x444738: "call 0x443f00",
        0x444740: "push eax", 0x444741: "mov ecx,0x647450", 0x44474E: "call 0x405b20",
    }, "apply_key_caption_global")
    block(0x41F649, 0x41F659, {
        0x41F649: "lea ecx,[esi+0x204]", 0x41F654: "call 0x44cde0",
    }, "sender_constructor")
    block(0x44CE16, 0x44CE1C, {0x44CE16: "mov dword ptr [esi],0x5de06c"}, "sender_button_vptr")
    block(0x420562, 0x420574, {
        0x420562: "lea edi,[ebx+0x204]", 0x420568: "mov eax,0x647450",
        0x42056D: "mov ecx,ebx", 0x42056F: "call 0x4520b0",
    }, "sender_creation_call")
    block(0x4520B0, 0x4520D3, {
        0x4520B3: "push 0x0", 0x4520B5: "push ecx", 0x4520BA: "push edx",
        0x4520BB: "mov ebx,eax", 0x4520BF: "mov eax,dword ptr [eax+0x13c]", 0x4520C5: "push 0x5000000b",
        0x4520CA: "push 0x5d1110", 0x4520CF: "mov ecx,edi", 0x4520D1: "call eax",
    }, "button_creation_arguments")
    block(0x4520D3, 0x4520D9, {0x4520D7: "mov eax,dword ptr [ebx]"}, "caption_source_dereference")
    block(0x482218, 0x48223C, {
        0x482221: "push dword ptr [ebp+0x18]", 0x482230: "push 0x5a8618",
        0x482235: "call dword ptr [eax+0x54]", 0x482239: "ret 0x14",
    }, "button_class_and_id_forwarding")
    block(0x47EC9B, 0x47ECB7, {
        0x47EC9B: "mov ebx,dword ptr [ebp+0x8]", 0x47ECA1: "cmp ebx,0x111",
        0x47ECA7: "jne 0x47eccb", 0x47ECA9: "push dword ptr [ebp+0x10]",
        0x47ECAC: "mov eax,dword ptr [edi]", 0x47ECAE: "push dword ptr [ebp+0xc]",
        0x47ECB1: "call dword ptr [eax+0xf0]",
    }, "wm_command_dispatch")
    block(0x421350, 0x421372, {
        0x421350: "sub esp,0x420", 0x421364: "push ebx", 0x421365: "push ebp",
        0x421366: "mov ebp,ecx", 0x421370: "push esi", 0x421371: "push edi",
    }, "picker_frame")
    require(-0x420 - 4 * 4 + 0x438 == 8, "lParam frame normalization failed")
    block(0x4213E1, 0x421417, {
        0x4213E1: "mov edx,dword ptr [esp+0x438]", 0x4213FE: "lea eax,[ebp+0x204]",
        0x42140C: "mov eax,dword ptr [eax+0x20]", 0x42140F: "cmp edx,eax",
        0x421411: "jne 0x421657",
    }, "sender_hwnd_gate")
    block(0x42144C, 0x42145A, {0x42144C: "mov eax,dword ptr [ebp+0x11ac]"}, "selection_state")
    block(0x421540, 0x421565, {
        0x421540: "cmp eax,0x5", 0x421543: "jne 0x421627", 0x42154B: "push 0x200",
        0x421550: "lea edx,[esp+0x30]", 0x421559: "mov ecx,dword ptr [ebp+0x11a8]",
        0x42155F: "push edx", 0x421560: "call 0x4806d1",
    }, "text_state_and_read")
    block(0x4806DD, 0x4806F6, {
        0x4806DF: "cmp dword ptr [esi+0x50],0x0", 0x4806E3: "jne 0x4806f6",
        0x4806EE: "call dword ptr ds:0x5a677c",
    }, "ordinary_window_text_read")
    block(0x421565, 0x4215E3, {
        0x421565: "xor eax,eax", 0x421567: "cmp ax,word ptr [esp+0x2c]", 0x42156C: "jne 0x421587",
        0x421587: "cmp dword ptr [edi],0xa00005b", 0x421596: "push 0x1",
        0x421598: "call 0x41f480", 0x42159F: "je 0x4215e5",
        0x4215A1: "mov dword ptr [ebp+0x17e4],0xa00005b",
        0x4215C0: "add eax,0x4", 0x4215C3: "push 0x200", 0x4215C8: "push eax",
        0x4215CF: "call 0x575e47", 0x4215D4: "mov edx,dword ptr ds:0x62a1fc",
        0x4215DD: "push edx", 0x4215DE: "call 0x41f540",
    }, "record_copy_and_save")
    block(0x41F583, 0x41F5CE, {
        0x41F58A: "push 0x2", 0x41F590: "push 0xc0000000",
        0x41F59A: "call dword ptr ds:0x5a6474", 0x41F5A2: "cmp esi,0xffffffff",
        0x41F5AE: "push 0xc8c8", 0x41F5B3: "push 0x60d3c4",
        0x41F5C1: "call dword ptr ds:0x5a646c", 0x41F5C8: "call dword ptr ds:0x5a64b8",
    }, "local_file_writer")
    block(0x46C146, 0x46C162, {
        0x46C146: "lea eax,[edi+0x508]", 0x46C156: "mov eax,dword ptr [eax+0x20]",
        0x46C159: "cmp dword ptr [ebp+0xc],eax", 0x46C15C: "jne 0x46c236",
    }, "welcome_sender_gate")
    block(0x46C1EF, 0x46C216, {
        0x46C1F1: "mov dword ptr ds:0x647320,esi", 0x46C1FC: "mov eax,dword ptr [edi+0x1440]",
        0x46C206: "mov ecx,dword ptr [esi]", 0x46C208: "movzx edx,word ptr [ecx+0x24e]",
        0x46C20F: "push edx", 0x46C210: "push eax", 0x46C211: "call 0x459f50",
    }, "welcome_selection_forwarding")
    block(0x46C236, 0x46C24D, {
        0x46C23A: "inc ebx", 0x46C23B: "add eax,0x184", 0x46C240: "cmp ebx,0xa",
        0x46C247: "jl 0x46c152",
    }, "welcome_ten_record_iteration")
    block(0x459F50, 0x459F99, {
        0x459F50: "push 0xffffffff", 0x459F52: "push 0x5a2ec1", 0x459F5D: "push eax",
        0x459F5E: "sub esp,0x25c", 0x459F72: "push ebx", 0x459F73: "push ebp",
        0x459F74: "push esi", 0x459F75: "push edi", 0x459F7D: "push eax",
        0x459F8B: "mov eax,dword ptr [esp+0x284]", 0x459F92: "mov ebp,dword ptr [esp+0x280]",
    }, "selection_routine_arguments")
    require(-0x25C - 8 * 4 + 0x284 == 8 and -0x25C - 8 * 4 + 0x280 == 4,
            "selection owner/new-ID argument normalization failed")
    block(0x459F99, 0x459FBA, {
        0x459F99: "mov edi,dword ptr ds:0x62a1fc", 0x459F9F: "cmp eax,0x6461",
        0x459FAA: "cmp edi,eax", 0x459FAC: "je 0x45a7d7",
        0x459FB2: "test eax,eax", 0x459FB4: "je 0x45a7d7",
    }, "new_selection_gate")
    block(0x45A04D, 0x45A05C, {
        0x45A04D: "cmp byte ptr ds:0x62b8b3,0x0", 0x45A054: "je 0x45a05c",
        0x45A056: "push edi", 0x45A057: "call 0x41f540",
    }, "old_partition_save")
    block(0x45A0D7, 0x45A0F3, {
        0x45A0D7: "mov esi,dword ptr [esp+0x284]", 0x45A0E4: "cmp byte ptr ds:0x62b8b3,0x0",
        0x45A0EB: "je 0x45a0f3", 0x45A0ED: "push esi", 0x45A0EE: "call 0x4597e0",
    }, "new_partition_load")
    imports = run_objdump(args.objdump, "-p", str(args.binary))
    for rva, name in ((0x1A677C, "GetWindowTextW"), (0x1A6474, "CreateFileW"), (0x1A646C, "WriteFile"), (0x1A64B8, "CloseHandle")):
        require(bool(re.search(rf"{rva:08x}\s+<none>\s+\S+\s+{name}\b", imports)), f"IAT mapping changed: {name}")
    out = args.out.open("w", newline="", encoding="utf-8") if args.out else sys.stdout
    try:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    finally:
        if args.out:
            out.close()
    print(f"Verified {len(rows)} static text-macro command/lifecycle evidence rows; visible labels/runtime delivery remain unobserved.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
