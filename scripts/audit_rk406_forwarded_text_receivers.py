#!/usr/bin/env python3
"""Verify five caller-scoped RK 4.06 text receiver chains without running the PE.

The listed paths reach the local DrawTextW adapter. This is not a whole-program
proof that every possible caller supplies that type, nor runtime observation.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path
import re
import struct
import sys

from audit_rk406_g5_vcall_resolution import (
    EXPECTED_SHA256,
    disassemble_range,
    instruction_map,
    run_objdump,
)


class Image:
    """Read mapped PE32 bytes; no image loading or execution is performed."""

    def __init__(self, path: Path):
        self.data = path.read_bytes()
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe:pe + 4] != b"PE\0\0":
            raise RuntimeError("invalid PE signature")
        count = struct.unpack_from("<H", self.data, pe + 6)[0]
        optional_size = struct.unpack_from("<H", self.data, pe + 20)[0]
        optional = pe + 24
        if struct.unpack_from("<H", self.data, optional)[0] != 0x10B:
            raise RuntimeError("expected PE32")
        self.base = struct.unpack_from("<I", self.data, optional + 28)[0]
        self.sections = []
        for index in range(count):
            start = optional + optional_size + index * 40
            size, rva, raw_size, raw = struct.unpack_from("<4I", self.data, start + 8)
            self.sections.append((rva, max(size, raw_size), raw, raw_size))

    def read(self, va: int, size: int) -> bytes:
        rva = va - self.base
        for start, mapped_size, raw, raw_size in self.sections:
            if start <= rva and rva + size <= start + mapped_size:
                relative = rva - start
                if relative + size > raw_size:
                    raise RuntimeError(f"VA 0x{va:08X} extends outside raw bytes")
                return self.data[raw + relative:raw + relative + size]
        raise RuntimeError(f"unmapped VA 0x{va:08X}")

    def words(self, va: int, count: int) -> tuple[int, ...]:
        return struct.unpack(f"<{count}I", self.read(va, count * 4))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def stack_delta(instructions: list[tuple[int, str]], stop: int) -> int:
    """Replay a call-free straight-line fragment up to, but excluding, stop."""
    delta = 0
    for va, asm in instructions:
        if va >= stop:
            break
        if asm.startswith("push "):
            delta -= 4
        elif asm.startswith("pop "):
            delta += 4
        elif match := re.fullmatch(r"(add|sub) esp,0x([0-9a-f]+)", asm):
            value = int(match.group(2), 16)
            delta += value if match.group(1) == "add" else -value
        elif asm.startswith("call "):
            raise RuntimeError(f"stack fragment crosses a call at 0x{va:08X}")
        elif re.match(r"(?:and|lea|mov) esp,", asm):
            raise RuntimeError(f"unsupported ESP mutation at 0x{va:08X}")
    return delta


def run() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    require(args.binary.is_file(), f"binary not found: {args.binary}")
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    require(digest == EXPECTED_SHA256, f"binary SHA-256 mismatch: {digest}")
    image = Image(args.binary)
    require(image.base == 0x400000, "unexpected image base")

    def block(start: int, stop: int, expected: dict[int, str]) -> list[tuple[int, str]]:
        result = disassemble_range(args.binary, args.objdump, start, stop)
        actual = instruction_map(result)
        for va, asm in expected.items():
            require(actual.get(va) == asm, f"0x{va:08X}: expected {asm!r}, got {actual.get(va)!r}")
        return result

    # Shared concrete adapter identity and imported target.
    block(0x47105C, 0x471070, {0x471060: "mov dword ptr [eax],0x59f314", 0x47106F: "ret"})
    require(image.words(0x59F314 + 0x68, 1) == (0x47111A,), "adapter slot +0x68 changed")
    block(0x47111A, 0x471138, {0x47112E: "call dword ptr ds:0x59e6b8", 0x471135: "ret 0x10"})
    imports = run_objdump(args.objdump, "-p", str(args.binary))
    require(bool(re.search(r"0019e6b8\s+<none>\s+\S+\s+DrawTextW", imports)), "DrawTextW IAT mapping changed")

    # Both custom owner maps inherit the base WM_PAINT entry. Their +0x144
    # virtuals take the concrete adapter as their first explicit argument.
    for table, target, map_va, entries in (
        (0x5D22AC, 0x434350, 0x5D22A0, 0x5D2240),
        (0x5D9BEC, 0x466C40, 0x5D9BE0, 0x5D9BB0),
    ):
        require(image.words(table + 0x144, 1) == (target,), "owner +0x144 target changed")
        require(image.words(map_va, 2) == (0x455780, entries), "owner base-message-map link changed")
    for table, col, descriptor, name in (
        (0x5D22AC, 0x5E4070, 0x60395C, b".?AVCMenuSrDlg@@\0"),
        (0x5D9BEC, 0x5E4934, 0x603C30, b".?AVCFrameEditView@@\0"),
    ):
        require(image.words(table - 4, 1) == (col,), "owner RTTI COL link changed")
        require(image.words(col + 12, 1) == (descriptor,), "owner RTTI descriptor link changed")
        require(image.read(descriptor + 8, len(name)) == name, "owner RTTI name changed")
    require(image.words(0x5D22AC + 0x28, 1) == (0x434240,), "CMenuSrDlg map accessor slot changed")
    require(image.words(0x5D9BEC + 0x28, 1) == (0x466C30,), "CFrameEditView map accessor slot changed")
    require(image.words(0x5D79A8, 2) == (0x4780A2, 0x5D7900), "base message-map header changed")
    require(image.words(0x5D7900, 6) == (0xF, 0, 0, 0, 0x13, 0x455790), "WM_PAINT map row changed")
    block(0x455780, 0x455786, {0x455780: "mov eax,0x5d79a8", 0x455785: "ret"})
    block(0x434240, 0x434246, {0x434240: "mov eax,0x5d22a0", 0x434245: "ret"})
    block(0x466C30, 0x466C36, {0x466C30: "mov eax,0x5d9be0", 0x466C35: "ret"})
    block(0x4341C5, 0x4341CB, {0x4341C5: "mov dword ptr [esi],0x5d22ac"})
    block(0x46AEC9, 0x46AECF, {0x46AEC9: "mov dword ptr [esi],0x5d9bec"})
    block(0x4557F4, 0x4557FD, {0x4557F4: "lea ecx,[esp+0x24]", 0x4557F8: "call 0x47105c"})
    painter = block(0x455860, 0x455879, {
        0x455866: "mov eax,dword ptr [esi]", 0x455868: "push ecx", 0x455869: "push edx",
        0x45586A: "mov edx,dword ptr [eax+0x144]", 0x455870: "lea ecx,[esp+0x2c]",
        0x455874: "push ecx", 0x455875: "mov ecx,esi", 0x455877: "call edx",
    })
    require(stack_delta(painter, 0x455870) + 0x2C == 0x24, "painter first argument is not adapter local +0x24")
    block(0x434350, 0x434353, {0x434350: "push ebp", 0x434351: "mov ebp,esp"})
    block(0x4343AE, 0x4343B6, {0x4343B3: "mov edi,dword ptr [ebp+0x8]"})
    block(0x4344E0, 0x4344FC, {
        0x4344E7: "mov edx,dword ptr [edi]", 0x4344E9: "push 0x8134",
        0x4344F5: "mov eax,dword ptr [edx+0x68]", 0x4344F8: "mov ecx,edi", 0x4344FA: "call eax",
    })
    block(0x466C40, 0x466C43, {0x466C40: "push ebp", 0x466C41: "mov ebp,esp"})
    saved_argument = block(0x466C80, 0x466C99, {
        0x466C80: "mov edi,dword ptr [ebp+0x8]", 0x466C8F: "push eax", 0x466C90: "push ecx",
        0x466C95: "mov dword ptr [esp+0x2c],edi",
    })
    require(stack_delta(saved_argument, 0x466C95) + 0x2C == 0x24, "saved DC argument is not local +0x24")
    leaf = block(0x466F2D, 0x466F5A, {
        0x466F2D: "mov edx,dword ptr [esp+0x24]", 0x466F40: "mov edx,dword ptr [edx]",
        0x466F42: "push 0x8135", 0x466F50: "mov ecx,dword ptr [esp+0x30]",
        0x466F55: "mov eax,dword ptr [edx+0x68]", 0x466F58: "call eax",
    })
    require(stack_delta(leaf, 0x466F50) + 0x30 == 0x24, "leaf ECX reload is not saved local +0x24")

    # A compiler-private register argument: both direct callers supply EBX.
    block(0x4267E4, 0x4267ED, {0x4267E4: "lea ecx,[esp+0x34]", 0x4267E8: "call 0x47105c"})
    for start, end, lea, call in ((0x426DD8, 0x426E02, 0x426DF6, 0x426DFD), (0x426EA2, 0x426ECC, 0x426EC0, 0x426EC7)):
        caller = block(start, end, {lea: "lea ebx,[esp+0x48]", call: "call 0x454c60"})
        require(stack_delta(caller, lea) + 0x48 == 0x34, "forwarded EBX does not equal caller adapter +0x34")
    helper = block(0x454C60, 0x454D87, {
        0x454CE2: "mov edi,0x8134", 0x454D1C: "mov edi,0x8114", 0x454D3F: "push edi",
        0x454D3D: "mov edx,dword ptr [ebx]", 0x454D46: "mov eax,dword ptr [edx+0x68]",
        0x454D49: "mov ecx,ebx", 0x454D4B: "call eax", 0x454D86: "ret",
    })
    writes_ebx = [va for va, asm in helper if re.match(r"(?:mov|lea|pop|add|sub|xor|and|or|inc|dec|xchg) ebx(?:,|$)", asm)]
    require(not writes_ebx, f"helper overwrites the hidden EBX argument: {writes_ebx}")

    # Two separate helpers receive the caller's adapter through a stack arg.
    for start, call in ((0x45BDE4, 0x45BDE8), (0x45D7B4, 0x45D7B8)):
        block(start, call + 5, {start: "lea ecx,[esp+0x3c]", call: "call 0x47105c"})
    for start, end, lea, call, target in (
        (0x45BF15, 0x45BF2A, 0x45BF1F, 0x45BF25, 0x45BFE0),
        (0x45D8E5, 0x45D8F9, 0x45D8EF, 0x45D8F4, 0x45D9B0),
    ):
        caller = block(start, end, {lea: "lea eax,[esp+0x44]", call: f"call 0x{target:x}"})
        require(stack_delta(caller, lea) + 0x44 == 0x3C, "forwarded stack argument is not caller adapter +0x3C")
    prologue_a = block(0x45BFE0, 0x45C000, {0x45BFEE: "sub esp,0xc4", 0x45BFFF: "push eax"})
    prologue_b = block(0x45D9B0, 0x45D9CF, {0x45D9BE: "sub esp,0xc4", 0x45D9CE: "push eax"})
    require(stack_delta(prologue_a, 0x45C000) == -0xE4, "first helper frame delta changed")
    require(stack_delta(prologue_b, 0x45D9CF) == -0xE0, "second helper frame delta changed")
    require(-0xE4 + 0xEC == 8 and -0xE0 + 0xE4 == 4, "helper argument normalization failed")
    block(0x45C586, 0x45C60C, {
        0x45C586: "mov esi,dword ptr [esp+0xec]", 0x45C5F4: "mov edx,dword ptr [esi]",
        0x45C5F6: "push 0x8134", 0x45C605: "mov eax,dword ptr [edx+0x68]",
        0x45C608: "mov ecx,esi", 0x45C60A: "call eax",
    })
    block(0x45DEFF, 0x45DF82, {
        0x45DEFF: "mov esi,dword ptr [esp+0xe4]", 0x45DF6D: "mov edx,dword ptr [esi]",
        0x45DF6F: "push 0x8134", 0x45DF7B: "mov eax,dword ptr [edx+0x68]",
        0x45DF7E: "mov ecx,esi", 0x45DF80: "call eax",
    })
    block(0x45C6A5, 0x45C6AE, {0x45C6AB: "ret 0x10"})
    block(0x45E001, 0x45E00A, {0x45E007: "ret 0xc"})

    cases = (
        (0x4344FA, "0x00455790 -> owner +0x144 -> 0x00434350", "0x004557F8", "+0x24", "first explicit argument -> EDI", "0x8134"),
        (0x454D4B, "0x00426DFD or 0x00426EC7 -> 0x00454C60", "0x004267E8", "+0x34", "compiler-private EBX argument", "0x8134/0x8114"),
        (0x45C60A, "0x0045BF25 -> 0x0045BFE0", "0x0045BDE8", "+0x3C", "second stack argument -> ESI at [esp+0xEC]", "0x8134"),
        (0x45DF80, "0x0045D8F4 -> 0x0045D9B0", "0x0045D7B8", "+0x3C", "first stack argument -> ESI at [esp+0xE4]", "0x8134"),
        (0x466F58, "0x00455790 -> owner +0x144 -> 0x00466C40", "0x004557F8", "+0x24", "first explicit argument -> saved local +0x24", "0x8135"),
    )
    rows = [{
        "call_va": f"0x{va:08X}", "caller_path": path,
        "adapter_constructor_call_va": constructor, "caller_frame_local": local,
        "forwarding": forwarding, "flags": flags, "adapter_vtable_va": "0x0059F314",
        "target_va": "0x0047111A", "import": "USER32!DrawTextW",
        "scope": "resolved on listed caller paths",
        "limitation": "alternate callers and runtime targets unknown; no device or target execution",
    } for va, path, constructor, local, forwarding, flags in cases]
    out = args.out.open("w", newline="", encoding="utf-8") if args.out else sys.stdout
    try:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    finally:
        if args.out:
            out.close()
    print("Verified 5 caller-scoped DrawTextW receiver chains; alternate callers/runtime targets remain unknown.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
