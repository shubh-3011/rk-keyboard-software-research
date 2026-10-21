#!/usr/bin/env python3
"""Resolve thirty-nine DeviceDriver +0x68 dispatches and compare them with G5 GetRealData.

This is a static disassembly audit. It invokes GNU objdump on a supplied PE;
it never executes the target binary or communicates with a keyboard.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path
import re
import subprocess
import sys


RECEIVER_STACK_OFFSETS = {
    0x00401E92: 0x48,
    0x00401F1E: 0x48,
    0x00401FB5: 0x48,
    0x00402059: 0x48,
    0x004020FD: 0x48,
    0x0040217A: 0x48,
    0x00421BE1: 0x58,
    0x00421C87: 0x58,
    0x00421D7C: 0x58,
    0x00421E12: 0x58,
    0x00421EA8: 0x58,
    0x00421F45: 0x58,
    0x00421FDD: 0x58,
    0x0042205D: 0x58,
    0x004269DC: 0x44,
    0x00426A61: 0x44,
    0x00426AE6: 0x44,
    0x00426B61: 0x44,
    0x00426BED: 0x44,
    0x00426C68: 0x44,
    0x00426CE3: 0x44,
    0x00426D5E: 0x44,
    0x00426F54: 0x44,
    0x00426FC7: 0x44,
    0x00433DDA: 0x38,
    0x00433E83: 0x38,
    0x004352CC: 0x1C,
    0x0044AEAE: 0x6C,
    0x0045792D: 0x58,
    0x0045795A: 0x58,
    0x00457984: 0x58,
    0x004579AE: 0x58,
    0x00466A8D: 0x2C,
    0x00466AD8: 0x2C,
    0x0045B714: 0x2C,
    0x0045B7E0: 0x2C,
    0x0045B5BF: 0x2C,
    0x00469345: 0x20,
    0x00469386: 0x20,
}
CANDIDATES = tuple(RECEIVER_STACK_OFFSETS)
PRE_CALL_INSTRUCTION_COUNTS = {
    0x00421C87: 12,
    0x00433E83: 12,
    0x00469345: 10,
}
ALTERNATE_CALL_REGISTERS = {0x00433DDA: "eax", 0x00433E83: "eax", 0x0044AEAE: "eax"}
SPECIAL_VPTR_SETUP = {
    0x00433DDA: (
        "mov edx,dword ptr [esp+0x28]",
        "mov eax,dword ptr [edx+0x68]",
        "lea ecx,[esp+0x38]",
    ),
    0x00433E83: (
        "mov edx,dword ptr [esp+0x28]",
        "mov eax,dword ptr [edx+0x68]",
        "lea ecx,[esp+0x38]",
    ),
    0x004352CC: (
        "mov eax,dword ptr [esp+0x18]",
        "mov edx,dword ptr [eax+0x68]",
        "lea ecx,[esp+0x1c]",
    ),
    0x0044AEAE: (
        "mov edx,dword ptr [esp+0x68]",
        "mov eax,dword ptr [edx+0x68]",
        "lea ecx,[esp+0x6c]",
    ),
}
DYNAMIC_FLAG_CALLS = {0x0044AEAE}
G5_WRAPPER = 0x00410700
EXPECTED_SHA256 = "c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6"
ENTRY_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}\s+)+)(\S.*)$")


def disassemble(binary: Path, objdump: str) -> list[tuple[int, str]]:
    result = subprocess.run(
        [objdump, "-d", "-Mintel", str(binary)],
        check=True,
        capture_output=True,
        text=True,
        errors="replace",
    )
    instructions: list[tuple[int, str]] = []
    for line in result.stdout.splitlines():
        match = ENTRY_RE.match(line)
        if match:
            asm = " ".join(match.group(3).lower().split())
            instructions.append((int(match.group(1), 16), asm))
    if not instructions:
        raise RuntimeError("objdump produced no parseable instructions")
    return instructions


def instruction_map(instructions: list[tuple[int, str]]) -> dict[int, str]:
    return dict(instructions)


def run_objdump(objdump: str, *arguments: str) -> str:
    return subprocess.run(
        [objdump, *arguments], check=True, capture_output=True, text=True, errors="replace"
    ).stdout


def nearest_window(instructions: list[tuple[int, str]], target: int, before: int, after: int) -> list[tuple[int, str]]:
    index_by_address = {address: index for index, (address, _) in enumerate(instructions)}
    if target not in index_by_address:
        raise RuntimeError(f"target VA 0x{target:08X} not found in disassembly")
    index = index_by_address[target]
    return instructions[max(0, index - before):index + after + 1]


def run() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="hash-verified 4.06 DeviceDriver.exe")
    parser.add_argument("--objdump", default="objdump", help="GNU objdump executable")
    parser.add_argument("--out", type=Path, help="CSV output path; defaults to stdout")
    args = parser.parse_args()
    if not args.binary.is_file():
        parser.error(f"binary not found: {args.binary}")
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    if digest != EXPECTED_SHA256:
        parser.error(f"binary SHA-256 mismatch: expected {EXPECTED_SHA256}, got {digest}")

    instructions = disassemble(args.binary, args.objdump)
    by_address = instruction_map(instructions)
    wrapper = nearest_window(instructions, G5_WRAPPER, 0, 5)
    wrapper_rets = [asm for _, asm in wrapper if asm.startswith("ret")]
    if not wrapper_rets or any(not re.fullmatch(r"ret\s+0x8", asm) for asm in wrapper_rets):
        raise RuntimeError(f"unexpected G5 wrapper return sequence at 0x{G5_WRAPPER:08X}: {wrapper_rets}")

    constructor = instruction_map(disassemble_range(args.binary, args.objdump, 0x0047105C, 0x00471070))
    if constructor.get(0x00471060) != "mov dword ptr [eax],0x59f314":
        raise RuntimeError("the observed local adapter constructor no longer installs vtable 0x0059F314")
    if constructor.get(0x00471069) != "mov dword ptr [eax+0x8],ecx" or constructor.get(0x0047106C) != "mov dword ptr [eax+0xc],ecx":
        raise RuntimeError("the local adapter constructor fields changed")

    local_constructor = instruction_map(disassemble_range(args.binary, args.objdump, 0x004216C7, 0x004216D0))
    if local_constructor.get(0x004216C7) != "lea ecx,[esp+0x48]" or local_constructor.get(0x004216CB) != "call 0x47105c":
        raise RuntimeError("the repeated-label receiver is no longer constructed at [esp+0x48] by 0x0047105C")

    later_page_constructor = instruction_map(disassemble_range(args.binary, args.objdump, 0x004267E4, 0x004267ED))
    if later_page_constructor.get(0x004267E4) != "lea ecx,[esp+0x34]" or later_page_constructor.get(0x004267E8) != "call 0x47105c":
        raise RuntimeError("the later-page receiver is no longer constructed at [esp+0x34] by 0x0047105C")

    color_page_constructor = instruction_map(disassemble_range(args.binary, args.objdump, 0x00433AB7, 0x00433AC0))
    if color_page_constructor.get(0x00433AB7) != "lea ecx,[esp+0x28]" or color_page_constructor.get(0x00433ABB) != "call 0x47105c":
        raise RuntimeError("the color-page receiver is no longer constructed at [esp+0x28] by 0x0047105C")

    focused_page_constructor = instruction_map(disassemble_range(args.binary, args.objdump, 0x00435125, 0x0043512E))
    if focused_page_constructor.get(0x00435125) != "lea ecx,[esp+0xc]" or focused_page_constructor.get(0x00435129) != "call 0x47105c":
        raise RuntimeError("the focused-page receiver is no longer constructed at [esp+0x0C] by 0x0047105C")

    scale_page_constructor = instruction_map(disassemble_range(args.binary, args.objdump, 0x0044A6C8, 0x0044A6D1))
    if scale_page_constructor.get(0x0044A6C8) != "lea ecx,[esp+0x5c]" or scale_page_constructor.get(0x0044A6CC) != "call 0x47105c":
        raise RuntimeError("the scale-page receiver is no longer constructed at [esp+0x5C] by 0x0047105C")

    mode_page_constructor = instruction_map(disassemble_range(args.binary, args.objdump, 0x00457517, 0x00457520))
    if mode_page_constructor.get(0x00457517) != "lea ecx,[esp+0x48]" or mode_page_constructor.get(0x0045751B) != "call 0x47105c":
        raise RuntimeError("the mode-page receiver is no longer constructed at [esp+0x48] by 0x0047105C")

    text_page_constructor = instruction_map(disassemble_range(args.binary, args.objdump, 0x0045B404, 0x0045B40D))
    if text_page_constructor.get(0x0045B404) != "lea ecx,[esp+0x1c]" or text_page_constructor.get(0x0045B408) != "call 0x47105c":
        raise RuntimeError("the text-page receiver is no longer constructed at [esp+0x1C] by 0x0047105C")

    repeated_model_page_constructor = instruction_map(disassemble_range(args.binary, args.objdump, 0x004668C4, 0x004668CD))
    if repeated_model_page_constructor.get(0x004668C4) != "lea ecx,[esp+0x1c]" or repeated_model_page_constructor.get(0x004668C8) != "call 0x47105c":
        raise RuntimeError("the repeated model-page receiver is no longer constructed at [esp+0x1C] by 0x0047105C")

    layout_page_constructor = instruction_map(disassemble_range(args.binary, args.objdump, 0x00469214, 0x0046921D))
    if layout_page_constructor.get(0x00469214) != "lea ecx,[esp+0x10]" or layout_page_constructor.get(0x00469218) != "call 0x47105c":
        raise RuntimeError("the layout-page receiver is no longer constructed at [esp+0x10] by 0x0047105C")

    dynamic_flags = instruction_map(disassemble_range(args.binary, args.objdump, 0x0044AE84, 0x0044AE92))
    expected_dynamic_flags = {
        0x0044AE84: "xor eax,eax",
        0x0044AE86: "cmp ecx,ebx",
        0x0044AE88: "setle al",
        0x0044AE8B: "add eax,0x8134",
        0x0044AE90: "mov ecx,eax",
    }
    if any(dynamic_flags.get(address) != asm for address, asm in expected_dynamic_flags.items()):
        raise RuntimeError("the 0x0044AEAE text flags are no longer derived as 0x8134 or 0x8135")

    vtable = run_objdump(args.objdump, "-s", "--start-address=0x59f374", "--stop-address=0x59f380", str(args.binary))
    if not re.search(r"59f374\s+bb104700\s+e2104700\s+1a114700", vtable.lower()):
        raise RuntimeError("vtable 0x0059F314 slot +0x68 no longer resolves to 0x0047111A")

    adapter = instruction_map(disassemble_range(args.binary, args.objdump, 0x0047111A, 0x00471138))
    if adapter.get(0x0047112E) != "call dword ptr ds:0x59e6b8" or adapter.get(0x00471135) != "ret 0x10":
        raise RuntimeError("the +0x68 adapter no longer forwards four arguments through IAT 0x0059E6B8 and returns with ret 0x10")
    imports = run_objdump(args.objdump, "-p", str(args.binary))
    if not re.search(r"0019e6b8\s+<none>\s+\S+\s+DrawTextW", imports):
        raise RuntimeError("IAT RVA 0x0019E6B8 no longer resolves to USER32!DrawTextW")

    rows: list[dict[str, str]] = []
    for call_va in CANDIDATES:
        window = nearest_window(
            instructions,
            call_va,
            PRE_CALL_INSTRUCTION_COUNTS.get(call_va, 8),
            1,
        )
        call_asm = by_address[call_va]
        call_register = ALTERNATE_CALL_REGISTERS.get(call_va, "edx")
        if not re.fullmatch(rf"call\s+{call_register}", call_asm):
            raise RuntimeError(f"candidate 0x{call_va:08X} no longer uses its expected indirect call register: {call_asm}")
        pre_call = [asm for _, asm in window[:-1]]
        pushes = [asm for asm in pre_call if asm.startswith("push ")]
        receiver_setups = [asm for asm in pre_call if asm.startswith("lea ecx,")]
        pushed_id = next((asm.removeprefix("push ") for asm in pushes if re.fullmatch(r"push\s+0x(?:811[45]|813[456])", asm)), "")
        if call_va in DYNAMIC_FLAG_CALLS and "push ecx" in pushes:
            pushed_id = "0x8134/0x8135 (derived)"
        # nearest_window includes the instruction after the call as the last row.
        following = nearest_window(instructions, call_va, 0, 1)[-1][1]
        immediate_adjust = bool(re.match(r"(?:add|lea)\s+esp\b|pop\s+", following))
        if len(pushes) != 4 or not receiver_setups or not pushed_id:
            raise RuntimeError(f"unexpected call setup at 0x{call_va:08X}: {pre_call}")
        # Every one of these sites loads slot +0x68 through the local adapter's
        # vtable, rather than through a CDevG5KB receiver.
        receiver_offset = RECEIVER_STACK_OFFSETS[call_va]
        receiver_stack = f"[esp+0x{receiver_offset:x}]"
        if call_va in SPECIAL_VPTR_SETUP:
            if any(asm not in pre_call for asm in SPECIAL_VPTR_SETUP[call_va]):
                raise RuntimeError(f"call 0x{call_va:08X} no longer follows its constructor-established virtual-call setup")
        elif call_va in ALTERNATE_CALL_REGISTERS:
            if "mov edx,dword ptr [esp+0x28]" not in pre_call or "mov eax,dword ptr [edx+0x68]" not in pre_call or f"lea ecx,{receiver_stack}" not in pre_call:
                raise RuntimeError(f"call 0x{call_va:08X} no longer loads the constructed adapter vptr and its +0x68 slot")
        elif f"mov eax,dword ptr {receiver_stack}" not in pre_call or "mov edx,dword ptr [eax+0x68]" not in pre_call or f"lea ecx,{receiver_stack}" not in pre_call:
            raise RuntimeError(f"call 0x{call_va:08X} no longer loads the local adapter receiver and its +0x68 slot")

        rows.append({
            "call_va": f"0x{call_va:08X}",
            "indirect_method_offset": "+0x68",
            "receiver_constructor_va": "0x0047105C",
            "receiver_vtable_va": "0x0059F314",
            "slot_target_va": "0x0047111A",
            "stack_push_count": str(len(pushes)),
            "literal_argument": pushed_id,
            "resolved_import": "USER32!DrawTextW (IAT VA 0x0059E6B8)",
            "adapter_return": "ret 0x10",
            "concrete_g5_wrapper_ret": "ret 8",
            "immediate_stack_adjust_after_call": str(immediate_adjust).lower(),
            "receiver_type": "local GDI text adapter",
            "assessment": "resolved DrawTextW layout call; not a CDevG5KB/GetRealData dispatch",
        })

    push_8134_count = sum(1 for _, asm in instructions if asm == "push 0x8134")
    push_8135_count = sum(1 for _, asm in instructions if asm == "push 0x8135")
    if push_8134_count != 62 or push_8135_count != 13:
        raise RuntimeError(f"literal-push counts changed: 0x8134={push_8134_count}, 0x8135={push_8135_count}")

    fields = list(rows[0])
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
    out = args.out.open("w", newline="", encoding="utf-8") if args.out else sys.stdout
    try:
        writer = csv.DictWriter(out, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    finally:
        if args.out:
            out.close()
    print(f"Resolved {len(rows)} +0x68 sites to USER32!DrawTextW; decoded push counts: 0x8134={push_8134_count}, 0x8135={push_8135_count}.", file=sys.stderr)
    print("These bounded UI calls are not GetRealData callers; the actual command-0x88 caller remains unresolved.", file=sys.stderr)
    return 0


def disassemble_range(binary: Path, objdump: str, start: int, stop: int) -> list[tuple[int, str]]:
    result = subprocess.run(
        [objdump, "-d", "-Mintel", f"--start-address=0x{start:x}", f"--stop-address=0x{stop:x}", str(binary)],
        check=True,
        capture_output=True,
        text=True,
        errors="replace",
    )
    parsed: list[tuple[int, str]] = []
    for line in result.stdout.splitlines():
        match = ENTRY_RE.match(line)
        if match:
            parsed.append((int(match.group(1), 16), " ".join(match.group(3).lower().split())))
    return parsed


if __name__ == "__main__":
    raise SystemExit(run())
