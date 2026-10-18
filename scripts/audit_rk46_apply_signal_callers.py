#!/usr/bin/env python3
"""Verify and export the 4.6 deferred-settings signal helper callsites.

The verifier reads the hash-pinned PE and GNU objdump output only. It never
launches the RK program, opens a device, sends a report, or touches firmware.
The caller notes are conservative local code observations; they do not prove
that the caller belongs to CDevRKKB or that the worker ran on hardware.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import shutil
import subprocess
from pathlib import Path

import pefile


EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
IMAGE_BASE = 0x00400000
SIGNAL_HELPER_VA = 0x00401100
QUEUE_PUSH_VA = 0x0043E6C0
SEMAPHORE_IAT_VA = 0x005A64A4

LINE_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}\s+)+)"
    r"\s*([a-zA-Z][a-zA-Z0-9.]*)\s*(.*?)\s*$"
)

# The mask expression is the value at the callsite. The helper clears bit
# 0x8000 before queueing it. Context notes report only nearby static effects.
CALLERS = [
    (0x004033D5, "0x00000002", "global 0x0062A234 != 0", "Follows call 0x00403EF0; no model-specific field or action name proven at this edge."),
    (0x00403876, "EBX (dynamic)", "global 0x0062A234 != 0", "Follows call 0x0045CFF0; caller later reloads its stack arguments. Meaning of EBX unresolved."),
    (0x0040399F, "0x00000002", "global 0x0062A234 != EBX", "Follows call 0x00403EF0; caller compares a global and local value before signaling."),
    (0x0040B2BF, "0x00000001", "global 0x0062A234 != 0", "Follows call 0x0040B840; exact UI control and modified payload remain unresolved."),
    (0x0041D043, "0x00000002", "global 0x0062A234 != 0", "Path stages data around a 16-byte record from global 0x00630870 before signaling; semantic field names unresolved."),
    (0x0041D073, "0x00000002", "global 0x0062A234 != 0", "Immediately follows a byte write to object offset +0x5EBF; field meaning unresolved."),
    (0x0041E53A, "0x00000001", "global 0x0062A234 != 0", "Follows call 0x004491E0 and a store of 0x0F at object offset +0x30; field meaning unresolved."),
    (0x0041EA16, "0x00000002", "global 0x0062A234 != 0", "Follows call 0x0045FBE0; exact operation and model gate unresolved."),
    (0x0041ED5A, "0x00000001", "global 0x0062A234 != 0", "Follows call 0x00418890; later calls 0x00460DA0. User-facing control unresolved."),
    (0x0041F19A, "0x00000001", "global 0x0062A234 != 0", "Follows call 0x00418890; later calls 0x00460DA0. User-facing control unresolved."),
    (0x00424104, "0x00000002", "global 0x0062A234 != 0", "After a list scan that skips entry index 0x1E; later calls 0x00460DA0. Data meaning unresolved."),
    (0x00424415, "EBP (dynamic; OR 0x4 on one branch)", "global 0x0062A234 != 0", "Nearby code writes a shifted bit to object offset +0x45A4 and waits 100 ms; EBP base meaning unresolved."),
    (0x00424546, "0x00000022", "global 0x0062A234 != 0", "Follows a write of zero to object offset +0x2B60 and call 0x00427530; per-entry path excludes index 0x1E."),
    (0x00424637, "0x00000004", "global 0x0062A234 != 0", "Sets a shifted bit in object offset +0x45A4 using bit position at +0x45A0; later calls 0x00460DA0."),
    (0x00424786, "0x00000004", "global 0x0062A234 != 0", "Sets a shifted bit in object offset +0x45A4 using bit position at +0x45A0; follows call 0x00427530."),
    (0x00426B04, "ESI (dynamic)", "global 0x0062A234 != 0", "After a list scan that skips entry index 0x1E; ESI is caller-derived and its mask meaning is unresolved."),
    (0x0042726A, "0x00000002", "global 0x0062A234 != 0", "Follows writes to global 0x0062047C and object offset +0x423C, call 0x00427400, and a 100 ms wait."),
    (0x0045A00A, "0x00000006", "global 0x0062A234 != 0", "Object offset +0x4238 changes 1->0, a 100 ms wait occurs, then it changes back to 1."),
    (0x0045CF30, "0x00000006", "global 0x0062A234 != ESI", "Path compares object offset +0x423C and may update the bit field at +0x45A4; later calls 0x00460DA0."),
    (0x0045DC67, "0x00000002", "global 0x0062A234 != 0", "Follows calls 0x0045DC90 and 0x0045F660; later calls 0x00460DA0."),
    (0x0045DE57, "0x00000002", "global 0x0062A234 != 0", "Follows a write to object offset +0x5D90 and call 0x0045F350; later calls 0x00460DA0."),
    (0x0045E000, "0x00000002", "global 0x0062A234 != 0", "Follows a list traversal and call 0x0045F660; later calls 0x00460DA0."),
    (0x0045F323, "0x00000002", "global 0x0062A234 != 0", "Sets object offset +0xA8 to 1 and calls 0x0045F660; later calls 0x00460DA0."),
    (0x00474833, "0x00000002", "global 0x0062A234 != EDI", "Nearby code conditionally writes a byte at object offset +0x5D83; exact state meaning unresolved."),
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def disassemble(binary: Path, objdump: str) -> dict[int, dict[str, str]]:
    completed = subprocess.run(
        [objdump, "-d", str(binary)],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    instructions: dict[int, dict[str, str]] = {}
    for line in completed.stdout.splitlines():
        match = LINE_RE.match(line)
        if not match:
            continue
        instructions[int(match.group(1), 16)] = {
            "bytes": bytes.fromhex(match.group(2)).hex(" ").upper(),
            "mnemonic": match.group(3).lower(),
            "operand": match.group(4).strip().lower(),
            "source": line.strip(),
        }
    return instructions


def require_va_bytes(pe: pefile.PE, data: bytes, va: int, expected: bytes, label: str) -> None:
    offset = pe.get_offset_from_rva(va - int(pe.OPTIONAL_HEADER.ImageBase))
    actual = data[offset : offset + len(expected)]
    if actual != expected:
        raise SystemExit(f"{label} mismatch at 0x{va:08X}: got {actual.hex(' ')}")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--driver",
        type=Path,
        default=root.parent / ".research" / "rk4_6_official_extract_20261015" / "app" / "DeviceDriver.exe",
    )
    parser.add_argument("--output", type=Path, default=root / "docs" / "rk-v4.6-apply-signal-callers.csv")
    parser.add_argument("--objdump", default="objdump", help="GNU objdump executable (default: objdump on PATH)")
    args = parser.parse_args()

    binary = args.driver.resolve()
    objdump = shutil.which(args.objdump) or (args.objdump if Path(args.objdump).exists() else None)
    if not binary.is_file():
        parser.error(f"driver does not exist: {binary}")
    if not objdump:
        parser.error(f"GNU objdump not found: {args.objdump}")
    digest = sha256(binary)
    if digest != EXPECTED_SHA256:
        parser.error(f"SHA-256 mismatch: expected {EXPECTED_SHA256}, got {digest}")

    data = binary.read_bytes()
    pe = pefile.PE(data=data, fast_load=False)
    if int(pe.OPTIONAL_HEADER.ImageBase) != IMAGE_BASE or int(pe.FILE_HEADER.Machine) != 0x14C:
        parser.error("expected the hash-pinned 32-bit x86 image at base 0x00400000")

    # Confirm the helper's high-bit mask, enqueue, and semaphore wakeup from PE bytes.
    require_va_bytes(pe, data, SIGNAL_HELPER_VA, bytes.fromhex("81 64 24 04 ff 7f ff ff"), "signal-helper mask clear")
    require_va_bytes(pe, data, 0x00401112, bytes.fromhex("e8 a9 d5 03 00"), "signal-helper queue call")
    require_va_bytes(pe, data, 0x00401122, bytes.fromhex("ff 15 a4 64 5a 00"), "signal-helper ReleaseSemaphore call")
    require_va_bytes(pe, data, 0x0045DF36, bytes.fromhex("e8 85 07 fe ff"), "inline queue producer")
    require_va_bytes(pe, data, 0x0045DF45, bytes.fromhex("ff 15 a4 64 5a 00"), "inline ReleaseSemaphore call")

    instructions = disassemble(binary, str(objdump))
    ordered_vas = sorted(instructions)
    previous_by_va = {
        va: instructions[ordered_vas[index - 1]]
        for index, va in enumerate(ordered_vas)
        if index > 0
    }
    found = {
        va: ins
        for va, ins in instructions.items()
        if ins["mnemonic"] == "call" and ins["operand"] == "0x401100"
    }
    expected = {va for va, *_ in CALLERS}
    if set(found) != expected:
        missing = sorted(expected - set(found))
        unexpected = sorted(set(found) - expected)
        raise SystemExit(f"callsite set mismatch; missing={[hex(v) for v in missing]}, unexpected={[hex(v) for v in unexpected]}")

    rows = []
    for va, arg, gate, note in CALLERS:
        ins = found[va]
        encoded = bytes.fromhex(ins["bytes"])
        if len(encoded) != 5 or encoded[0] != 0xE8:
            raise SystemExit(f"not a direct rel32 call at 0x{va:08X}: {ins['source']}")
        target = va + 5 + int.from_bytes(encoded[1:], "little", signed=True)
        if target != SIGNAL_HELPER_VA:
            raise SystemExit(f"call at 0x{va:08X} resolves to 0x{target:08X}, not helper")
        previous = previous_by_va.get(va)
        expected_push = {
            "0x00000001": "$0x1",
            "0x00000002": "$0x2",
            "0x00000004": "$0x4",
            "0x00000006": "$0x6",
            "0x00000022": "$0x22",
            "EBX (dynamic)": "%ebx",
            "EBP (dynamic; OR 0x4 on one branch)": "%ebp",
            "ESI (dynamic)": "%esi",
        }[arg]
        if not previous or previous["mnemonic"] != "push" or previous["operand"] != expected_push:
            detail = previous["source"] if previous else "no preceding decoded instruction"
            raise SystemExit(f"argument-push mismatch at 0x{va:08X}; expected {expected_push}, got {detail}")
        rows.append(
            {
                "callsite_va": f"0x{va:08X}",
                "signal_helper_va": f"0x{SIGNAL_HELPER_VA:08X}",
                "argument_expression": arg,
                "queued_value": "argument & 0xFFFF7FFF",
                "nearby_gate": gate,
                "nearby_static_effect": note,
                "call_instruction": ins["source"],
                "evidence_level": "direct call proven; semantic label not proven",
                "scope_limit": "GNU objdump x86 linear sweep; caller edge is not CFG reachability and receiver is not proven CDevRKKB",
            }
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    print(f"verified {digest}; found exactly {len(rows)} direct helper callsites")
    print("also verified inline queue producer 0x0045DF36 and ReleaseSemaphore at 0x0045DF45")
    print(f"wrote {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
