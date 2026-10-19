#!/usr/bin/env python3
"""Reproduce the static registry-key recursive-delete evidence for RK Hub 4.6.

This script reads a caller-supplied, hash-pinned PE32 image and emits only a
small instruction ledger for the registry traversal, wrapper, resolver, and
caller path discussed in docs/rk-v4.6-registry-recursive-delete-followup-2026-10-20.md.
It never executes the target or accesses a registry/device.

Requires pefile and Capstone 5.x. Example:
  python scripts/audit_rk46_registry_recursive_delete.py \
    .research/rk46-extract-full/app/DeviceDriver.exe \
    --output docs/rk-v4.6-registry-recursive-delete-edge-ledger-2026-10-20.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from pathlib import Path

import capstone
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM


EXPECTED_SIZE = 2_418_176
EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
IMAGE_BASE = 0x00400000


# VA -> static relationship justified in the companion report.
FACTS = {
    0x004ACF15: ("recursive-open", "Loads inherited registry-view flags from the wrapper."),
    0x004ACF18: ("recursive-open", "ORs 0x2001f into the requested RegOpenKeyExW access mask."),
    0x004ACF3C: ("recursive-open", "Calls the wrapper that opens this path beneath the parent HKEY."),
    0x004ACF65: ("enumeration", "Loads the RegEnumKeyExW IAT address into EBX."),
    0x004ACF6D: ("recursive-edge", "Selects the returned child-name buffer as the recursive path."),
    0x004ACF7F: ("recursive-edge", "Tests recursive status; nonzero child status exits without deleting the parent."),
    0x004ACF81: ("recursive-edge", "Branches to cleanup on any nonzero child status."),
    0x004ACF83: ("enumeration", "Begins the next index-zero enumeration pass after a child was deleted."),
    0x004ACF8A: ("enumeration", "Passes null optional enumeration outputs."),
    0x004ACF8B: ("enumeration", "Passes null optional enumeration outputs."),
    0x004ACF8C: ("enumeration", "Passes null reserved/class-related enumeration outputs."),
    0x004ACF9B: ("enumeration", "Passes child index zero."),
    0x004ACF9C: ("enumeration", "Passes the currently opened subkey HKEY."),
    0x004ACF7A: ("recursive-edge", "Direct self-call: recurse on the child name using the newly opened child-key wrapper."),
    0x004ACFA2: ("enumeration", "Resets the child-name capacity to 0x100 WCHARs for each enumeration attempt."),
    0x004ACFAC: ("enumeration", "Calls RegEnumKeyExW through EBX; index and optional outputs are zero/null."),
    0x004ACFAE: ("enumeration", "Tests the RegEnumKeyExW status."),
    0x004ACFB0: ("enumeration", "Status zero processes the returned child; any nonzero status takes the delete path."),
    0x004ACFB8: ("cleanup-delete", "Closes the currently opened subkey wrapper before deleting its name from the parent."),
    0x004ACFC5: ("cleanup-delete", "Calls the dynamic RegDeleteKeyExW resolver/fallback with the original path."),
    0x004ACFD0: ("cleanup-delete", "Saves delete status before wrapper cleanup; cleanup is idempotent."),
    0x004AC9FB: ("resolver", "Resolver entry: caches one lookup of RegDeleteKeyExW."),
    0x004ACA11: ("resolver", "Calls GetModuleHandleW with the UTF-16 string Advapi32.dll."),
    0x004ACA21: ("resolver", "Calls GetProcAddress with the ASCII string RegDeleteKeyExW."),
    0x004ACA3C: ("resolver-arguments", "Pushes reserved=0 for the RegDeleteKeyExW signature."),
    0x004ACA3E: ("resolver-arguments", "Pushes the wrapper's registry-view flags as samDesired."),
    0x004ACA41: ("resolver-arguments", "Pushes the original subkey path."),
    0x004ACA44: ("resolver-arguments", "Pushes the parent HKEY."),
    0x004ACA46: ("resolver", "Invokes the cached RegDeleteKeyExW pointer with reserved=0."),
    0x004ACA4A: ("fallback-arguments", "Pushes the original subkey path for RegDeleteKeyW."),
    0x004ACA4D: ("fallback-arguments", "Pushes the parent HKEY for RegDeleteKeyW."),
    0x004ACA4F: ("resolver", "Fallback imported RegDeleteKeyW(hKey, subKey)."),
    0x004367A3: ("open-wrapper", "Imported RegOpenKeyExW call inside the HKEY wrapper."),
    0x004367E7: ("close-wrapper", "Tests the wrapper HKEY before closing."),
    0x004367EC: ("close-wrapper", "Calls RegCloseKey for a non-null wrapper HKEY."),
    0x004367F2: ("close-wrapper", "Clears the stored HKEY after RegCloseKey."),
    0x004367F8: ("close-wrapper", "Clears stored registry-view flags; later cleanup with a null HKEY is a no-op."),
    0x004AD28B: ("caller-method", "CSettingsStore-associated method entry from the existing static audit."),
    0x004AD2C4: ("caller-method", "Calls the recursive key helper with the caller-supplied path."),
    0x004AD2CE: ("caller-method", "Normalizes the helper's zero/nonzero LSTATUS into true/false."),
}


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    columns = [
        "binary_sha256",
        "va",
        "bytes",
        "mnemonic",
        "operands",
        "direct_target_va",
        "iat_symbol",
        "relationship",
        "static_note",
        "coverage_limit",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Extracted DeviceDriver.exe")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/rk-v4.6-registry-recursive-delete-edge-ledger-2026-10-20.csv"),
        help="CSV output path",
    )
    args = parser.parse_args()

    data = args.image.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        print(
            f"Refusing unexpected target: size={len(data)} sha256={digest}; "
            f"expected size={EXPECTED_SIZE} sha256={EXPECTED_SHA256}",
            file=sys.stderr,
        )
        return 2

    pe = pefile.PE(data=data, fast_load=False)
    if pe.FILE_HEADER.Machine != 0x014C or pe.OPTIONAL_HEADER.Magic != 0x010B:
        print("Refusing unexpected architecture; expected x86 PE32", file=sys.stderr)
        return 2
    if int(pe.OPTIONAL_HEADER.ImageBase) != IMAGE_BASE:
        print("Refusing unexpected preferred image base", file=sys.stderr)
        return 2

    imports = {}
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = descriptor.dll.decode("ascii", errors="replace")
        for imp in descriptor.imports:
            symbol = imp.name.decode("ascii", errors="replace") if imp.name else f"ordinal_{imp.ordinal}"
            imports[int(imp.address)] = f"{dll}!{symbol}"
    expected_imports = {
        0x005A6000: "ADVAPI32.dll!RegOpenKeyExW",
        0x005A6020: "ADVAPI32.dll!RegEnumKeyExW",
        0x005A6024: "ADVAPI32.dll!RegCloseKey",
        0x005A6030: "ADVAPI32.dll!RegDeleteKeyW",
        0x005A63FC: "KERNEL32.dll!GetProcAddress",
        0x005A6420: "KERNEL32.dll!GetModuleHandleW",
    }
    for iat, expected in expected_imports.items():
        if imports.get(iat) != expected:
            print(f"Unexpected import at 0x{iat:08x}: {imports.get(iat)!r}; expected {expected!r}", file=sys.stderr)
            return 2

    def va_bytes(va: int, count: int) -> bytes:
        return pe.get_data(va - IMAGE_BASE, count)

    if not va_bytes(0x005ACE00, 16).startswith(b"RegDeleteKeyExW\0"):
        print("RegDeleteKeyExW resolver string did not match", file=sys.stderr)
        return 2
    if not va_bytes(0x005ACE10, 30).startswith("Advapi32.dll\0".encode("utf-16le")):
        print("Advapi32.dll resolver string did not match", file=sys.stderr)
        return 2

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    md.skipdata = True
    instructions = {}
    for section in pe.sections:
        if not (int(section.Characteristics) & 0x20000000):
            continue
        start = IMAGE_BASE + int(section.VirtualAddress)
        for insn in md.disasm(section.get_data(), start):
            instructions[int(insn.address)] = insn

    # Make sure the two important function entries and all recorded sites are
    # actual decoded instruction boundaries in this linear sweep.
    required = set(FACTS) | {0x004ACEF8}
    missing = sorted(required - instructions.keys())
    if missing:
        print("Required sites were not decoded: " + ", ".join(hex(x) for x in missing), file=sys.stderr)
        return 2

    expected_calls = {
        0x004ACF3C: 0x00436780,
        0x004ACF7A: 0x004ACEF8,
        0x004ACFB8: 0x004367E0,
        0x004ACFC5: 0x004AC9FB,
        0x004AD2C4: 0x004ACEF8,
    }
    for site, expected_target in expected_calls.items():
        insn = instructions[site]
        actual_target = None
        if insn.mnemonic == "call" and insn.operands and insn.operands[0].type == X86_OP_IMM:
            actual_target = int(insn.operands[0].imm) & 0xFFFFFFFF
        if actual_target != expected_target:
            print(
                f"Unexpected call at 0x{site:08x}: {actual_target!r}; expected 0x{expected_target:08x}",
                file=sys.stderr,
            )
            return 2

    # Static direct-call xrefs to the relevant method/helper are emitted too,
    # so the caller chain can be reproduced without asserting reachability.
    xref_facts = {
        0x004AD28B: ("xref-to-caller-method", "Direct call candidate to the settings-store method."),
        0x004ACEF8: ("xref-to-recursive-helper", "Direct call candidate to recursive helper, including self-recursion."),
    }
    selected: dict[int, tuple[str, str]] = dict(FACTS)
    for site, insn in instructions.items():
        if insn.mnemonic != "call" or not insn.operands or insn.operands[0].type != X86_OP_IMM:
            continue
        target = int(insn.operands[0].imm) & 0xFFFFFFFF
        if target in xref_facts:
            if site in selected:
                relation, note = selected[site]
                selected[site] = (relation, note + " " + xref_facts[target][1])
            else:
                selected[site] = xref_facts[target]

    rows = []
    for site in sorted(selected):
        insn = instructions[site]
        direct_target = ""
        if insn.mnemonic in {"call", "jmp"} and insn.operands and insn.operands[0].type == X86_OP_IMM:
            direct_target = f"0x{int(insn.operands[0].imm) & 0xFFFFFFFF:08x}"
        iat_symbol = ""
        for operand in insn.operands:
            if operand.type == capstone.x86.X86_OP_MEM and operand.mem.base == 0 and operand.mem.index == 0:
                iat_symbol = imports.get(int(operand.mem.disp) & 0xFFFFFFFF, "")
                if iat_symbol:
                    break
        relation, note = selected[site]
        rows.append(
            {
                "binary_sha256": digest,
                "va": f"0x{site:08x}",
                "bytes": " ".join(f"{b:02X}" for b in insn.bytes),
                "mnemonic": insn.mnemonic,
                "operands": insn.op_str,
                "direct_target_va": direct_target,
                "iat_symbol": iat_symbol,
                "relationship": relation,
                "static_note": note,
                "coverage_limit": "Linear-sweep decoded candidate; no full CFG, runtime reachability, caller string, or registry state is asserted.",
            }
        )

    write_csv(args.output, rows)
    print(f"input_sha256={digest}")
    print(f"input_size={len(data)}")
    print(f"capstone={capstone.__version__}")
    print(f"rows={len(rows)}")
    print(f"output={args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
