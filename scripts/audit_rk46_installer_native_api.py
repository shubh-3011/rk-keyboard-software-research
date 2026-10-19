#!/usr/bin/env python3
"""Hash-pinned import/callsite and direct-syscall boundary scan for RK 4.6 setup."""

from __future__ import annotations

import argparse
import hashlib
import sys
from collections import Counter
from pathlib import Path

import pefile


EXPECTED_SHA256 = "47a1fc21c3af548b93fa40d499584abecb3341e62b15948ae537b78ca987aad8"
PATTERNS = {
    "syscall": bytes((0x0F, 0x05)),
    "sysenter": bytes((0x0F, 0x34)),
    "int_2e": bytes((0xCD, 0x2E)),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "binary",
        nargs="?",
        type=Path,
        default=repo.parent / ".research" / "RK_Keyboard_Software_Setup_V4.6_20261015.exe",
    )
    parser.add_argument(
        "output",
        nargs="?",
        type=Path,
        default=repo / "docs" / "rk-v4.6-installer-native-api-call-sites.csv",
    )
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()

    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"installer does not exist: {binary}")
    actual_hash = sha256(binary)
    if actual_hash != EXPECTED_SHA256:
        parser.error(f"SHA-256 mismatch: expected {EXPECTED_SHA256}, got {actual_hash}")

    # Reuse the established transfer decoder while imposing this installer's
    # own SHA-256 pin before parsing it.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import audit_rk46_import_call_sites as transfer_scan

    pe = pefile.PE(str(binary), fast_load=False)
    if pe.FILE_HEADER.Machine != 0x14C:
        parser.error(f"expected 32-bit x86 PE (0x014c), found 0x{pe.FILE_HEADER.Machine:04x}")
    imports = transfer_scan.collect_imports(pe)
    instructions = transfer_scan.disassemble(binary, args.objdump)
    sites, thunks = transfer_scan.collect_sites(
        imports, instructions, int(pe.OPTIONAL_HEADER.ImageBase)
    )
    transfer_scan.write_csv(args.output.resolve(), imports, sites, int(pe.OPTIONAL_HEADER.ImageBase))

    raw = binary.read_bytes()
    raw_candidates: list[tuple[str, int, int, str]] = []
    executable_sections = []
    for section in pe.sections:
        if not (section.Characteristics & 0x20000000):
            continue
        name = section.Name.rstrip(b"\0").decode("ascii", errors="replace")
        start = int(section.PointerToRawData)
        end = start + int(section.SizeOfRawData)
        base = int(pe.OPTIONAL_HEADER.ImageBase) + int(section.VirtualAddress)
        executable_sections.append((name, int(section.SizeOfRawData)))
        section_bytes = raw[start:end]
        for label, pattern in PATTERNS.items():
            offset = 0
            while True:
                offset = section_bytes.find(pattern, offset)
                if offset < 0:
                    break
                candidate_va = base + offset
                containing = next(
                    (
                        instruction
                        for instruction in instructions
                        if int(instruction["va"]) <= candidate_va
                        < int(instruction["va"]) + len(instruction["bytes"])
                    ),
                    None,
                )
                classification = (
                    f"inside {containing['source_line'].strip()}"
                    if containing
                    else "not covered by the GNU objdump linear-sweep record"
                )
                raw_candidates.append((label, candidate_va, start + offset, classification))
                offset += 1

    import_symbols = [str(row["symbol"]) for row in imports]
    native_named_imports = [
        f"{row['dll']}!{row['symbol']}"
        for row in imports
        if str(row["dll"]).lower() == "ntdll.dll"
        or str(row["symbol"]).startswith(("Nt", "Zw"))
    ]
    syscall_instructions = [
        instruction
        for instruction in instructions
        if instruction["mnemonic"] in {"syscall", "sysenter"}
        or (
            instruction["mnemonic"] == "int"
            and "2e" in str(instruction["operand"]).lower()
        )
    ]
    site_counts = Counter(
        site["site_kind"] for per_import in sites.values() for site in per_import
    )

    print(f"binary={binary}")
    print(f"sha256={actual_hash}")
    print(f"size_bytes={binary.stat().st_size}")
    print(f"machine=0x{pe.FILE_HEADER.Machine:04x}")
    print(f"entrypoint_va=0x{int(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint):08x}")
    print(f"ordinary_import_rows={sum(1 for row in imports if row['import_kind'] == 'ordinary')}")
    print(f"delay_import_rows={sum(1 for row in imports if row['import_kind'] == 'delay')}")
    print("executable_sections=" + ", ".join(f"{name}:{size}" for name, size in executable_sections))
    print(f"decoded_instruction_records={len(instructions)}")
    print("transfer_sites=" + ", ".join(f"{key}:{value}" for key, value in sorted(site_counts.items())))
    print(f"imports_without_decoded_transfer={sum(1 for row in imports if int(row['iat_va']) not in sites)}")
    print(f"unique_import_symbols={len(set(import_symbols))}")
    print(f"native_named_imports={native_named_imports}")
    print(f"direct_syscall_instruction_records={len(syscall_instructions)}")
    print("raw_syscall_opcode_candidates=" + repr(raw_candidates))
    print(f"iat_jump_thunks={len(thunks)}")
    print(f"csv={args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
