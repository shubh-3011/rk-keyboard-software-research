#!/usr/bin/env python3
"""Inventory 4.06 DeviceDriver.exe register-indirect import transfers.

This hash-pinned static scan records decoded `mov reg,[IAT]` loads and later
`call reg`/`jmp reg` sites in the same branch-free instruction region. It does
not execute the vendor binary, prove CFG reachability, or establish runtime
behavior. Run from the repository root:

    python scripts/audit_rk406_register_indirect_calls.py \
        "C:\\Program Files (x86)\\RK Keyboard Software\\DeviceDriver.exe" \
        docs/rk-406-register-indirect-call-candidates.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import shutil
from pathlib import Path

import pefile

from audit_rk46_import_call_sites import collect_imports, collect_sites, disassemble


EXPECTED_SHA256 = "c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6"
REG_NAMES = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
NONVOLATILE = {"ebx", "ebp", "esi", "edi"}
BYTE_ALIAS_TO_REG = {
    "al": "eax", "ah": "eax", "ax": "eax",
    "cl": "ecx", "ch": "ecx", "cx": "ecx",
    "dl": "edx", "dh": "edx", "dx": "edx",
    "bl": "ebx", "bh": "ebx", "bx": "ebx",
    "spl": "esp", "sp": "esp", "bpl": "ebp", "bp": "ebp",
    "sil": "esi", "si": "esi", "dil": "edi", "di": "edi",
}
BRANCH_OR_TERMINAL = {
    "ret", "retf", "iret", "iretd", "jmp", "ljmp", "loop", "loope",
    "loopne", "jecxz", "jcxz",
}

CSV_FIELDS = [
    "import_kind",
    "dll",
    "symbol",
    "iat_rva",
    "iat_va",
    "baseline_direct_or_thunk_site_present",
    "transfer_kind",
    "iat_load_va",
    "iat_load_instruction",
    "transfer_va",
    "register",
    "transfer_instruction",
    "validation_scope",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def collect_register_transfers(imports, instructions):
    """Track exact absolute IAT loads until a register call or branch boundary."""
    by_iat = {int(row["iat_va"]): row for row in imports}
    tainted: dict[str, tuple[int, int, str]] = {}
    transfers: dict[int, list[dict[str, object]]] = {iat: [] for iat in by_iat}

    for ins in instructions:
        raw = ins["bytes"]
        va = int(ins["va"])
        mnemonic = str(ins["mnemonic"])
        operand = str(ins["operand"])
        loaded_reg = None
        loaded_iat = None

        # MOV EAX,moffs32 or MOV r32,[disp32] with no base/index register.
        if len(raw) == 5 and raw[0] == 0xA1:
            loaded_reg = "eax"
            loaded_iat = int.from_bytes(raw[1:5], "little")
        elif len(raw) == 6 and raw[0] == 0x8B and (raw[1] & 0xC7) == 0x05:
            loaded_reg = REG_NAMES[(raw[1] >> 3) & 7]
            loaded_iat = int.from_bytes(raw[2:6], "little")

        if loaded_reg is not None and loaded_iat in by_iat and mnemonic == "mov":
            tainted[loaded_reg] = (
                int(loaded_iat),
                va,
                str(ins["source_line"]).strip(),
            )
            continue

        # CALL/JMP r32 encodings are FF D0..D7 / FF E0..E7.
        if len(raw) == 2 and raw[0] == 0xFF and raw[1] >= 0xD0:
            reg = REG_NAMES[raw[1] & 7]
            extension = (raw[1] >> 3) & 7
            if extension in (2, 4) and reg in tainted:
                iat, load_va, load_text = tainted[reg]
                transfers[iat].append(
                    {
                        "transfer_kind": "call_iat_register" if extension == 2 else "jmp_iat_register",
                        "iat_load_va": load_va,
                        "iat_load_instruction": load_text,
                        "transfer_va": va,
                        "register": reg,
                        "transfer_instruction": str(ins["source_line"]).strip(),
                    }
                )
                if extension == 4:
                    tainted.clear()
                    continue
                # Match the shared scanner's heuristic: retain the IAT value
                # in nonvolatile registers for repeated calls; discard the
                # target value when the call uses a volatile register.
                if reg not in NONVOLATILE:
                    tainted.pop(reg, None)
                continue

        # Any branch or non-register call ends this conservative region.
        if mnemonic in BRANCH_OR_TERMINAL or mnemonic.startswith("j") or mnemonic.startswith("call"):
            tainted.clear()
            continue

        # Invalidate a tainted destination register on ordinary writes.
        last_operand = operand.split(",")[-1].strip().lstrip("*")
        if last_operand.startswith("%"):
            name = last_operand[1:].lower()
            reg = name if name in REG_NAMES else BYTE_ALIAS_TO_REG.get(name)
            if reg:
                tainted.pop(reg, None)
        if mnemonic in {"pop", "inc", "dec", "neg", "not", "bswap"} and operand.startswith("%"):
            name = operand[1:].lower()
            reg = name if name in REG_NAMES else BYTE_ALIAS_TO_REG.get(name)
            if reg:
                tainted.pop(reg, None)

    return transfers


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Path to the installed 4.06 DeviceDriver.exe")
    parser.add_argument("output", type=Path, help="Output CSV path")
    parser.add_argument("--objdump", default="objdump", help="GNU objdump executable")
    parser.add_argument("--allow-hash-mismatch", action="store_true")
    args = parser.parse_args()

    binary = args.binary.resolve()
    output = args.output.resolve()
    objdump = shutil.which(args.objdump) or (args.objdump if Path(args.objdump).exists() else None)
    if not binary.is_file():
        parser.error(f"binary does not exist: {binary}")
    if not objdump:
        parser.error(f"GNU objdump not found: {args.objdump}")
    actual_hash = sha256(binary)
    if actual_hash != EXPECTED_SHA256 and not args.allow_hash_mismatch:
        parser.error(f"SHA-256 mismatch: expected {EXPECTED_SHA256}, got {actual_hash}")

    pe = pefile.PE(str(binary), fast_load=False)
    if pe.FILE_HEADER.Machine != 0x14C:
        parser.error(f"expected 32-bit x86 PE (0x014c), found 0x{pe.FILE_HEADER.Machine:04x}")
    imports = collect_imports(pe)
    instructions = disassemble(binary, str(objdump))
    register_sites = collect_register_transfers(imports, instructions)
    baseline_sites, _ = collect_sites(imports, instructions, int(pe.OPTIONAL_HEADER.ImageBase))

    output.parent.mkdir(parents=True, exist_ok=True)
    candidate_total = 0
    covered_imports = 0
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for imp in imports:
            iat = int(imp["iat_va"])
            baseline = any(
                site["site_kind"] in {"call_iat", "call_thunk", "jmp_iat"}
                for site in baseline_sites.get(iat, [])
            )
            sites = sorted(
                register_sites[iat],
                key=lambda site: (int(site["transfer_va"]), str(site["transfer_kind"])),
            )
            if sites:
                covered_imports += int(baseline)
                candidate_total += len(sites)
            rows = sites or [None]
            for site in rows:
                writer.writerow(
                    {
                        "import_kind": imp["import_kind"],
                        "dll": imp["dll"],
                        "symbol": imp["symbol"],
                        "iat_rva": f"0x{int(imp['iat_rva']):08X}",
                        "iat_va": f"0x{iat:08X}",
                        "baseline_direct_or_thunk_site_present": str(baseline).lower(),
                        "transfer_kind": site["transfer_kind"] if site else "no_candidate_detected",
                        "iat_load_va": f"0x{int(site['iat_load_va']):08X}" if site else "",
                        "iat_load_instruction": site["iat_load_instruction"] if site else "",
                        "transfer_va": f"0x{int(site['transfer_va']):08X}" if site else "",
                        "register": site["register"] if site else "",
                        "transfer_instruction": site["transfer_instruction"] if site else "",
                        "validation_scope": (
                            "objdump x86 linear-sweep boundaries; same-region absolute IAT load followed by register transfer; shared scanner register-taint heuristic; not CFG reachability"
                            if site
                            else "No matching same-region transfer found by this heuristic; not proof of no use"
                        ),
                    }
                )

    baseline_candidates = sum(
        len(register_sites[iat])
        for iat, sites in register_sites.items()
        if sites and any(
            site["site_kind"] in {"call_iat", "call_thunk", "jmp_iat"}
            for site in baseline_sites.get(iat, [])
        )
    )
    print(f"binary={binary}")
    print(f"sha256={actual_hash}")
    print(f"imports={len(imports)}")
    print(f"decoded_instruction_lines={len(instructions)}")
    print(f"register_transfer_candidates={candidate_total}")
    print(f"candidates_for_imports_with_direct_or_thunk_sites={baseline_candidates}")
    print(f"covered_import_rows_with_register_candidates={covered_imports}")
    legacy_register_calls = sum(
        1
        for sites in baseline_sites.values()
        for site in sites
        if site["site_kind"] == "call_iat_register"
    )
    print(f"shared_scanner_register_call_candidates={legacy_register_calls}")
    print(f"csv={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
