#!/usr/bin/env python3
"""Inventory 4.6 DeviceDriver.exe imports and instruction-boundary callsites.

This is a static parser around pefile and GNU objdump. It never launches the
input executable and performs no device I/O. The binary hash pin prevents a
same-named file from silently changing the address evidence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import pefile


EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
LINE_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}\s+)+)"
    r"\s*([a-zA-Z][a-zA-Z0-9.]*)\s*(.*?)\s*$"
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def decode_import_name(item) -> str:
    if item.name:
        return item.name.decode("ascii", errors="replace")
    return f"ordinal:{item.ordinal}"


def collect_imports(pe: pefile.PE) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for kind, descriptors in (
        ("ordinary", getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])),
        ("delay", getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", [])),
    ):
        for descriptor in descriptors:
            dll = descriptor.dll.decode("ascii", errors="replace")
            for item in descriptor.imports:
                va = int(item.address)
                rows.append(
                    {
                        "import_kind": kind,
                        "dll": dll,
                        "symbol": decode_import_name(item),
                        "iat_va": va,
                        "iat_rva": va - int(pe.OPTIONAL_HEADER.ImageBase),
                    }
                )
    return rows


def disassemble(path: Path, objdump: str) -> list[dict[str, object]]:
    """Run objdump's x86 linear sweep and retain parsed instruction records."""
    proc = subprocess.Popen(
        [objdump, "-d", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.stdout is not None
    instructions: list[dict[str, object]] = []
    for line in proc.stdout:
        match = LINE_RE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        encoded = bytes.fromhex(match.group(2))
        mnemonic = match.group(3).lower()
        operand = match.group(4).strip()
        instructions.append(
            {
                "va": address,
                "bytes": encoded,
                "mnemonic": mnemonic,
                "operand": operand,
                "source_line": line.rstrip("\r\n"),
            }
        )
    stderr = proc.stderr.read() if proc.stderr else ""
    code = proc.wait()
    if code:
        raise RuntimeError(f"objdump exited with {code}: {stderr[-2000:]}")
    return instructions


def collect_sites(imports: list[dict[str, object]], instructions: list[dict[str, object]], image_base: int):
    by_iat = {int(row["iat_va"]): row for row in imports}
    thunks: dict[int, set[int]] = defaultdict(set)
    direct: dict[int, list[dict[str, object]]] = defaultdict(list)

    # Only accept objdump-decoded instructions whose exact x86 encoding agrees
    # with their printed mnemonic and operand shape.
    for ins in instructions:
        raw = ins["bytes"]
        va = int(ins["va"])
        mnemonic = str(ins["mnemonic"])
        operand = str(ins["operand"])
        if len(raw) == 6 and raw[:2] in (b"\xff\x15", b"\xff\x25"):
            target_iat = int.from_bytes(raw[2:6], "little")
            row = by_iat.get(target_iat)
            expected = "call" if raw[:2] == b"\xff\x15" else "jmp"
            if row and mnemonic == expected and operand.startswith("*"):
                kind = "call_iat" if expected == "call" else "jmp_iat"
                direct[target_iat].append(
                    {"site_kind": kind, "site_va": va, "thunk_va": "", "instruction": raw.hex(" ").upper(), "decoded": ins["source_line"]}
                )
                if expected == "jmp":
                    thunks[target_iat].add(va)

    # Relative CALL rel32 instructions to already validated import veneers.
    for ins in instructions:
        raw = ins["bytes"]
        if len(raw) != 5 or raw[0] != 0xE8 or ins["mnemonic"] != "call":
            continue
        site_va = int(ins["va"])
        target = site_va + 5 + int.from_bytes(raw[1:5], "little", signed=True)
        for iat_va, thunk_vas in thunks.items():
            if target in thunk_vas:
                direct[iat_va].append(
                    {"site_kind": "call_thunk", "site_va": site_va, "thunk_va": target, "instruction": raw.hex(" ").upper(), "decoded": ins["source_line"]}
                )

    # Recover the common compiler pattern `mov reg,[absolute IAT] ... call reg`
    # within one decoded basic block. This is supplemental to the requested
    # direct-IAT/thunk classes; it avoids claiming that unreferenced IAT rows
    # are unused when the code first copies the IAT pointer into a register.
    reg_names = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
    byte_alias_to_reg = {
        "al": "eax", "ah": "eax", "ax": "eax",
        "cl": "ecx", "ch": "ecx", "cx": "ecx",
        "dl": "edx", "dh": "edx", "dx": "edx",
        "bl": "ebx", "bh": "ebx", "bx": "ebx",
        "spl": "esp", "sp": "esp", "bpl": "ebp", "bp": "ebp",
        "sil": "esi", "si": "esi", "dil": "edi", "di": "edi",
    }
    tainted: dict[str, int] = {}
    conditional_or_terminal = {
        "ret", "retf", "iret", "iretd", "jmp", "ljmp", "loop", "loope", "loopne", "jecxz", "jcxz",
    }
    for ins in instructions:
        raw = ins["bytes"]
        va = int(ins["va"])
        mnemonic = str(ins["mnemonic"])
        operand = str(ins["operand"])
        loaded_reg = None
        loaded_iat = None

        # MOV EAX,moffs32 or MOV r32, moffs-equivalent absolute [disp32].
        if len(raw) == 5 and raw[0] == 0xA1:
            loaded_reg = "eax"
            loaded_iat = int.from_bytes(raw[1:5], "little")
        elif len(raw) == 6 and raw[0] == 0x8B and (raw[1] & 0xC7) == 0x05:
            loaded_reg = reg_names[(raw[1] >> 3) & 7]
            loaded_iat = int.from_bytes(raw[2:6], "little")

        if loaded_reg is not None and loaded_iat in by_iat and mnemonic == "mov":
            tainted[loaded_reg] = loaded_iat
            continue

        # CALL/JMP r32 encodings are FF D0..D7 / FF E0..E7.
        if len(raw) == 2 and raw[0] == 0xFF and raw[1] >= 0xD0:
            reg_id = raw[1] & 7
            extension = (raw[1] >> 3) & 7
            reg = reg_names[reg_id]
            if extension in (2, 4) and reg in tainted:
                iat = tainted[reg]
                direct[iat].append(
                    {
                        "site_kind": "call_iat_register" if extension == 2 else "jmp_iat_register",
                        "site_va": va,
                        "thunk_va": "",
                        "instruction": raw.hex(" ").upper(),
                        "decoded": ins["source_line"],
                    }
                )
                # Windows x86 ABI preserves EBX/EBP/ESI/EDI across calls.
                # Keep those IAT values live for repeated calls in the same
                # straight-line block; volatile registers are discarded.
                if reg not in {"ebx", "ebp", "esi", "edi"}:
                    tainted.pop(reg, None)
                continue

        # Do not follow a guessed pointer through branch/call boundaries.
        if mnemonic in conditional_or_terminal or mnemonic.startswith("j") or mnemonic.startswith("call"):
            tainted.clear()
            continue

        # Kill register aliases when the last AT&T operand is an explicit
        # register destination; this covers the normal MOV/LEA/arithmetic
        # forms used by MSVC at these callsites.
        last_operand = operand.split(",")[-1].strip().lstrip("*")
        if last_operand.startswith("%"):
            name = last_operand[1:].lower()
            reg = name if name in reg_names else byte_alias_to_reg.get(name)
            if reg:
                tainted.pop(reg, None)
        if mnemonic in {"pop", "inc", "dec", "neg", "not", "bswap"} and operand.startswith("%"):
            name = operand[1:].lower()
            reg = name if name in reg_names else byte_alias_to_reg.get(name)
            if reg:
                tainted.pop(reg, None)
    return direct, thunks


CSV_FIELDS = [
    "import_kind",
    "dll",
    "symbol",
    "iat_rva",
    "iat_va",
    "site_kind",
    "site_va",
    "matching_thunk_va",
    "instruction_bytes",
    "objdump_decoded_instruction",
    "validation_scope",
]


def write_csv(output: Path, imports, sites, image_base: int):
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for imp in imports:
            iat = int(imp["iat_va"])
            found = sorted(sites.get(iat, []), key=lambda item: (int(item["site_va"]), str(item["site_kind"])))
            rows = found or [{"site_kind": "none_decoded", "site_va": "", "thunk_va": "", "instruction": "", "decoded": ""}]
            for site in rows:
                writer.writerow(
                    {
                        "import_kind": imp["import_kind"],
                        "dll": imp["dll"],
                        "symbol": imp["symbol"],
                        "iat_rva": f"0x{int(imp['iat_rva']):08X}",
                        "iat_va": f"0x{iat:08X}",
                        "site_kind": site["site_kind"],
                        "site_va": f"0x{int(site['site_va']):08X}" if site["site_va"] != "" else "",
                        "matching_thunk_va": f"0x{int(site['thunk_va']):08X}" if site["thunk_va"] != "" else "",
                        "instruction_bytes": site["instruction"],
                        "objdump_decoded_instruction": site["decoded"],
                        "validation_scope": (
                            "GNU objdump x86 linear-sweep boundary; same-straight-line-block IAT-register heuristic; not CFG reachability"
                            if site["site_kind"] in {"call_iat_register", "jmp_iat_register"}
                            else "GNU objdump x86 linear-sweep boundary and exact IAT/thunk encoding; not CFG reachability"
                        ),
                    }
                )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Path to the extracted 4.6 DeviceDriver.exe")
    parser.add_argument("output", type=Path, help="Output CSV path")
    parser.add_argument("--objdump", default="objdump", help="GNU objdump executable (default: objdump on PATH)")
    parser.add_argument("--allow-hash-mismatch", action="store_true", help="Permit a different hash, clearly weakening reproducibility")
    args = parser.parse_args()

    binary = args.binary.resolve()
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
    sites, thunks = collect_sites(imports, instructions, int(pe.OPTIONAL_HEADER.ImageBase))
    write_csv(args.output, imports, sites, int(pe.OPTIONAL_HEADER.ImageBase))

    kinds = defaultdict(int)
    for by_import in sites.values():
        for site in by_import:
            kinds[site["site_kind"]] += 1
    print(f"binary={binary}")
    print(f"sha256={actual_hash}")
    print(f"ordinary_imports={sum(1 for row in imports if row['import_kind'] == 'ordinary')}")
    print(f"delay_imports={sum(1 for row in imports if row['import_kind'] == 'delay')}")
    print(f"decoded_instruction_lines={len(instructions)}")
    print(f"thunk_slots={len(thunks)}")
    print("site_counts=" + ",".join(f"{kind}:{count}" for kind, count in sorted(kinds.items())))
    print(f"imports_with_no_decoded_sites={sum(1 for row in imports if int(row['iat_va']) not in sites)}")
    print(f"csv={args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
