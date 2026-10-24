#!/usr/bin/env python3
"""Verify the RK 4.6 device-report -> text-macro -> host SendInput path.

Static PE bytes only. The checker does not execute the target, open a device,
or send input. It pins the selected worker, report decoder, private-message,
macro lookup, and SendInput callsite edges to one exact image.
"""

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

# Exact instruction bytes, phase, and the bounded fact they support.
FACTS = {
    0x00448870: ("b868d25d00", "mfc-map", "Message-map accessor returns the COemDrvDlg descriptor selected in the existing map ledger."),
    0x00448875: ("c3", "mfc-map", "Message-map accessor returns."),
    0x0040DC63: ("8b3db0645a00", "3632-thread-start", "Loads the CreateEventW import address."),
    0x0040DCA3: ("68d0d74000", "3632-thread-start", "Pushes worker entry 0x0040D7D0."),
    0x0040DCB7: ("ff1568645a00", "3632-thread-start", "Calls imported CreateThread."),
    0x0040D7D0: ("83ec64", "3632-read-worker", "Worker entry allocates its local frame."),
    0x0040D808: ("8b8f7c020000", "3632-read-worker", "Reads the object's event handle at +0x27C."),
    0x0040D80E: ("8b2d70645a00", "3632-read-worker", "Loads the ReadFile import address."),
    0x0040D814: ("8b1d9c645a00", "3632-read-worker", "Loads the WaitForMultipleObjects import address."),
    0x0040D874: ("6a14", "3632-read-worker", "Passes a 0x14-byte read length."),
    0x0040D881: ("ffd5", "3632-read-worker", "Calls ReadFile through the loaded import pointer."),
    0x0040D883: ("85c0", "3632-read-worker", "Tests the ReadFile result."),
    0x0040D885: ("740b", "3632-read-worker", "Only the nonzero-result fallthrough reaches report parsing."),
    0x0040D88B: ("e800010000", "3632-read-worker", "Calls packet decoder 0x0040D990."),
    0x0040D990: ("807e010a", "3632-report-decoder", "Requires packet byte +1 to equal 0x0A."),
    0x0040D9C9: ("8b872c020000", "3632-report-decoder", "Loads the object's target-window holder at +0x22C."),
    0x0040D9E4: ("80f908", "3632-report-decoder", "Selects the report branch when packet byte +5 equals 8."),
    0x0040D9D7: ("ff1548675a00", "3632-report-decoder", "Calls IsWindow for the nested HWND."),
    0x0040DA0D: ("83c808", "3632-report-decoder", "Sets the low byte of packed WPARAM to 8."),
    0x0040DA2D: ("6a00", "3632-report-decoder", "Pushes lParam zero for PostMessageW."),
    0x0040DA2F: ("50", "3632-report-decoder", "Pushes the packed report fields as WPARAM."),
    0x0040DA30: ("8b4220", "3632-report-decoder", "Loads HWND from nested object +0x20."),
    0x0040DA33: ("68eb070000", "3632-report-decoder", "Pushes private message value 0x07EB."),
    0x0040DA39: ("ff153c675a00", "3632-report-decoder", "Calls imported PostMessageW."),
    0x0040F6EB: ("6840f14000", "g5-thread-start", "Pushes G5 worker entry 0x0040F140."),
    0x0040F6FF: ("ffd7", "g5-thread-start", "Calls CreateThread through its loaded import pointer."),
    0x0040F140: ("83ec68", "g5-read-worker", "G5 worker entry allocates its local frame."),
    0x0040F189: ("8b1d70645a00", "g5-read-worker", "Loads the ReadFile import address."),
    0x0040F18F: ("8b2d9c645a00", "g5-read-worker", "Loads the WaitForMultipleObjects import address."),
    0x0040F209: ("6a08", "g5-read-worker", "Passes an 8-byte read length."),
    0x0040F211: ("ffd3", "g5-read-worker", "Calls ReadFile through the loaded import pointer."),
    0x0040F213: ("85c0", "g5-read-worker", "Tests the ReadFile result."),
    0x0040F215: ("740b", "g5-read-worker", "Only the nonzero-result fallthrough reaches report parsing."),
    0x0040F21B: ("e800010000", "g5-read-worker", "Calls packet decoder 0x0040F320."),
    0x0040F332: ("807e010a", "g5-report-decoder", "Requires packet byte +1 to equal 0x0A."),
    0x0040F33C: ("807e0206", "g5-report-decoder", "Separates packet type 6 from the later type-8 route."),
    0x0040F351: ("8b872c020000", "g5-report-decoder", "Loads the object's target-window holder at +0x22C."),
    0x0040F35F: ("ff1548675a00", "g5-report-decoder", "Calls IsWindow for the nested HWND."),
    0x0040F36C: ("80f908", "g5-report-decoder", "Selects the report branch when packet byte +2 equals 8."),
    0x0040F398: ("83c808", "g5-report-decoder", "Sets the low byte of packed WPARAM to 8."),
    0x0040F3C1: ("6a00", "g5-report-decoder", "Pushes lParam zero for PostMessageW."),
    0x0040F3C3: ("50", "g5-report-decoder", "Pushes the packed report fields as WPARAM."),
    0x0040F3C4: ("8b4220", "g5-report-decoder", "Loads HWND from nested object +0x20."),
    0x0040F3C7: ("68eb070000", "g5-report-decoder", "Pushes private message value 0x07EB."),
    0x0040F3CD: ("ff153c675a00", "g5-report-decoder", "Calls imported PostMessageW."),
    0x0044AFF0: ("55", "dlg-message-handler", "MFC message handler 0x0044AFF0 begins."),
    0x0044AFF9: ("8b550c", "dlg-message-handler", "Loads the second explicit message argument."),
    0x0044AFFD: ("8b5d08", "dlg-message-handler", "Loads WPARAM into EBX."),
    0x0044B113: ("83ff08", "dlg-message-handler", "Branches on WPARAM low byte 8."),
    0x0044B11C: ("8b7c2410", "dlg-message-handler", "Loads saved WPARAM bits 8..15 as a profile-table index."),
    0x0044B120: ("8bf3", "dlg-message-handler", "Copies WPARAM for extracting category bits."),
    0x0044B122: ("c1ee10", "dlg-message-handler", "Extracts WPARAM bits 16..31."),
    0x0044B125: ("c1eb18", "dlg-message-handler", "Extracts WPARAM bits 24..31 as category."),
    0x0044B143: ("0f84b2010000", "dlg-message-handler", "Rejects a null profile-table base."),
    0x0044B151: ("85ff", "dlg-message-handler", "Checks the profile-table index before use."),
    0x0044B159: ("3b3de89e6200", "dlg-message-handler", "Bounds the index against global 0x00629EE8."),
    0x0044B165: ("83fb03", "dlg-message-handler", "Requires category at most 3."),
    0x0044B16E: ("69db84000000", "dlg-message-handler", "Scales category by 0x84 table entries."),
    0x0044B174: ("03df", "dlg-message-handler", "Adds the selected table index."),
    0x0044B176: ("c1e304", "dlg-message-handler", "Scales selected table entry by 0x10 bytes."),
    0x0044B179: ("8b740338", "dlg-message-handler", "Reads selected cell dword at +0x38."),
    0x0044B17D: ("0fb67c033b", "dlg-message-handler", "Reads selected cell byte at +0x3B."),
    0x0044B182: ("8d5c0338", "dlg-message-handler", "Forms pointer to selected cell +0x38."),
    0x0044B186: ("81e6ffffff00", "dlg-message-handler", "Masks selected cell dword to its low 24 bits."),
    0x0044B19C: ("83ff0a", "dlg-message-handler", "Requires selected cell byte +0x3B to equal 0x0A."),
    0x0044B1A5: ("83fe5b", "dlg-message-handler", "Requires selected cell low 24-bit value to equal 0x5B."),
    0x0044B1AE: ("8b5308", "dlg-message-handler", "Reads the macro record key at selected cell +0x40."),
    0x0044B1B1: ("6a00", "dlg-message-handler", "Uses non-allocating mode for macro-record lookup."),
    0x0044B1B3: ("e8c842fdff", "dlg-message-handler", "Looks up the record using helper 0x0041F480."),
    0x0044B1B8: ("85c0", "dlg-message-handler", "Tests whether the record lookup found a result."),
    0x0044B1BC: ("83c004", "dlg-message-handler", "Selects the UTF-16 text at record +4."),
    0x0044B1BF: ("e8bcd40000", "dlg-message-handler", "Passes record text to helper 0x00458680."),
    0x0041F480: ("83ec14", "record-lookup", "Macro lookup helper begins."),
    0x0041F484: ("85d2", "record-lookup", "Uses EDX as the lookup key."),
    0x0041F48A: ("b9c4d36000", "record-lookup", "Scans the fixed macro table at 0x0060D3C4."),
    0x0041F494: ("81c104040000", "record-lookup", "Advances by 0x404 bytes per record."),
    0x0041F4A3: ("837c241c00", "record-lookup", "Checks the stack allocation flag; zero keeps playback lookup non-allocating."),
    0x00458680: ("83ec10", "sendinput-helper", "Host text-input helper begins."),
    0x00458684: ("8bf0", "sendinput-helper", "Takes text pointer from EAX."),
    0x004586BC: ("68000e0000", "sendinput-helper", "Allocates a 0xE00-byte input-record buffer."),
    0x0045877A: ("ff15dc665a00", "sendinput-helper", "Calls imported USER32!SendInput."),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    require(len(data) == EXPECTED_SIZE and digest == EXPECTED_SHA256, "input size/SHA-256 mismatch")
    pe = pefile.PE(data=data)
    base = pe.OPTIONAL_HEADER.ImageBase
    require(base == 0x00400000 and pe.FILE_HEADER.Machine == 0x14C, "expected x86 PE at preferred base")
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)

    def read(va: int, size: int) -> bytes:
        offset = pe.get_offset_from_rva(va - base)
        result = data[offset:offset + size]
        require(len(result) == size, f"unavailable bytes at 0x{va:08X}")
        return result

    imports = {entry.address: entry.name.decode("ascii") for group in pe.DIRECTORY_ENTRY_IMPORT
               for entry in group.imports if entry.name}
    for address, name in ((0x5A6468, "CreateThread"), (0x5A6470, "ReadFile"),
                          (0x5A649C, "WaitForMultipleObjects"), (0x5A673C, "PostMessageW"),
                          (0x5A6748, "IsWindow"), (0x5A66DC, "SendInput")):
        require(imports.get(address) == name, f"IAT mismatch: {name}")

    require(struct.unpack("<I", read(0x5D2470, 4))[0] == 0x40DC60,
            "CDev3632 worker-start vtable slot changed")
    require(struct.unpack("<I", read(0x5D3D18, 4))[0] == 0x40F670,
            "CDevG5KB worker-start vtable slot changed")
    require(read(0x448870, 6) == bytes.fromhex("b868d25d00c3"),
            "COemDrvDlg MFC map accessor changed")
    expected_map_row = (0x07EB, 0, 0, 0, 0x0E, 0x0044AFF0)
    require(struct.unpack("<6I", read(0x5DD1C0, 24)) == expected_map_row,
            "COemDrvDlg message 0x07EB map row changed")

    root = Path(__file__).resolve().parents[1]
    map_csv = root / "docs" / "rk-v4.6-mfc-message-map-entries.csv"
    with map_csv.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = [row for row in csv.DictReader(stream) if row.get("entry_va") == "0x005DD1C0"]
    require(len(rows) == 1, "expected one existing MFC ledger row at 0x005DD1C0")
    row = rows[0]
    require((row["accessor_va"], row["rtti_vtable_types"], row["message_hex"], row["handler_va"])
            == ("0x00448870", ".?AVCOemDrvDlg@@", "0x07EB", "0x0044AFF0"),
            "existing MFC owner ledger disagrees with pinned map row")

    evidence = []
    for va, (expected_hex, phase, observation) in FACTS.items():
        expected = bytes.fromhex(expected_hex)
        actual = read(va, len(expected))
        require(actual == expected, f"instruction bytes changed at 0x{va:08X}")
        insn = next(decoder.disasm(read(va, 15), va, count=1), None)
        require(insn is not None and insn.size == len(expected),
                f"expected a complete instruction at 0x{va:08X}")
        evidence.append({"binary_sha256": digest, "va": f"0x{va:08X}", "bytes": actual.hex().upper(),
                         "instruction": f"{insn.mnemonic} {insn.op_str}".strip(), "phase": phase,
                         "observation": observation,
                         "scope": "static exact instruction; execution and device behavior unobserved"})

    evidence.append({"binary_sha256": digest, "va": "0x005DD1C0",
                     "bytes": read(0x5DD1C0, 24).hex().upper(), "instruction": "",
                     "phase": "mfc-map-row",
                     "observation": "COemDrvDlg message 0x07EB -> 0x0044AFF0; six DWORD row verified against PE and existing RTTI ledger",
                     "scope": "static data row; Windows message delivery unobserved"})

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(evidence[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(evidence)
    print(f"Verified {len(FACTS)} instruction guards, both device-worker senders, the COemDrvDlg map row, macro lookup, and SendInput import.")
    print("Static only: message delivery, report meaning, active profile, key gesture, and SendInput success remain unobserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
