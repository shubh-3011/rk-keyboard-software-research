#!/usr/bin/env python3
"""Verify two bounded HidD_GetFeature consumers in the S98 01BF updater."""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path

import pefile

EXPECTED_SHA256 = "475e8d7b97adfbd861c3b7b16721ad598df04095b81228e381319b6be23129e6"
EXPECTED_SIZE = 2_140_176
EXPECTED_TEXT_SHA256 = "3643f4d710a296b62598d3d8b71c7dd9dcab049ebbb540588b11757ccd5f03ed"
THAI_EXPECTED_SHA256 = "399020b7b66fda67cc6c69ae81336d67024204cbc9e15ffabde26a2cccd072ca"
THAI_EXPECTED_TEXT_SHA256 = "bfc4506d668ee1ff8809a0455abd5f589545e45ff1d0b358a5fe3d4871e85ff2"
IMAGE_BASE = 0x00400000

FACTS: dict[int, tuple[str, str]] = {
    0x004029F7: ("c70305520000", "Builds update-verification feature request prefix 05 52."),
    0x00402A03: ("ff15e0a15500", "Calls HidD_SetFeature through IAT slot 0x0055A1E0."),
    0x00402A5C: ("6802080000", "Allocates a 0x802-byte response buffer."),
    0x00402A78: ("66c7030672", "Builds response prefix 06 72 in the feature buffer."),
    0x00402AFD: ("ff15c8a15500", "Calls HidD_GetFeature through IAT slot 0x0055A1C8."),
    0x00402B79: ("8b0dfce35b00", "Reads the host image payload length from global 0x005BE3FC."),
    0x00402B88: ("be00080000", "Sets the compare chunk size to 0x800 bytes."),
    0x00402B95: ("a1f8e35b00", "Loads the host image payload pointer from global 0x005BE3F8."),
    0x00402BC0: ("8b01", "Loads a DWORD from the read response comparison buffer."),
    0x00402BC2: ("3b02", "Compares each response DWORD with the host image bytes."),
    0x00402C09: ("81c700080000", "Advances the host-image offset by 0x800 per loop."),
    0x0040265F: ("e84c030000", "Calls the verifier helper at 0x004029B0."),
    0x0040266F: ("83f80a", "Bounds verifier retries at ten attempts."),
    0x00402672: ("7cdd", "Branches back to retry while the count is below ten."),
    0x00409205: ("c7010552f0fc", "Builds the six-byte query request beginning 05 52 F0 FC."),
    0x0040920B: ("c6410404", "Sets query request byte +4 to 0x04."),
    0x00409218: ("ff15e0a15500", "Calls HidD_SetFeature for the six-byte query."),
    0x0040923F: ("66c7010572", "Changes the query buffer to response prefix 05 72."),
    0x0040924D: ("ff15c8a15500", "Calls HidD_GetFeature for the query response."),
    0x00409261: ("80790261", "Checks response byte +2 against 0x61."),
    0x00409275: ("0fb64105", "Reads response byte +5 into updater state selection logic."),
}

THAI_FACTS: dict[int, tuple[str, str]] = {
    0x00402857: ("c70305520000", "Thai counterpart builds the update-verification request; 01BF counterpart is 0x004029F7."),
    0x00402863: ("ff15e0a15500", "Thai counterpart calls HidD_SetFeature; 01BF counterpart is 0x00402A03."),
    0x004028D8: ("66c7030672", "Thai counterpart sets response prefix 06 72; 01BF counterpart is 0x00402A78."),
    0x0040295D: ("ff15c8a15500", "Thai counterpart calls HidD_GetFeature at helper offset +0x14D; 01BF counterpart is 0x00402AFD."),
    0x004029D9: ("8b0dfce35b00", "Thai verifier loads host-image payload length; 01BF counterpart is 0x00402B79."),
    0x00402A20: ("8b013b027510", "Thai verifier compares response data against host-image bytes; 01BF loop begins at 0x00402BC0."),
    0x00402A69: ("81c700080000", "Thai verifier advances host-image offset by 0x800; 01BF counterpart is 0x00402C09."),
    0x00409055: ("c7010552f0fc", "Thai counterpart builds the six-byte query beginning 05 52 F0 FC; 01BF counterpart is 0x00409205."),
    0x0040905B: ("c6410404", "Thai counterpart sets query byte +4 to 0x04; 01BF counterpart is 0x0040920B."),
    0x00409068: ("ff15e0a15500", "Thai counterpart calls HidD_SetFeature for the six-byte query; 01BF counterpart is 0x00409218."),
    0x0040908F: ("66c7010572", "Thai counterpart sets query response prefix 05 72; 01BF counterpart is 0x0040923F."),
    0x0040909D: ("ff15c8a15500", "Thai counterpart calls HidD_GetFeature at query offset +0xCA; 01BF counterpart is 0x0040924D."),
    0x004090B1: ("80790261", "Thai counterpart checks response byte +2 against 0x61; 01BF counterpart is 0x00409261."),
    0x004090C5: ("0fb64105", "Thai counterpart reads response byte +5 into state selection logic; 01BF counterpart is 0x00409275."),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--thai-binary", type=Path,
                        help="optional hash-pinned Thai PID 0x0223 build for counterpart verification")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        raise SystemExit("input size/SHA-256 mismatch")
    pe = pefile.PE(data=data)
    if pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE or pe.FILE_HEADER.Machine != 0x14C:
        raise SystemExit("expected x86 PE at preferred base")
    text = next((section.get_data() for section in pe.sections
                 if section.Name.rstrip(b"\0") == b".text"), None)
    if text is None or hashlib.sha256(text).hexdigest() != EXPECTED_TEXT_SHA256:
        raise SystemExit(".text SHA-256 mismatch")
    iat = {entry.address: (library.dll.decode(errors="replace").upper(),
                           entry.name.decode(errors="replace") if entry.name else "")
           for library in pe.DIRECTORY_ENTRY_IMPORT for entry in library.imports}
    expected_imports = {0x0055A1E0: ("HID.DLL", "HidD_SetFeature"),
                        0x0055A1C8: ("HID.DLL", "HidD_GetFeature")}
    for slot, expected in expected_imports.items():
        if iat.get(slot) != expected:
            raise SystemExit(f"unexpected IAT mapping at 0x{slot:08X}: {iat.get(slot)!r}")

    def raw(va: int, size: int) -> bytes:
        offset = pe.get_offset_from_rva(va - IMAGE_BASE)
        return data[offset:offset + size]

    rows = []
    for va, (expected_hex, note) in FACTS.items():
        expected = bytes.fromhex(expected_hex)
        actual = raw(va, len(expected))
        if actual != expected:
            raise SystemExit(f"0x{va:08X}: expected {expected.hex()}, got {actual.hex()}")
        rows.append({"binary_sha256": digest, "evidence_va": f"0x{va:08X}",
                     "bytes": actual.hex().upper(), "observation": note,
                     "scope": "static bytes only; updater/device execution and HID results unobserved"})
    for slot, (_, name) in expected_imports.items():
        rows.append({"binary_sha256": digest, "evidence_va": f"0x{slot:08X}", "bytes": "",
                     "observation": f"IAT slot resolves to HID.DLL!{name}.",
                     "scope": "static import table; runtime API call and return unobserved"})

    thai_text_sha256 = None
    if args.thai_binary:
        thai_data = args.thai_binary.read_bytes()
        thai_digest = hashlib.sha256(thai_data).hexdigest()
        if len(thai_data) != EXPECTED_SIZE or thai_digest != THAI_EXPECTED_SHA256:
            raise SystemExit("Thai package size/SHA-256 mismatch")
        thai_pe = pefile.PE(data=thai_data)
        if thai_pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE or thai_pe.FILE_HEADER.Machine != 0x14C:
            raise SystemExit("expected Thai x86 PE at preferred base")
        thai_text = next((section.get_data() for section in thai_pe.sections
                          if section.Name.rstrip(b"\0") == b".text"), None)
        if thai_text is None or hashlib.sha256(thai_text).hexdigest() != THAI_EXPECTED_TEXT_SHA256:
            raise SystemExit("Thai .text SHA-256 mismatch")
        thai_iat = {entry.address: (library.dll.decode(errors="replace").upper(),
                                    entry.name.decode(errors="replace") if entry.name else "")
                    for library in thai_pe.DIRECTORY_ENTRY_IMPORT for entry in library.imports}
        for slot, expected in expected_imports.items():
            if thai_iat.get(slot) != expected:
                raise SystemExit(f"unexpected Thai IAT mapping at 0x{slot:08X}: {thai_iat.get(slot)!r}")

        def thai_raw(va: int, size: int) -> bytes:
            offset = thai_pe.get_offset_from_rva(va - IMAGE_BASE)
            return thai_data[offset:offset + size]

        for va, (expected_hex, note) in THAI_FACTS.items():
            expected = bytes.fromhex(expected_hex)
            actual = thai_raw(va, len(expected))
            if actual != expected:
                raise SystemExit(f"Thai 0x{va:08X}: expected {expected.hex()}, got {actual.hex()}")
            rows.append({"binary_sha256": thai_digest, "evidence_va": f"0x{va:08X}",
                         "bytes": actual.hex().upper(), "observation": note,
                         "scope": "static bytes only; Thai updater/device execution and HID results unobserved"})
        for slot, (_, name) in expected_imports.items():
            rows.append({"binary_sha256": thai_digest, "evidence_va": f"0x{slot:08X}", "bytes": "",
                         "observation": f"Thai IAT slot resolves to HID.DLL!{name}.",
                         "scope": "static import table; runtime API call and return unobserved"})
        thai_text_sha256 = THAI_EXPECTED_TEXT_SHA256
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("binary_sha256", "evidence_va", "bytes", "observation", "scope"))
        writer.writeheader()
        writer.writerows(rows)
    thai_summary = (f", plus {len(THAI_FACTS)} Thai counterpart facts and Thai .text hash {thai_text_sha256}"
                    if args.thai_binary else "")
    print(f"Verified {len(FACTS)} 01BF instruction facts, .text hash, and HID feature imports{thai_summary}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
