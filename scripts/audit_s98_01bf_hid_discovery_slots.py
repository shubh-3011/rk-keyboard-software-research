#!/usr/bin/env python3
"""Verify the hash-pinned S98 01BF HID-discovery-to-slot trace.

This reads the updater PE as data and writes a CSV evidence ledger. It never
launches the updater, enumerates live HID devices, sends a report, or modifies
keyboard state.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import struct
import sys
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM

from audit_dialog_resources import parse_dialog


EXPECTED_SHA256 = "475e8d7b97adfbd861c3b7b16721ad598df04095b81228e381319b6be23129e6"
EXPECTED_SIZE = 2_140_176
EXPECTED_TEXT_SHA256 = "3643f4d710a296b62598d3d8b71c7dd9dcab049ebbb540588b11757ccd5f03ed"
IMAGE_BASE = 0x00400000
RESOURCE_DIALOG_ID = 102
RESOURCE_LANGUAGE_ID = 1028
MAP_DESCRIPTOR_VA = 0x0058DC1C
MAP_ENTRIES_VA = 0x0058DC28
ALL_START_MAP_ROW_VA = 0x0058DC88
ALL_START_MAP_ROW = (0x111, 0, 1, 1, 0x3A, 0x004096A0)

# Exact instruction starts in the hash-pinned 01BF image. These facts anchor
# direct discovery gates, path-record transfers, and the worker slot index.
FACTS: dict[int, tuple[str, str]] = {
    0x00407C66: ("a104e45b00", "Loads configured VendorID value from global 0x005BE404."),
    0x00407C78: ("8986288c0000", "Copies the configured VendorID value to dialog field +0x8C28."),
    0x00407C7E: ("a100e45b00", "Loads configured ProductID value from global 0x005BE400."),
    0x00407C95: ("8986248c0000", "Copies the configured ProductID value to dialog field +0x8C24."),
    0x004086F4: ("6820275c00", "Pushes the HID class-GUID output buffer at 0x005C2720."),
    0x004086F9: ("ff15d8a15500", "Calls HID.DLL!HidD_GetHidGuid through IAT 0x0055A1D8."),
    0x004086FF: ("6a12", "Pushes SetupDiGetClassDevsW flags 0x12: present and device-interface class flags."),
    0x00408708: ("ff15bca45500", "Calls SetupAPI!SetupDiGetClassDevsW through IAT 0x0055A4BC."),
    0x00408710: ("c745c81c000000", "Sets SP_DEVICE_INTERFACE_DATA.cbSize to 0x1C."),
    0x0040874F: ("ff15b8a45500", "Calls SetupAPI!SetupDiEnumDeviceInterfaces through IAT 0x0055A4B8."),
    0x00408763: ("8b3db0a45500", "Loads SetupDiGetDeviceInterfaceDetailW from IAT 0x0055A4B0."),
    0x004087A8: ("ffd7", "Calls SetupDiGetDeviceInterfaceDetailW for the current interface path."),
    0x004087BC: ("8d7304", "Uses the returned interface-detail path at the allocated detail record +4."),
    0x004087C0: ("ff155ca25500", "Calls CreateFileW for the candidate path."),
    0x004087DA: ("c745e40c000000", "Sets HID_ATTRIBUTES.Size to 12."),
    0x004087E3: ("ff15dca15500", "Calls HidD_GetAttributes on the opened candidate handle."),
    0x004087F1: ("ff15cca15500", "Calls HidD_GetPreparsedData on the opened candidate handle."),
    0x00408801: ("ff15d0a15500", "Calls HidP_GetCaps on the candidate preparsed data."),
    0x0040880D: ("ff15d4a15500", "Calls HidD_FreePreparsedData."),
    0x00408813: ("668b7dea", "Loads HID_ATTRIBUTES.ProductID (structure offset 6)."),
    0x00408819: ("668b5590", "Loads HIDP_CAPS.FeatureReportByteLength (structure offset 8)."),
    0x00408824: ("b903060000", "Loads the special-path VendorID constant 0x0603."),
    0x00408829: ("66394de8", "Compares HID_ATTRIBUTES.VendorID (offset 4) with 0x0603."),
    0x0040882F: ("663bbd50ffffff", "Compares ProductID with special-path constant 0x1020."),
    0x00408838: ("663b855cffffff", "Compares HIDP_CAPS.UsagePage with 0xFF00."),
    0x00408841: ("b802080000", "Loads the special-path feature-report length 0x0802."),
    0x00408849: ("0f849d010000", "Branches on FeatureReportByteLength == 0x0802."),
    0x0040884F: ("6683fa06", "Checks the alternative special-path FeatureReportByteLength == 6."),
    0x00408862: ("3981248c0000", "Compares candidate ProductID with the dialog's configured value at +0x8C24."),
    0x00408877: ("0fb745e8", "Loads candidate VendorID for the configured-ID comparison."),
    0x0040887B: ("3981288c0000", "Compares candidate VendorID with the dialog's configured value at +0x8C28."),
    0x0040888E: ("663b855cffffff", "The configured-ID branch also requires UsagePage == 0xFF00."),
    0x004088A5: ("6689873e8c0000", "Stores the matched descriptor VersionNumber at dialog +0x8C3E."),
    0x00408920: ("66c7070575", "The configured-ID branch builds feature report prefix 05 75."),
    0x00408931: ("ff15e0a15500", "The configured-ID branch calls HidD_SetFeature; this is an active report path."),
    0x004089B4: ("8bbd70ffffff", "For FeatureReportByteLength == 6, selects the path table rooted at dialog +0x6A9C."),
    0x004089EC: ("8bbd6cffffff", "For FeatureReportByteLength == 0x0802, selects the path table rooted at dialog +0x4A1C."),
    0x00408A16: ("ff4580", "The 0x0802 path branch increments its accepted-path count."),
    0x00408EE2: ("897d94", "Discovery-to-slot routine retains the current 0x0802 path-table entry."),
    0x004090D9: ("8145a408020000", "Advances the per-slot status/path index by the 0x208-byte record stride."),
    0x004090E4: ("83fe10", "Bounds the per-slot scan at 16 entries."),
    0x00409123: ("c68660e45b0001", "Marks the selected global worker slot populated before the feature-response qualification probe."),
    0x00409138: ("894598", "Retains the selected dialog slot row base (dialog + i*0x208)."),
    0x0040913B: ("051c090000", "Selects that row's primary path field at +0x91C."),
    0x00409150: ("0fb701", "Copies the primary UTF-16 interface path into the selected row."),
    0x00409166: ("81c180200000", "Selects the parallel path table 0x2080 bytes after the primary table."),
    0x00409176: ("6689840a9a290000", "Copies the paired UTF-16 path into the selected row field at +0x299C."),
    0x00409198: ("ff155ca25500", "Opens the selected row's primary interface path for the qualification probe."),
    0x004091D5: ("66837db800", "Rejects the selected interface if FeatureReportByteLength is zero."),
    0x004091E0: ("b806000000", "For the following probe, sets the local feature-report length to 6."),
    0x00409205: ("c7010552f0fc", "Builds the active 05 52 feature request bytes."),
    0x00409218: ("ff15e0a15500", "Sends the 05 52 request through HidD_SetFeature."),
    0x0040923F: ("66c7010572", "Builds the following 05 72 feature-read request."),
    0x0040924D: ("ff15c8a15500", "Calls HidD_GetFeature for the 05 72 request."),
    0x00409261: ("80790261", "Requires response byte +2 == 0x61 before setting the slot eligibility flag."),
    0x0040926E: ("c6824490000001", "Sets the dialog's current qualification-success byte at +0x9044."),
    0x00409275: ("0fb64105", "Reads the response classification byte at +5."),
    0x00409305: ("888471448e0000", "Copies qualification success to per-row byte +0x8E44 + 2*i."),
    0x00409312: ("888471458e0000", "Copies classification to per-row byte +0x8E45 + 2*i."),
    0x00409320: ("8d4601", "Formats the visible row ordinal as i+1."),
    0x00409337: ("8d8114010000", "Targets the corresponding per-row display string at row base +0x114."),
    0x00409349: ("80bc72448e000000", "Reads the per-row qualification-success byte."),
    0x00409353: ("0fb68472458e0000", "Reads the per-row classification byte."),
    0x004096BB: ("80be60e45b0000", "All Start gates on the global populated byte for slot i; it does not test dialog +0x8E44 here."),
    0x004096C9: ("833cb520e45b0000", "All Start requires the worker-state dword for the same index to be zero."),
    0x004096D5: ("83bbc490000000", "Before setup, All Start also requires dialog field +0x90C4 to be zero."),
    0x004096E1: ("e84a000000", "Eligible All Start row i calls per-slot setup 0x00409730 with index i."),
    0x004096E6: ("ff83c4900000", "After setup, increments dialog field +0x90C4; its reset/lifecycle is outside this trace."),
    0x00409755: ("69f31c040000", "Computes worker-record offset i*0x41C."),
    0x0040975B: ("c7049d20e45b0001000000", "Marks global worker state for the selected index as started."),
    0x0040976B: ("8d881c090000", "Selects the dialog row's primary path at +0x91C."),
    0x00409771: ("8d9680e45b00", "Selects worker-record primary path destination at 0x5BE480+i*0x41C."),
    0x00409793: ("8d9688e65b00", "Selects worker-record paired-path destination at 0x5BE688+i*0x41C."),
    0x00409799: ("81c19c290000", "Selects the same dialog row's paired path at +0x299C."),
    0x004097B1: ("889e90e85b00", "Stores the selected row index in the worker record."),
}

CALL_EDGES = {
    0x00407D15: 0x00408650,
    0x00407D25: 0x00408650,
    0x00407D65: 0x00408E80,
    0x00408AE4: 0x00408650,
    0x00408AF9: 0x00408650,
    0x00408B48: 0x00408650,
    0x004096E1: 0x00409730,
}

EXPECTED_IMPORTS = {
    0x0055A1D8: ("HID.DLL", "HidD_GetHidGuid"),
    0x0055A4BC: ("SETUPAPI.dll", "SetupDiGetClassDevsW"),
    0x0055A4B8: ("SETUPAPI.dll", "SetupDiEnumDeviceInterfaces"),
    0x0055A4B0: ("SETUPAPI.dll", "SetupDiGetDeviceInterfaceDetailW"),
    0x0055A4B4: ("SETUPAPI.dll", "SetupDiDestroyDeviceInfoList"),
    0x0055A25C: ("KERNEL32.dll", "CreateFileW"),
    0x0055A264: ("KERNEL32.dll", "CloseHandle"),
    0x0055A1DC: ("HID.DLL", "HidD_GetAttributes"),
    0x0055A1CC: ("HID.DLL", "HidD_GetPreparsedData"),
    0x0055A1D0: ("HID.DLL", "HidP_GetCaps"),
    0x0055A1D4: ("HID.DLL", "HidD_FreePreparsedData"),
    0x0055A1E0: ("HID.DLL", "HidD_SetFeature"),
    0x0055A1C8: ("HID.DLL", "HidD_GetFeature"),
}


def locate_dialog(pe: pefile.PE) -> tuple[int, bytes]:
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if resource_type.id != 5:  # RT_DIALOG
            continue
        for resource_name in resource_type.directory.entries:
            if resource_name.id != RESOURCE_DIALOG_ID:
                continue
            for language in resource_name.directory.entries:
                if language.id == RESOURCE_LANGUAGE_ID:
                    info = language.data.struct
                    return int(info.OffsetToData), pe.get_data(int(info.OffsetToData), int(info.Size))
    raise ValueError("RT_DIALOG #102 language 1028 was not found")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="hash-pinned S98 01BF updater PE")
    parser.add_argument("--out", type=Path, required=True, help="evidence CSV output")
    args = parser.parse_args()

    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        raise SystemExit(f"input size/SHA-256 mismatch: {len(data)} bytes, {digest}")
    pe = pefile.PE(data=data)
    if pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE or pe.FILE_HEADER.Machine != 0x14C:
        raise SystemExit("expected x86 PE32 image at preferred base 0x00400000")
    text_section = next((section for section in pe.sections if section.Name.rstrip(b"\0") == b".text"), None)
    if text_section is None or hashlib.sha256(text_section.get_data()).hexdigest() != EXPECTED_TEXT_SHA256:
        raise SystemExit(".text section hash mismatch")

    def raw_va(va: int, size: int) -> bytes:
        return data[pe.get_offset_from_rva(va - IMAGE_BASE):pe.get_offset_from_rva(va - IMAGE_BASE) + size]

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    rows: list[dict[str, str]] = []

    def add(evidence_va: str, byte_text: str, observation: str, status: str = "confirmed static fact") -> None:
        rows.append({
            "binary_sha256": digest,
            "evidence_va": evidence_va,
            "bytes": byte_text,
            "observation": observation,
            "claim_status": status,
        })

    for va, (expected_hex, observation) in FACTS.items():
        expected = bytes.fromhex(expected_hex)
        actual = raw_va(va, len(expected))
        if actual != expected:
            raise SystemExit(f"instruction-byte mismatch at 0x{va:08X}: {actual.hex()} != {expected.hex()}")
        add(f"0x{va:08X}", actual.hex().upper(), observation)

    for callsite, target in CALL_EDGES.items():
        instruction = next(decoder.disasm(raw_va(callsite, 5), callsite, count=1), None)
        if (instruction is None or instruction.mnemonic != "call" or len(instruction.operands) != 1
                or instruction.operands[0].type != X86_OP_IMM or instruction.operands[0].imm != target):
            raise SystemExit(f"direct-call target mismatch at 0x{callsite:08X}")
        add(f"0x{callsite:08X}", raw_va(callsite, instruction.size).hex().upper(),
            f"Direct call to 0x{target:08X}.")

    imports = {
        entry.address: (library.dll.decode(errors="replace"), entry.name.decode(errors="replace") if entry.name else "")
        for library in pe.DIRECTORY_ENTRY_IMPORT
        for entry in library.imports
    }
    for slot, expected in EXPECTED_IMPORTS.items():
        if imports.get(slot) != expected:
            raise SystemExit(f"IAT mismatch at 0x{slot:08X}: {imports.get(slot)!r} != {expected!r}")
        add(f"IAT 0x{slot:08X}", "", f"IAT resolves to {expected[0]}!{expected[1]}.")

    descriptor = struct.unpack_from("<2I", data, pe.get_offset_from_rva(MAP_DESCRIPTOR_VA - IMAGE_BASE))
    map_row = struct.unpack_from("<6I", data, pe.get_offset_from_rva(ALL_START_MAP_ROW_VA - IMAGE_BASE))
    if descriptor != (0x00415EB6, MAP_ENTRIES_VA) or map_row != ALL_START_MAP_ROW:
        raise SystemExit("All Start MFC map descriptor/row mismatch")
    add(f"0x{MAP_DESCRIPTOR_VA:08X}", raw_va(MAP_DESCRIPTOR_VA, 8).hex().upper(),
        f"MFC message map uses entry array at 0x{MAP_ENTRIES_VA:08X}.")
    add(f"0x{ALL_START_MAP_ROW_VA:08X}", raw_va(ALL_START_MAP_ROW_VA, 24).hex().upper(),
        "WM_COMMAND ID 1 (All Start) is mapped to handler 0x004096A0.")

    resource_rva, resource = locate_dialog(pe)
    dialog = parse_dialog(resource)
    if dialog["title"] != "Update Tool" or dialog["item_count"] != 40:
        raise SystemExit("Update Tool dialog resource metadata mismatch")
    start_controls = [control for control in dialog["controls"] if control["id"] == 1]
    if (len(start_controls) != 1 or start_controls[0]["class"] != "BUTTON"
            or start_controls[0]["caption"] != "全部開始"):
        raise SystemExit("All Start resource control mismatch")
    slot_controls = {
        int(control["id"]): (control["class"], control["caption"])
        for control in dialog["controls"]
        if isinstance(control["id"], int) and 0x3E8 <= control["id"] <= 0x3F7
    }
    expected_controls = {0x3E8 + index: ("STATIC", str(index + 1)) for index in range(16)}
    if slot_controls != expected_controls:
        raise SystemExit(f"resource slot captions mismatch: {slot_controls!r}")
    add(f"RT_DIALOG #102 RVA 0x{resource_rva:08X}", "",
        "Dialog title is Update Tool; control ID 1 is the 全部開始 button; 16 STATIC controls ID 0x3E8–0x3F7 are captioned 1–16.",
        "confirmed resource fact; direct HWND binding remains unproven")

    # Data-flow relation anchors: the 16-slot source stride, paired-array
    # distance, worker stride, and All Start eligibility / idle-state checks.
    add("derived from 0x004090D9/0x00409166/0x00409755", "",
        "Observed slot strides are 0x208 bytes in dialog path storage, 0x2080 bytes between the two 16-entry path tables, and 0x41C bytes in worker records.")
    add("derived from 0x00409261/0x00409305/0x004096BB", "",
        "Conditional path: response byte +2 == 0x61 sets current success and it is copied to per-row +0x8E44+2*i. All Start gates instead test global populated byte 0x5BE460[i], idle state 0x5BE420[i], and dialog +0x90C4 == 0; response success is not one of those gates.")
    handler_bytes = raw_va(0x004096A0, 0x004096FA - 0x004096A0)
    handler_text = " ".join(insn.op_str.lower() for insn in decoder.disasm(handler_bytes, 0x004096A0))
    if "0x8e44" in handler_text or "0x8e45" in handler_text:
        raise SystemExit("unexpected direct per-row qualification-status reference in the All Start handler")
    add("function 0x004096A0..0x004096F9", "",
        "The bounded All Start handler body has no direct +0x8E44/+0x8E45 operand; its explicit checks use 0x5BE460[i], 0x5BE420[i], and dialog +0x90C4, which it increments after setup.")
    add("scope", "",
        "Static file evidence only. No updater execution, live HID enumeration, report transmission, bootloader entry, or firmware write.")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("binary_sha256", "evidence_va", "bytes", "observation", "claim_status"))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Verified 01BF hashes, {len(FACTS)} instruction facts, {len(CALL_EDGES)} direct-call edges, {len(EXPECTED_IMPORTS)} IAT mappings, the All Start message-map row, and 16 numbered dialog controls.")
    print(f"Wrote {len(rows)} evidence rows to {args.out}")
    print("Static trace reaches same-index All Start worker records conditionally; runtime identity, candidate acceptance, and HWND binding remain unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
