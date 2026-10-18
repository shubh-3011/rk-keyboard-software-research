#!/usr/bin/env python3
"""Verify the V4.6 CDevG5KB vtable and emit its static method ledger.

Reads the hash-pinned DeviceDriver.exe as PE bytes only. It neither starts RK
software nor opens a device interface or sends a HID report.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path

import pefile


EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
IMAGE_BASE = 0x00400000
VTABLE_VA = 0x005D3D0C
CONSTRUCTOR_SITE_VA = 0x0040F4C3
EXPECTED_TARGETS = [
    0x0040F5A0, 0x0040FB20, 0x0040D710, 0x0040F670, 0x0040F740,
    0x00413D90, 0x0040F7C0, 0x00411B80, 0x0040FED0, 0x0040FF50,
    0x0040FFA0, 0x00410F70, 0x00410640, 0x00410D10, 0x00410C00,
    0x004103C0, 0x0040FDD0, 0x004127B0, 0x00410FA0, 0x00411050,
    0x00410B60, 0x00413CB0, 0x00413620, 0x0040D750, 0x0040D780,
    0x0040D7A0, 0x004110E0, 0x00411840, 0x00411030,
]

ROWS = [
    ("scalar deleting destructor", "proven", "0x0040F5A0 calls destructor 0x0040F5C0; its deleting branch calls the deallocator at 0x00477060.", "Object teardown and deleting-destructor wrapper; no device command."),
    ("HID discovery / open", "proven", "0x0040FB20 enumerates interfaces and checks HID attributes; diagnostic at 0x005D29C0 is `CDevG5KB::FindHIDDevice`; 0x005D2AC8 logs selected handles.", "Software-side discovery path only; physical-device compatibility was not tested."),
    ("zero-return stub", "proven", "0x0040D710 is `xor eax,eax; ret`.", "Returns zero; precise inherited interface name is unavailable."),
    ("G5 service-thread resource start", "proven", "0x0040F670 creates event objects and starts worker entry 0x0040F140; it has a guarded failure path.", "Thread creation is statically present; this audit did not run it."),
    ("G5 service-thread resource stop", "proven", "0x0040F740 closes event/thread handles at object offsets +0x278/+0x284/+0x280/+0x27C and resets fields.", "Cleanup routine; no device command."),
    ("primary HID handle getter", "proven", "0x00413D90 returns the DWORD at object offset +0x04.", "Handle value is static object state; validity was not runtime-tested."),
    ("primary handle close/reset", "proven", "0x0040F7C0 closes object handles at +0x04/+0x08 and clears the connection state at +0x22.", "Cleanup routine; no device command."),
    ("forwarding adapter to vtable +0x6C", "proven", "0x00411B80 loads this object's vtable entry +0x6C, forwards the buffer and a zero argument, then returns.", "The caller relationship is proven; the forwarded data's user-facing name is not."),
    ("synchronization / child-worker status helper", "unresolved", "0x0040FED0 checks object thread state, uses the thread wait/status API path, and delegates to a child object's vtable +0x20 when present.", "Exact UI meaning and all return-state meanings remain unresolved."),
    ("VID/PID equality check", "proven", "0x0040FF50 compares supplied words with primary object fields +0x24C/+0x24E, then tries the child object at +0x254.", "Checks configured identifiers; it does not prove model identity."),
    ("child readiness gate", "proven", "0x0040FFA0 returns true only when a child object exists and its vtable +0x14 call succeeds.", "The child method's semantic name is unresolved."),
    ("child state forwarding", "proven", "0x00410F70 delegates to child vtable +0x2C when a child exists, otherwise returns 1.", "The delegated state meaning is unresolved."),
    ("power query", "proven", "0x00410640 builds a G5 feature-report request and logs `GetPower failed` at 0x005D2E3C; it uses the G5 response-read helper.", "Power units and report fields are unresolved."),
    ("password query", "proven", "0x00410D10 reads command 0x88 data and logs `GetPassword failed` at 0x005D2E84.", "Password representation and its UI caller are unresolved."),
    ("reset-device request", "proven", "0x00410C00 sends operation 1, command 0x11, one data byte set to zero; error text at 0x005D1ED8 is `ResetDevice failed`.", "Effect and firmware behavior are unknown; the path is a write if invoked."),
    ("G5 AccessData transport", "proven", "0x004103C0 is the G5 feature request/response helper. Its reader/writer branches reach HidD_SetFeature/HidD_GetFeature; logs at 0x005D2BD0–0x005D2D90 identify AccessData failures.", "Report framing is described in the companion audit; command acceptance was not tested."),
    ("profile LED preflight/cache", "inferred", "0x0040FDD0 calls vtable +0x3C for a 0x80-byte read, parses the returned buffer through 0x0040D270, and updates fields +0x270/+0x248/+0x274.", "The read/cache behavior is proven; its exact feature label and invocation source are not."),
    ("ApplySetting", "proven", "0x004127B0 has the string `CDevG5KB::ApplySetting` at 0x005D33A0 and contains the flag-controlled G5 settings paths summarized in the flag ledger.", "Static serializer reachability only; UI-event source and runtime success remain unresolved."),
    ("command-8 feature writer", "proven", "0x00410FA0 rejects work while busy at +0x238 and calls the generic writer with operation 1 and command 8.", "Feature purpose and payload schema are unresolved."),
    ("LED settings read/modify/write", "proven", "0x00411050 reads 0x80 bytes through vtable +0x3C, then calls 0x00410340 (operation 1, command 4, 0x80-byte buffer); error string at 0x005D1E04 is `SetLED failed`.", "Active read/write when invoked; fields, values, and units are unresolved."),
    ("screen parameter writer", "proven", "0x00410B60 calls the generic writer with operation 1, command 0x0B, 0x19-byte payload; error text at 0x005D1E8C is `SetScreenParam failed`.", "Screen parameter schema and UI-control mapping are unresolved."),
    ("screen page-transfer wrapper", "proven", "0x00413CB0 chooses a primary/secondary handle and forwards to page-transfer core 0x004138A0; see the V4.6 screen/GIF audit.", "Page field meanings and firmware acknowledgement semantics remain partly unresolved."),
    ("GIF parameter writer", "proven", "0x00413620 constructs five bytes and calls generic writer operation 1, command 0x0D; diagnostic at 0x005D3748 names the frame/index/delay inputs.", "Exact index/flag meaning and device acceptance are unresolved."),
    ("cancel request signal", "proven", "0x0040D750 sets object flag +0x28C and signals event +0x290.", "Cancellation outcome depends on worker observation; no worker was run."),
    ("cancel reset signal", "proven", "0x0040D780 clears object flag +0x28C and signals event +0x290.", "Meaning is limited to the matching object/event fields."),
    ("cancel-state query", "proven", "0x0040D7A0 returns the object state at +0x28C.", "Exact state lifecycle beyond the set/clear methods remains unresolved."),
    ("key/action hardware-code translator", "proven", "0x004110E0 branches on action-record type/subtype and emits packed hardware-code values; failure text at 0x005D2EB0 names macro-ID lookup.", "The complete action taxonomy and meanings of every packed field remain unresolved."),
    ("key/macro event serializer", "inferred", "0x00411840 reads variable event records, maps action classes, and constructs output bytes; it is reached through a virtual +0x6C forwarding path.", "Record schema and exact event-to-firmware meaning are unresolved."),
    ("busy-guarded GetRealData wrapper", "proven", "0x00411030 returns early while +0x238 is set, otherwise calls 0x00410890; that helper reads command 0x88 and logs `GetRealData failed` at 0x005D2E5C.", "Return data semantics and the source of its caller are unresolved."),
]


def read_va(pe: pefile.PE, data: bytes, va: int, size: int) -> bytes:
    return data[pe.get_offset_from_rva(va - pe.OPTIONAL_HEADER.ImageBase) :][:size]


def read_u32(pe: pefile.PE, data: bytes, va: int) -> int:
    raw = read_va(pe, data, va, 4)
    if len(raw) != 4:
        raise ValueError(f"truncated PE data at 0x{va:08X}")
    return int.from_bytes(raw, "little")


def read_c_string(pe: pefile.PE, data: bytes, va: int) -> str:
    return read_va(pe, data, va, 512).split(b"\0", 1)[0].decode("ascii", errors="replace")


def validate_rtti(pe: pefile.PE, data: bytes) -> None:
    col_va = read_u32(pe, data, VTABLE_VA - 4)
    signature = read_u32(pe, data, col_va)
    type_va = read_u32(pe, data, col_va + 12)
    if signature != 0 or read_c_string(pe, data, type_va + 8) != ".?AVCDevG5KB@@":
        raise SystemExit("vtable RTTI does not identify the expected x86 CDevG5KB class")
    site = read_va(pe, data, CONSTRUCTOR_SITE_VA, 6)
    if site[:1] != b"\xC7" or int.from_bytes(site[2:6], "little") != VTABLE_VA:
        raise SystemExit(f"constructor vtable install mismatch at 0x{CONSTRUCTOR_SITE_VA:08X}")


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--driver",
        type=Path,
        default=root.parent / ".research" / "rk4_6_official_extract_20261015" / "app" / "DeviceDriver.exe",
    )
    parser.add_argument("--output", type=Path, default=root / "docs" / "rk-v4.6-cdevg5-vtable-map.csv")
    args = parser.parse_args()

    data = args.driver.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"DeviceDriver.exe SHA-256 mismatch: {digest}")
    pe = pefile.PE(data=data, fast_load=False)
    if pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE:
        raise SystemExit(f"unexpected image base: 0x{pe.OPTIONAL_HEADER.ImageBase:08X}")
    validate_rtti(pe, data)

    targets = [read_u32(pe, data, VTABLE_VA + slot * 4) for slot in range(len(EXPECTED_TARGETS))]
    if targets != EXPECTED_TARGETS:
        raise SystemExit("CDevG5KB vtable contents differ from the reviewed 29-slot ledger")
    for target in targets:
        rva = target - IMAGE_BASE
        section = pe.get_section_by_rva(rva)
        if section is None or not section.IMAGE_SCN_MEM_EXECUTE:
            raise SystemExit(f"vtable target is not in an executable PE section: 0x{target:08X}")
    marker = read_va(pe, data, VTABLE_VA + len(targets) * 4, 64).decode("utf-16le", errors="replace")
    if not marker.startswith("CDevRKKB::WriteDevice"):
        raise SystemExit(f"unexpected data after vtable extent: {marker!r}")

    if len(ROWS) != len(targets):
        raise SystemExit("row count differs from vtable entry count")
    rows = []
    for index, (role, status, evidence, limits) in enumerate(ROWS):
        rows.append({
            "slot_index": index,
            "vtable_offset": f"+0x{index * 4:02X}",
            "entry_va": f"0x{VTABLE_VA + index * 4:08X}",
            "target_va": f"0x{targets[index]:08X}",
            "role": role,
            "status": status,
            "static_evidence": evidence,
            "scope_limit": limits,
        })

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    counts = {key: sum(row["status"] == key for row in rows) for key in ("proven", "inferred", "unresolved")}
    print(f"verified SHA-256 {digest}; CDevG5KB RTTI and constructor vtable install; {len(rows)} slots")
    print(f"wrote {args.output}; proven={counts['proven']}, inferred={counts['inferred']}, unresolved={counts['unresolved']}")


if __name__ == "__main__":
    main()
