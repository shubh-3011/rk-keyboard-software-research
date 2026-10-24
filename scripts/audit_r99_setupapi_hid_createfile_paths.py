#!/usr/bin/env python3
"""Verify two R99 SetupAPI/HID CreateFileA paths from a pinned PE, offline.

The verifier reads the executable as PE bytes, checks its SHA-256, import
bindings, targeted instructions and direct-call census, then writes a compact
instruction evidence ledger. It never launches the binary or accesses a device.
Requires the existing pefile and Capstone packages.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from dataclasses import dataclass
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM


EXPECTED_SHA256 = "61dd118400a4652ba053db6ceb87cdd865e183f59822948ea9018da218aec2e5"
IMAGE_BASE = 0x00400000
CREATEFILE_IAT = 0x0057B0A8
CREATEFILE_CALLS = (0x0041AED9, 0x00475020, 0x00475358)
OPENER_CALLERS = (
    0x004734EA,
    0x00474054,
    0x004740B7,
    0x0047411A,
    0x0047417D,
    0x004741E0,
    0x00474243,
    0x004742A6,
    0x00474309,
    0x0047436C,
    0x004743CF,
    0x0047442A,
    0x00474478,
    0x00474517,
)
DEFAULT_OUTPUT = Path("docs/rk-r99-setupapi-hid-createfile-paths-2026-10-25.csv")


@dataclass(frozen=True)
class Evidence:
    address: int
    claim: str
    classification: str = "proven statically"
    raw_length: int = 0


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fmt(instruction) -> str:
    return f"{instruction.mnemonic} {instruction.op_str}".strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="extracted R99 RK Driver.exe")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help=f"CSV ledger (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--overwrite", action="store_true", help="replace the exact named output ledger")
    args = parser.parse_args()
    binary = args.binary.resolve()
    output = args.output.resolve()
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")
    if output.exists() and not args.overwrite:
        parser.error(f"refusing to replace existing output: {output}; pass --overwrite")

    digest = sha256(binary)
    if digest != EXPECTED_SHA256:
        raise ValueError(f"input SHA-256 {digest} does not match pinned R99 image {EXPECTED_SHA256}")
    pe = pefile.PE(str(binary), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    if pe.FILE_HEADER.Machine != 0x014C or pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE:
        raise ValueError("unexpected image architecture or base")

    imports: dict[tuple[str, str], int] = {}
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = descriptor.dll.decode("ascii", errors="replace").lower()
        for item in descriptor.imports:
            name = item.name.decode("ascii", errors="replace") if item.name else f"#{item.ordinal}"
            imports[(dll, name)] = int(item.address)

    expected_imports = {
        ("kernel32.dll", "CreateFileA"): 0x0057B0A8,
        ("kernel32.dll", "CloseHandle"): 0x0057B240,
        ("kernel32.dll", "CancelIo"): 0x0057B0C0,
        ("kernel32.dll", "CreateEventW"): 0x0057B0C8,
        ("kernel32.dll", "ReadFile"): 0x0057B0A4,
        ("kernel32.dll", "WriteFile"): 0x0057B0C4,
        ("kernel32.dll", "GetOverlappedResult"): 0x0057B0D8,
        ("kernel32.dll", "ResetEvent"): 0x0057B0D4,
        ("kernel32.dll", "LocalFree"): 0x0057B0DC,
        ("kernel32.dll", "LoadLibraryA"): 0x0057B0D0,
        ("kernel32.dll", "GetProcAddress"): 0x0057B23C,
        ("setupapi.dll", "SetupDiGetClassDevsA"): 0x0057B310,
        ("setupapi.dll", "SetupDiEnumDeviceInfo"): 0x0057B314,
        ("setupapi.dll", "SetupDiGetDeviceRegistryPropertyA"): 0x0057B318,
        ("setupapi.dll", "SetupDiDestroyDeviceInfoList"): 0x0057B31C,
        ("setupapi.dll", "SetupDiEnumDeviceInterfaces"): 0x0057B320,
        ("setupapi.dll", "SetupDiGetDeviceInterfaceDetailA"): 0x0057B30C,
    }
    for key, expected in expected_imports.items():
        actual = imports.get(key)
        if actual != expected:
            raise ValueError(f"import {key!r}: {actual!r}, expected 0x{expected:08x}")

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    decoded = []
    executable_sections = []
    for section in pe.sections:
        if int(section.Characteristics) & 0x20000000:
            base = IMAGE_BASE + int(section.VirtualAddress)
            data = section.get_data()
            executable_sections.append((base, data))
            decoded.extend(decoder.disasm(data, base))
    by_address = {instruction.address: instruction for instruction in decoded}

    createfile_calls = tuple(
        instruction.address
        for instruction in decoded
        if instruction.mnemonic == "call"
        and len(instruction.operands) == 1
        and instruction.operands[0].type == X86_OP_MEM
        and instruction.operands[0].mem.base == 0
        and instruction.operands[0].mem.index == 0
        and instruction.operands[0].mem.disp == CREATEFILE_IAT
    )
    if createfile_calls != CREATEFILE_CALLS:
        raise ValueError(f"CreateFileA call census changed: {[hex(x) for x in createfile_calls]}")

    direct_opener_calls = tuple(
        instruction.address
        for instruction in decoded
        if instruction.mnemonic == "call"
        and len(instruction.operands) == 1
        and instruction.operands[0].type == X86_OP_IMM
        and instruction.operands[0].imm == 0x00475290
    )
    if direct_opener_calls != OPENER_CALLERS:
        raise ValueError(f"selected-path opener caller census changed: {[hex(x) for x in direct_opener_calls]}")

    for address in direct_opener_calls:
        instruction = by_address.get(address - 2)
        if instruction is None or fmt(instruction) != "mov ecx, dword ptr [esi]":
            actual = "missing" if instruction is None else fmt(instruction)
            raise ValueError(f"caller 0x{address:08x} does not pass node[0] in ECX: {actual!r}")

    def direct_callers(target: int) -> tuple[int, ...]:
        return tuple(
            instruction.address
            for instruction in decoded
            if instruction.mnemonic == "call"
            and len(instruction.operands) == 1
            and instruction.operands[0].type == X86_OP_IMM
            and instruction.operands[0].imm == target
        )

    write_helper_callers = direct_callers(0x00475430)
    read_helper_callers = direct_callers(0x00475510)
    if len(write_helper_callers) != 14 or len(read_helper_callers) != 12:
        raise ValueError(f"report I/O helper census changed: writes={len(write_helper_callers)}, reads={len(read_helper_callers)}")

    def require(address: int, expected: str) -> None:
        instruction = by_address.get(address)
        actual = "missing" if instruction is None else fmt(instruction)
        if actual != expected:
            raise ValueError(f"instruction mismatch at 0x{address:08x}: got {actual!r}, expected {expected!r}")

    landmarks = {
        # SetupAPI HID interface enumeration and detail-path acquisition.
        0x00474E2D: "mov dword ptr [esp + 0x30], 0x4d1e55b2",
        0x00474E45: "mov dword ptr [esp + 0x38], 0x11cff16f",
        0x00474E4D: "mov dword ptr [esp + 0x3c], 0x1100cb88",
        0x00474E55: "mov dword ptr [esp + 0x40], 0x30000011",
        0x00474EA6: "push 0x12",
        0x00474ED6: "call dword ptr [0x57b310]",
        0x00474EFB: "test eax, eax",
        0x00474F03: "mov esi, dword ptr [0x57b30c]",
        0x00474F24: "call esi",
        0x00474F37: "mov dword ptr [eax], 5",
        0x00474F4F: "call esi",
        0x00474F62: "call dword ptr [0x57b314]",
        0x00474F89: "call dword ptr [0x57b318]",
        0x00474F97: "mov eax, 0x59770c",
        0x00474FDc: "push 9",
        0x00474FE4: "call dword ptr [0x57b318]",
        0x00475009: "mov eax, dword ptr [esp + 0x14]",
        0x0047500D: "push 0",
        0x0047500F: "push 0x40000000",
        0x00475014: "push 3",
        0x00475016: "push 0",
        0x00475018: "push 3",
        0x0047501A: "add eax, 4",
        0x0047501D: "push 0",
        0x0047501F: "push eax",
        0x00475020: "call dword ptr [0x57b0a8]",
        0x00475026: "mov esi, eax",
        0x0047502C: "cmp esi, -1",
        0x0047502F: "je 0x4751e1",
        0x00475039: "mov dword ptr [esp + 0x44], 0xc",
        0x00475043: "call dword ptr [0x5be0b8]",
        0x0047508F: "call dword ptr [0x5be0ac]",
        0x004750A5: "call dword ptr [0x5be0b0]",
        0x004750AB: "cmp eax, 0x110000",
        0x004750CE: "call dword ptr [0x5be0a8]",
        0x0047511B: "push eax",
        0x00475121: "call dword ptr [0x57b608]",
        0x0047514A: "call dword ptr [0x5be0bc]",
        0x004751E1: "push esi",
        0x004751E2: "call dword ptr [0x57b240]",
        0x004751EE: "push dword ptr [esp + 0x14]",
        0x004751F2: "call dword ptr [0x57b4c8]",
        0x0047521A: "call dword ptr [0x57b320]",
        0x0047522D: "call dword ptr [0x57b31c]",
        # Dynamically resolved HID exports used by both stages.
        0x00474D00: "push 0x597648",
        0x00474D05: "call dword ptr [0x57b0d0]",
        0x00474D19: "mov esi, dword ptr [0x57b23c]",
        0x00474D1F: "push 0x5976a0",
        0x00474D25: "call esi",
        0x00474D27: "mov dword ptr [0x5be0b8], eax",
        0x00474DC0: "push 0x5976b4",
        0x00474DCB: "call esi",
        0x00474DCD: "mov dword ptr [0x5be0ac], eax",
        0x00474DD6: "push 0x597728",
        0x00474DE1: "call esi",
        0x00474DE3: "mov dword ptr [0x5be0a8], eax",
        0x00474DF1: "push 0x597718",
        0x00474DFC: "call esi",
        0x00474DFE: "mov dword ptr [0x5be0b0], eax",
        # Selected-path opener: persistent overlapped handle/event context.
        0x004752AD: "mov esi, ecx",
        0x004752FD: "push 0x38",
        0x00475301: "call dword ptr [0x57b4d0]",
        0x00475311: "push eax",
        0x00475312: "push eax",
        0x00475333: "push eax",
        0x00475338: "push eax",
        0x0047533C: "call dword ptr [0x57b0c8]",
        0x00475342: "push 0",
        0x00475344: "push 0x40000000",
        0x00475349: "push 3",
        0x0047534B: "push 0",
        0x0047534D: "push 3",
        0x00475339: "mov dword ptr [edi + 0x34], eax",
        0x0047534F: "push 0xc0000000",
        0x00475354: "push esi",
        0x00475358: "call dword ptr [0x57b0a8]",
        0x0047535E: "mov dword ptr [edi], eax",
        0x00475360: "cmp eax, -1",
        0x00475365: "mov ecx, edi",
        0x00475367: "call 0x474c80",
        0x00475374: "call dword ptr [0x5be0ac]",
        0x00475387: "call dword ptr [0x5be0b0]",
        0x0047538D: "cmp eax, 0x110000",
        0x0047539F: "call dword ptr [0x5be0a8]",
        0x004753A5: "push dword ptr [edi + 0x34]",
        0x004753AE: "call esi",
        0x004753B0: "push dword ptr [edi]",
        0x004753B2: "call esi",
        0x004753B4: "push dword ptr [edi + 0x14]",
        0x004753B7: "call dword ptr [0x57b0dc]",
        0x004753BD: "push dword ptr [edi + 0x20]",
        0x004753C6: "call esi",
        0x004753C8: "push edi",
        0x004753C9: "call esi",
        0x004753E1: "movzx eax, word ptr [esp + 0x16]",
        0x004753EA: "movzx eax, word ptr [esp + 0x14]",
        0x004753F2: "movzx eax, word ptr [esp + 0x18]",
        0x00475405: "push dword ptr [edi + 0xc]",
        0x00475418: "mov eax, edi",
        0x00473582: "mov dword ptr [ebx + 0x414], edi",
        # Report-length-aware overlapped I/O operations.
        0x0047545B: "movzx ecx, word ptr [edi + 8]",
        0x00475493: "lea eax, [ebp - 0x1c]",
        0x00475496: "push eax",
        0x00475497: "push 0",
        0x00475499: "push ebx",
        0x0047549A: "push esi",
        0x0047549B: "push dword ptr [edi]",
        0x0047549D: "call dword ptr [0x57b0c4]",
        0x004754AD: "cmp eax, 0x3e5",
        0x004754CF: "call dword ptr [0x57b0d8]",
        0x0047552E: "cmp dword ptr [esi + 0x1c], 0",
        0x0047554F: "call dword ptr [0x57b0d4]",
        0x00475558: "push eax",
        0x0047555C: "push eax",
        0x0047555D: "push dword ptr [esi + 0xc]",
        0x00475560: "push dword ptr [esi + 0x20]",
        0x00475563: "push dword ptr [esi]",
        0x00475565: "call dword ptr [0x57b0a4]",
        0x00475575: "cmp eax, 0x3e5",
        0x0047557E: "call dword ptr [0x57b0c0]",
        0x004755D8: "call dword ptr [0x57b0d8]",
        0x004755F3: "cmp byte ptr [edx], 0",
        # Successful context teardown found in its owner destructor path.
        0x00471E1F: "mov ebx, dword ptr [esi + 0x414]",
        0x00471DD3: "mov edx, dword ptr [0x57b0c0]",
        0x00471E29: "push dword ptr [ebx]",
        0x00471E2B: "call edx",
        0x00471E2D: "push dword ptr [ebx + 0x34]",
        0x00471E30: "call dword ptr [0x57b240]",
        0x00471E36: "push dword ptr [ebx]",
        0x00471E38: "call dword ptr [0x57b240]",
        0x00471E41: "call dword ptr [0x57b0dc]",
        0x00471E4A: "call dword ptr [0x57b4c8]",
    }
    for address, expected in landmarks.items():
        require(address, expected)

    strings = {
        0x00597648: b"hid.dll\0",
        0x005976A0: b"HidD_GetAttributes\0",
        0x005976B4: b"HidD_GetPreparsedData\0",
        0x00597718: b"HidP_GetCaps\0",
        0x00597728: b"HidD_FreePreparsedData\0",
        0x0059770C: b"HIDClass\0",
        0x00597704: b"&mi_\0",
    }
    for va, expected in strings.items():
        actual = pe.get_data(va - IMAGE_BASE, len(expected))
        if actual != expected:
            raise ValueError(f"string mismatch at 0x{va:08x}: {actual!r}, expected {expected!r}")

    evidence: list[Evidence] = [
        Evidence(CREATEFILE_IAT, "KERNEL32!CreateFileA is imported at the only IAT slot used by the three direct app callsites"),
        *[Evidence(address, "direct CreateFileA callsite in this pinned executable") for address in CREATEFILE_CALLS],
        Evidence(0x00474E2D, "GUID data begins with 4D1E55B2; remaining fields at following stores form the HID device-interface GUID"),
        Evidence(0x00474E45, "HID interface GUID field 0xF16F11CF in little-endian storage"),
        Evidence(0x00474E4D, "HID interface GUID Data4 prefix 88-CB-00-11"),
        Evidence(0x00474E55, "HID interface GUID Data4 suffix 11-00-00-30"),
        Evidence(0x00474EA6, "SetupDiGetClassDevsA flags 0x12 (DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)"),
        Evidence(0x00474ED6, "SetupDiGetClassDevsA receives the HID interface GUID and flags 0x12"),
        Evidence(0x00474EF5, "SetupDiEnumDeviceInterfaces enumerates HID interfaces; the later loop increments MemberIndex"),
        Evidence(0x00474F03, "loads SetupDiGetDeviceInterfaceDetailA from its IAT slot for indirect calls"),
        Evidence(0x00474F24, "first SetupDiGetDeviceInterfaceDetailA call queries required detail-buffer size with a null buffer"),
        Evidence(0x00474F37, "sets SP_DEVICE_INTERFACE_DETAIL_DATA_A cbSize to 5 on x86"),
        Evidence(0x00474F4F, "second SetupDiGetDeviceInterfaceDetailA call fills the allocated detail buffer"),
        Evidence(0x0047501A, "CreateFileA path is detail-buffer base plus four bytes, the x86 DevicePath field offset"),
        Evidence(0x00475009, "loads the allocated detail buffer; subsequent add-four and push supply its DevicePath"),
        Evidence(0x00474F62, "a separate SetupDiEnumDeviceInfo loop queries device registry properties"),
        Evidence(0x00474F89, "SetupDiGetDeviceRegistryPropertyA requests property 7 into a 0x100-byte buffer"),
        Evidence(0x00474F97, "property-7 string is compared with the embedded HIDClass name"),
        Evidence(0x00474FDC, "on HIDClass match, property 9 is requested as a second registry-property filter"),
        Evidence(0x00475020, "first remaining CreateFileA path: short-lived SetupAPI-discovered HID interface metadata probe"),
        Evidence(0x0047501D, "first path requests desired access zero"),
        Evidence(0x00475018, "first path uses FILE_SHARE_READ | FILE_SHARE_WRITE"),
        Evidence(0x00475016, "first path passes null security attributes"),
        Evidence(0x00475014, "first path uses OPEN_EXISTING"),
        Evidence(0x0047500F, "first path sets FILE_FLAG_OVERLAPPED"),
        Evidence(0x0047500D, "first path passes a null template handle"),
        Evidence(0x0047502C, "first path checks CreateFileA failure against INVALID_HANDLE_VALUE"),
        Evidence(0x0047502F, "failure skips HID queries and joins common handle cleanup"),
        Evidence(0x00475043, "first path calls dynamically resolved HidD_GetAttributes; HIDD_ATTRIBUTES cbSize is 12"),
        Evidence(0x0047508F, "first path calls dynamically resolved HidD_GetPreparsedData"),
        Evidence(0x004750A5, "first path calls dynamically resolved HidP_GetCaps"),
        Evidence(0x004750AB, "the HidP_GetCaps success branch compares with HIDP_STATUS_SUCCESS 0x00110000"),
        Evidence(0x004750CE, "preparsed data is freed after the caps-query branch"),
        Evidence(0x0047514A, "first path also queries the product string after capability probing"),
        Evidence(0x004751E2, "first path closes its temporary file handle on common exit, including the invalid-handle branch"),
        Evidence(0x004751F2, "first path frees the per-interface detail buffer before moving to the next interface"),
        Evidence(0x0047521A, "interface enumeration advances to the next MemberIndex until SetupAPI reports end-of-list"),
        Evidence(0x0047522D, "first path destroys its HDEVINFO set at enumeration completion"),
        Evidence(0x00474D05, "one-time resolver loads the embedded hid.dll name with LoadLibraryA"),
        Evidence(0x00474D25, "GetProcAddress resolves the embedded HidD_GetAttributes export name"),
        Evidence(0x00474D27, "resolved HidD_GetAttributes pointer is cached at 0x005BE0B8"),
        Evidence(0x00474DCD, "resolved HidD_GetPreparsedData pointer is cached at 0x005BE0AC"),
        Evidence(0x00474DE3, "resolved HidD_FreePreparsedData pointer is cached at 0x005BE0A8"),
        Evidence(0x00474DFE, "resolved HidP_GetCaps pointer is cached at 0x005BE0B0"),
        Evidence(0x00597648, "embedded dynamic-library name is hid.dll", raw_length=8),
        Evidence(0x005976A0, "embedded dynamic-export name is HidD_GetAttributes", raw_length=19),
        Evidence(0x005976B4, "embedded dynamic-export name is HidD_GetPreparsedData", raw_length=22),
        Evidence(0x00597718, "embedded dynamic-export name is HidP_GetCaps", raw_length=14),
        Evidence(0x00597728, "embedded dynamic-export name is HidD_FreePreparsedData", raw_length=23),
        Evidence(0x0059770C, "embedded registry-class comparison string is HIDClass", raw_length=9),
        Evidence(0x004752AD, "selected-path opener receives its input DevicePath in ECX"),
        Evidence(0x00475301, "selected-path opener allocates a 0x38-byte zeroed connection context"),
        Evidence(0x0047533C, "selected-path opener creates an unnamed default event and stores its handle in context+0x34"),
        Evidence(0x00475358, "second remaining CreateFileA path: opens a previously discovered interface as a persistent connection"),
        Evidence(0x00475354, "second path uses the supplied DevicePath string as lpFileName"),
        Evidence(0x0047534F, "second path requests GENERIC_READ | GENERIC_WRITE"),
        Evidence(0x0047534D, "second path uses read/write sharing"),
        Evidence(0x0047534B, "second path passes null security attributes"),
        Evidence(0x00475349, "second path uses OPEN_EXISTING"),
        Evidence(0x00475344, "second path sets FILE_FLAG_OVERLAPPED"),
        Evidence(0x00475342, "second path passes a null template handle"),
        Evidence(0x0047535E, "second path stores the returned file handle at connection-context offset zero"),
        Evidence(0x00475360, "second path checks INVALID_HANDLE_VALUE and routes failure through diagnostic/cleanup"),
        Evidence(0x00475367, "failure invokes the last-error message formatter before cleanup"),
        Evidence(0x00475374, "second path obtains HID preparsed data for the open handle"),
        Evidence(0x00475387, "second path calls HidP_GetCaps and requires status 0x00110000"),
        Evidence(0x0047539F, "second path frees preparsed data after a successful caps query"),
        Evidence(0x00475405, "allocates an input-report-sized buffer from HIDP_CAPS.InputReportByteLength"),
        Evidence(0x00475418, "successful opener returns the allocated connection context; its handle/event remain open"),
        Evidence(0x00473582, "caller stores the returned connection context in its device-owner object at +0x414"),
        Evidence(0x0047545B, "write helper compares requested payload length with context OutputReportByteLength"),
        Evidence(0x0047549D, "write helper calls WriteFile with context handle, report buffer and output-report length"),
        Evidence(0x004754AD, "write helper recognizes ERROR_IO_PENDING 997"),
        Evidence(0x004754CF, "pending writes are completed through GetOverlappedResult with wait=true"),
        Evidence(0x0047552E, "read helper uses a context state field to avoid overlapping reads"),
        Evidence(0x0047554F, "read helper resets the context event before ReadFile"),
        Evidence(0x00475565, "read helper calls ReadFile with context handle, input-report-sized buffer and OVERLAPPED"),
        Evidence(0x00475575, "read helper recognizes ERROR_IO_PENDING 997"),
        Evidence(0x0047557E, "non-pending read failure cancels I/O on the context handle"),
        Evidence(0x004755D8, "pending reads are completed through GetOverlappedResult"),
        Evidence(0x004755F3, "read completion checks whether the first input byte is a zero report ID before copying data"),
        Evidence(0x00471E1F, "owner teardown reaches the live connection context through a stored pointer"),
        Evidence(0x00471E2B, "owner teardown calls CancelIo on the connection handle"),
        Evidence(0x00471E30, "owner teardown closes the connection event handle at context+0x34"),
        Evidence(0x00471E38, "owner teardown closes the connection file handle at context+0"),
        Evidence(0x00471E41, "owner teardown releases the context's LocalFree-managed diagnostic string"),
        Evidence(0x00471E4A, "owner teardown frees the context's input report buffer"),
        *[
            Evidence(address, "direct caller passes the discovered node's first field (DevicePath pointer) in ECX to the selected-path opener")
            for address in OPENER_CALLERS
        ],
        Evidence(0x00473B10, "one selected-device caller probes the DevicePath context and records a model-specific response; response semantics remain separately unresolved", "proven statically"),
    ]

    fieldnames = ["binary", "binary_sha256", "evidence_id", "address_va", "file_offset", "bytes", "instruction", "claim", "classification"]
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for index, item in enumerate(evidence, 1):
            instruction = by_address.get(item.address)
            if instruction is not None:
                offset = pe.get_offset_from_rva(item.address - IMAGE_BASE)
                raw = instruction.bytes.hex(" ")
                disassembly = fmt(instruction)
            else:
                rva = item.address - IMAGE_BASE
                offset = pe.get_offset_from_rva(rva)
                raw = pe.get_data(rva, item.raw_length).hex(" ") if item.raw_length else ""
                disassembly = ""
            writer.writerow({
                "binary": binary.name,
                "binary_sha256": digest,
                "evidence_id": f"R99-SHID-CFA-{index:03d}",
                "address_va": f"0x{item.address:08x}",
                "file_offset": f"0x{offset:x}",
                "bytes": raw,
                "instruction": disassembly,
                "claim": item.claim,
                "classification": item.classification,
            })

    print(f"Input SHA-256: {digest}")
    print(f"CreateFileA direct callsites: {', '.join(hex(x) for x in createfile_calls)}")
    print(f"Selected-path opener direct callers: {len(direct_opener_calls)}")
    print(f"Evidence rows written: {len(evidence)} -> {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
