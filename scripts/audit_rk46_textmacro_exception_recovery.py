#!/usr/bin/env python3
"""Verify one 4.6 text-macro TLS exception recovery route from pinned PE bytes."""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path
import struct

import pefile

EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
EXPECTED_SIZE = 2_418_176
IMAGE_BASE = 0x00400000
FUNCINFO_MAGIC = 0x19930522

INSTRUCTIONS: dict[int, tuple[str, str, str]] = {
    0x00480C33: ("e8dab6ffff", "picker-validation-call", "Picker virtual handler calls validation helper 0x0047C312."),
    0x0047C32E: ("e8f6e10000", "validation-tls-accessor-call", "Validation helper calls TLS guard 0x0048A529 before entering its local try state."),
    0x0047C350: ("897dfc", "validation-eh-state", "Validation helper sets EH state to zero after the TLS accessor returns."),
    0x0047C353: ("ff90fc000000", "validation-protected-call", "The first protected virtual call occurs after the EH state becomes zero."),
    0x0048A529: ("68a07a4700b998c36100e84c250000", "tls-guard-call", "Passes callback 0x00477AA0 and state 0x0061C398 to helper 0x0048CA84."),
    0x0048A538: ("85c0", "tls-guard-null-test", "Tests the helper's returned object pointer."),
    0x0048A53A: ("7505", "tls-guard-nonnull-branch", "A non-null pointer returns normally; null falls through to the shared throw jump."),
    0x0048A53C: ("e943d5feff", "tls-guard-null-throw", "Null result jumps to shared exception stub 0x00477A84."),
    0x0048CA84: ("6a04b8001f5900e824b70e00", "tls-helper-eh-frame", "Helper registers EH handler thunk 0x00591F00 before its body."),
    0x0048CA9E: ("e8e1affeff", "tls-helper-invalid-callback-throw", "Invalid callback/context setup also calls the shared exception stub."),
    0x00591F11: ("b8fc055f00", "tls-helper-funcinfo-link", "EH thunk selects FuncInfo 0x005F05FC."),
    0x00477A84: ("8bff558bec5168b0f15e008d45fc50c745fcc8736000e81f081000", "shared-throw-stub", "Constructs a pointer exception using object 0x006073C8 and ThrowInfo 0x005EF1B0, then calls 0x005782BE."),
    0x005CC030: ("63736de0", "msvc-exception-code", "Exception template starts with MSVC C++ exception code 0xE06D7363."),
    0x00578300: ("ff15a4625a00", "raise-exception-call", "Calls the RaiseException IAT slot 0x005A62A4."),
    0x004811E8: ("b849155900", "modal-wrapper-eh-thunk", "Modal wrapper registers EH thunk 0x00591549."),
    0x0059155A: ("b810f95e00", "modal-wrapper-funcinfo-link", "EH thunk selects FuncInfo 0x005EF910."),
    0x004812CD: ("8365fc00", "modal-wrapper-eh-state-enter", "Sets modal wrapper EH state to zero."),
    0x0048130E: ("e84ab2ffff", "modal-loop-call", "Calls modal-loop helper 0x0047C55D while wrapper EH state is zero."),
    0x0048132B: ("834dfcff", "modal-wrapper-eh-state-exit", "Normal return path resets wrapper EH state to -1."),
    0x00481331: ("8b4dd085c97405e83f66ffff", "modal-catch-cleanup", "Catch handler loads the caught pointer at [ebp-0x30] and calls helper 0x0047797C when non-null."),
    0x00481340: ("834844ff", "modal-catch-result", "Catch handler stores -1 in dialog result field +0x44."),
    0x00481344: ("834dfcff", "modal-catch-state-exit", "Catch handler resets wrapper EH state to -1."),
    0x00481348: ("b84e134800c3", "modal-catch-continuation", "Catch handler returns continuation address 0x0048134E."),
    0x004813A9: ("8b4644", "modal-result-return", "Common modal epilogue loads dialog result field +0x44 into EAX."),
    0x0041CF25: ("686b2c5a00", "picker-parent-eh-thunk", "Parent handler function registers EH thunk 0x005A2C6B."),
    0x005A2C89: ("b8b8196000", "picker-parent-funcinfo-link", "EH thunk selects FuncInfo 0x006019B8."),
    0x0041D157: ("e88a400600", "picker-parent-modal-call", "Parent calls modal wrapper 0x004811E6."),
    0x0041D15C: ("83f801", "picker-parent-result-test", "Parent compares the modal result against 1."),
    0x0041D15F: ("0f854d010000", "picker-parent-non-one-branch", "Every result other than 1 branches to cleanup at 0x0041D2B2."),
    0x0041D267: ("e8e4190000", "picker-parent-success-followup", "The result-1 path calls follow-up handler 0x0041EC50."),
    0x0041D2B2: ("8d8d88e7ffff", "picker-parent-cleanup", "Non-1 path begins picker-object cleanup."),
    0x0041D2B8: ("c745fcffffffff", "picker-parent-cleanup-state", "Parent cleanup resets its EH state to -1."),
    0x0041D2BF: ("e82c250000", "picker-parent-cleanup-call", "Parent cleanup calls picker destructor 0x0041F7F0."),
}

THROWABLE_TYPES = {
    0x006070E8: ".PAVCInvalidArgException@@",
    0x006070A0: ".PAVCSimpleException@@",
    0x00619F3C: ".PAVCException@@",
    0x00607058: ".PAVCObject@@",
    0x00607070: ".PAX",
}
THROWABLE_RECORDS = (0x005EF1D8, 0x005EF150, 0x005EF060, 0x005EF07C, 0x005EF098)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    require(len(data) == EXPECTED_SIZE and digest == EXPECTED_SHA256,
            "input size/SHA-256 mismatch")
    pe = pefile.PE(data=data)
    require(pe.OPTIONAL_HEADER.ImageBase == IMAGE_BASE and pe.FILE_HEADER.Machine == 0x14C,
            "expected x86 PE at preferred base")

    def raw(va: int, size: int) -> bytes:
        rva = va - IMAGE_BASE
        offset = pe.get_offset_from_rva(rva)
        require(offset + size <= len(data), f"VA range outside file: 0x{va:08X}+0x{size:X}")
        return data[offset:offset + size]

    rows: list[dict[str, str]] = []

    def emit(va: int, byte_data: bytes, stage: str, observation: str, scope: str) -> None:
        rows.append({
            "binary_sha256": digest,
            "evidence_va": f"0x{va:08X}",
            "bytes": byte_data.hex().upper(),
            "stage": stage,
            "observation": observation,
            "scope": scope,
        })

    for va, (expected_hex, stage, observation) in INSTRUCTIONS.items():
        expected = bytes.fromhex(expected_hex)
        actual = raw(va, len(expected))
        require(actual == expected,
                f"0x{va:08X}: expected {expected.hex()}, got {actual.hex()}")
        emit(va, actual, stage, observation,
             "hash-pinned static instruction bytes; execution and runtime exception dispatch unobserved")

    picker_handler_vtable = raw(0x005D5464, 4)
    require(struct.unpack("<I", picker_handler_vtable)[0] == 0x00480C2C,
            "CKeyFunPickDlg virtual slot +0x158 no longer targets 0x00480C2C")
    emit(0x005D5464, picker_handler_vtable, "picker-handler-vtable-link",
         "CKeyFunPickDlg slot +0x158 targets picker handler 0x00480C2C, which calls validation helper 0x0047C312.",
         "static RTTI/vtable target and instruction link; the event's runtime delivery is unobserved")

    # MSVC x86 ThrowInfo -> CatchableTypeArray -> CatchableType records.
    throw_info = raw(0x005EF1B0, 16)
    throw_fields = struct.unpack("<4I", throw_info)
    require(throw_fields == (0, 0, 0, 0x005EF1C0),
            f"ThrowInfo changed: {throw_fields!r}")
    emit(0x005EF1B0, throw_info, "throw-info",
         "ThrowInfo points to the five-entry catchable-type array at 0x005EF1C0.",
         "static MSVC exception metadata; no exception instance was observed")

    array_head = raw(0x005EF1C0, 24)
    count, *record_ptrs = struct.unpack("<6I", array_head)
    require(count == 5 and tuple(record_ptrs) == THROWABLE_RECORDS,
            f"catchable-type array changed: {count}, {record_ptrs!r}")
    emit(0x005EF1C0, array_head, "catchable-type-array",
         "Five static catchable-type record pointers, including CInvalidArgException* and CException*.",
         "static type metadata; no C++ catch dispatch was observed")

    observed_names: set[str] = set()
    for record_va in THROWABLE_RECORDS:
        record = raw(record_va, 28)
        fields = struct.unpack("<7I", record)
        type_va = fields[1]
        require(type_va in THROWABLE_TYPES, f"unexpected catchable TypeDescriptor 0x{type_va:08X}")
        expected_name = THROWABLE_TYPES[type_va].encode("ascii") + b"\0"
        name = raw(type_va + 8, len(expected_name))
        require(name == expected_name,
                f"TypeDescriptor 0x{type_va:08X} name changed: {name!r}")
        observed_names.add(THROWABLE_TYPES[type_va])
        emit(record_va, record, "catchable-type-record",
             f"CatchableType record references TypeDescriptor 0x{type_va:08X} ({THROWABLE_TYPES[type_va]}).",
             "static MSVC exception metadata; this record does not prove runtime throw selection")
        emit(type_va + 8, name, "catchable-type-name",
             f"TypeDescriptor name is {THROWABLE_TYPES[type_va]}.",
             "static RTTI/type-descriptor string")
    require(".PAVCInvalidArgException@@" in observed_names and ".PAVCException@@" in observed_names,
            "expected thrown pointer/base-catchable type descriptors missing")

    # FuncInfo and maps use the x86 MSVC EH layout: 7 DWORD FuncInfo, 5 DWORD
    # TryBlockMapEntry, then 4 DWORD HandlerType records.
    def check_funcinfo(va: int, expected: tuple[int, ...], stage: str, observation: str) -> None:
        raw_info = raw(va, 28)
        fields = struct.unpack("<7I", raw_info)
        require(fields == expected, f"FuncInfo at 0x{va:08X} changed: {fields!r}")
        require(fields[0] == FUNCINFO_MAGIC, f"unexpected MSVC FuncInfo magic at 0x{va:08X}")
        emit(va, raw_info, stage, observation,
             "static x86 MSVC EH metadata; it describes compiler tables, not observed dispatch")

    # The TLS helper and parent picker event handler have unwind metadata but
    # no local C++ catch blocks. The validator has a catch map, but its accessor
    # call precedes the state-0 transition proven by the instruction facts.
    check_funcinfo(0x005F05FC,
                   (FUNCINFO_MAGIC, 1, 0x005F05F4, 0, 0, 0, 0),
                   "tls-helper-funcinfo",
                   "TLS helper FuncInfo has zero try blocks (cleanup/unwind metadata only).")
    check_funcinfo(0x005EF4DC,
                   (FUNCINFO_MAGIC, 2, 0x005EF498, 1, 0x005EF4A8, 0, 0),
                   "validator-funcinfo",
                   "Picker validation helper has one local try-block map.")
    validation_try = raw(0x005EF4A8, 20)
    require(struct.unpack("<5I", validation_try) == (0, 0, 1, 2, 0x005EF4BC),
            "validator try-block map changed")
    emit(0x005EF4A8, validation_try, "validator-try-block-map",
         "Validator catch covers EH state 0 and has two handlers; TLS call at 0x0047C32E is before the state transition at 0x0047C350.",
         "static EH metadata paired with exact call/state instruction bytes")
    for handler_va, expected_type, disp, target in (
            (0x005EF4BC, 0x00607540, -0x30, 0x0047C377),
            (0x005EF4CC, 0x00619F3C, -0x1C, 0x0047C37F)):
        handler = raw(handler_va, 16)
        fields = struct.unpack("<4I", handler)
        expected = (0, expected_type, disp & 0xFFFFFFFF, target)
        require(fields == expected, f"validator HandlerType at 0x{handler_va:08X} changed: {fields!r}")
        emit(handler_va, handler, "validator-handler-type",
             f"Validator handler type at 0x{handler_va:08X} targets 0x{target:08X}.",
             "static catch table; the accessor call is outside the mapped active try state")

    check_funcinfo(0x005EF910,
                   (FUNCINFO_MAGIC, 2, 0x005EF8EC, 1, 0x005EF8FC, 0, 0),
                   "modal-wrapper-funcinfo",
                   "Modal wrapper has one C++ try-block map covering EH state 0.")
    modal_try = raw(0x005EF8FC, 20)
    require(struct.unpack("<5I", modal_try) == (0, 0, 1, 1, 0x005EF8DC),
            "modal-wrapper try-block map changed")
    emit(0x005EF8FC, modal_try, "modal-wrapper-try-block-map",
         "Wrapper try interval is state 0 through state 0; one handler record is at 0x005EF8DC.",
         "static EH metadata; active-state relationship is verified by instructions at 0x004812CD and 0x0048130E")
    modal_handler = raw(0x005EF8DC, 16)
    modal_handler_fields = struct.unpack("<4I", modal_handler)
    require(modal_handler_fields == (0, 0x00619F3C, 0xFFFFFFD0, 0x00481331),
            f"modal-wrapper handler changed: {modal_handler_fields!r}")
    emit(0x005EF8DC, modal_handler, "modal-wrapper-handler-type",
         "Handler catches CException* into [ebp-0x30] and enters 0x00481331.",
         "static catch table; compatibility is based on the ThrowInfo catchable-type array")

    check_funcinfo(0x006019B8,
                   (FUNCINFO_MAGIC, 3, 0x006019A0, 0, 0, 0, 0),
                   "picker-parent-funcinfo",
                   "Picker parent FuncInfo has zero try blocks; its handler metadata is cleanup/unwind only.")

    imports = {
        entry.address: (library.dll.decode(errors="replace"),
                        entry.name.decode(errors="replace") if entry.name else "")
        for library in pe.DIRECTORY_ENTRY_IMPORT for entry in library.imports
    }
    require(imports.get(0x005A62A4) == ("KERNEL32.dll", "RaiseException"),
            f"RaiseException IAT mapping changed: {imports.get(0x005A62A4)!r}")
    emit(0x005A62A4, b"", "raise-exception-import",
         "IAT slot 0x005A62A4 resolves to KERNEL32.dll!RaiseException.",
         "static import table; API invocation, exception dispatch, and catch execution unobserved")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("binary_sha256", "evidence_va", "bytes", "stage", "observation", "scope"))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Verified hash-pinned TLS throw metadata and modal recovery route; wrote {len(rows)} evidence rows.")
    print("Static conclusion: the modal wrapper has a matching CException* catch active around its modal-loop call, which sets result -1; the picker parent routes non-1 to cleanup.")
    print("Runtime exception occurrence, dispatch, and handler execution are unobserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
