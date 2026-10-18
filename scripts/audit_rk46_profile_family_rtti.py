#!/usr/bin/env python3
"""Verify the V4.6 profile selector's constructed class via PE RTTI.

Reads only the extracted V4.6-labeled DeviceDriver.exe and the selector map
derived from models-4.6.json. It performs no device I/O and never executes RK
software. The input PE hash is pinned so the static addresses cannot silently
be reused against another build.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from collections import Counter
from pathlib import Path

import pefile


EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"

# The Fw=0 branch first initializes the common CHidDev base, then replaces
# its vtable in the selector. Nonzero constructors install their class vtables.
ROUTES = {
    "0x0040D640": {
        "install_site": 0x0041655B,
        "vtable_va": 0x005D410C,
        "class_name": "CDevRKKB",
        "class_evidence": "selector branch calls CHidDev base initializer then overwrites its vtable with CDevRKKB",
        "protocol_boundary": "This pass proves class routing only; V4.6 RKKB method semantics are not fully crosswalked.",
    },
    "0x0040F490": {
        "install_site": 0x0040F4C3,
        "vtable_va": 0x005D3D0C,
        "class_name": "CDevG5KB",
        "class_evidence": "profile constructor writes derived vtable",
        "protocol_boundary": "V4.6 screen/GIF path maps G5 slots +0x54/+0x58; all-feature protocol mapping remains incomplete.",
    },
    "0x0040DAD0": {
        "install_site": 0x0040DB03,
        "vtable_va": 0x005D2464,
        "class_name": "CDev3632",
        "class_evidence": "dedicated Fw=3 constructor writes derived vtable",
        "protocol_boundary": "V4.6 20-byte request/read/write transport is mapped; selector meanings remain unresolved.",
    },
}


def read_va(pe: pefile.PE, data: bytes, va: int, size: int) -> bytes:
    return data[pe.get_offset_from_rva(va - pe.OPTIONAL_HEADER.ImageBase) :][:size]


def read_u32(pe: pefile.PE, data: bytes, va: int) -> int:
    raw = read_va(pe, data, va, 4)
    if len(raw) != 4:
        raise ValueError(f"truncated PE data at VA 0x{va:08X}")
    return int.from_bytes(raw, "little")


def read_c_string(pe: pefile.PE, data: bytes, va: int) -> str:
    raw = read_va(pe, data, va, 512).split(b"\0", 1)[0]
    return raw.decode("ascii", errors="replace")


def read_class_rtti(pe: pefile.PE, data: bytes, vtable_va: int) -> tuple[str, list[str]]:
    # MSVC x86 vftable[-1] points to a Complete Object Locator.
    col_va = read_u32(pe, data, vtable_va - 4)
    signature, _offset, _cd_offset, type_va, hierarchy_va = (
        read_u32(pe, data, col_va + offset) for offset in (0, 4, 8, 12, 16)
    )
    if signature != 0:
        raise ValueError(f"unexpected x86 COL signature at 0x{col_va:08X}: {signature}")
    type_name = read_c_string(pe, data, type_va + 8)
    if not (type_name.startswith(".?AV") and type_name.endswith("@@")):
        raise ValueError(f"unexpected type descriptor at 0x{type_va:08X}: {type_name!r}")
    class_name = type_name[4:-2]

    count = read_u32(pe, data, hierarchy_va + 8)
    base_array_va = read_u32(pe, data, hierarchy_va + 12)
    if count == 0 or count > 32:
        raise ValueError(f"unexpected base-class count {count} at 0x{hierarchy_va:08X}")
    bases: list[str] = []
    for index in range(count):
        descriptor_va = read_u32(pe, data, base_array_va + index * 4)
        base_type_va = read_u32(pe, data, descriptor_va)
        base_type = read_c_string(pe, data, base_type_va + 8)
        if not (base_type.startswith(".?AV") and base_type.endswith("@@")):
            raise ValueError(f"unexpected base type at 0x{base_type_va:08X}: {base_type!r}")
        bases.append(base_type[4:-2])
    return class_name, bases


def validate_install_site(pe: pefile.PE, data: bytes, route: dict[str, object]) -> None:
    site = int(route["install_site"])
    vtable = int(route["vtable_va"])
    expected = b"\xC7"  # mov r/m32, imm32; exact ModRM varies by route.
    raw = read_va(pe, data, site, 6)
    if raw[:1] != expected or int.from_bytes(raw[2:6], "little") != vtable:
        raise ValueError(
            f"vtable install mismatch at 0x{site:08X}: got {raw.hex(' ')}, "
            f"expected a C7 / imm32 write of 0x{vtable:08X}"
        )


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--driver",
        type=Path,
        default=root.parent / ".research" / "rk4_6_official_extract_20261015" / "app" / "DeviceDriver.exe",
    )
    parser.add_argument(
        "--selector-map",
        type=Path,
        default=root / "docs" / "rk-v4.6-profile-selector-map.csv",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "docs" / "rk-v4.6-profile-family-rtti-map.csv",
    )
    args = parser.parse_args()

    data = args.driver.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"DeviceDriver.exe hash mismatch: {digest}")
    pe = pefile.PE(data=data, fast_load=False)
    if pe.OPTIONAL_HEADER.ImageBase != 0x00400000:
        raise SystemExit(f"unexpected image base: 0x{pe.OPTIONAL_HEADER.ImageBase:08X}")

    for constructor, route in ROUTES.items():
        validate_install_site(pe, data, route)
        class_name, bases = read_class_rtti(pe, data, int(route["vtable_va"]))
        if class_name != route["class_name"]:
            raise SystemExit(f"constructor {constructor} vtable RTTI is {class_name}, expected {route['class_name']}")
        if "CHidDev" not in bases:
            raise SystemExit(f"{class_name} RTTI does not list CHidDev among its bases: {bases}")
        route["base_class"] = "CHidDev"

    with args.selector_map.open(newline="", encoding="utf-8-sig") as stream:
        selector_rows = list(csv.DictReader(stream))

    rows: list[dict[str, str]] = []
    for profile in selector_rows:
        constructor = profile["implementation_constructor_va"]
        route = ROUTES.get(constructor)
        if route is None:
            raise SystemExit(f"unmapped constructor for profile {profile['profile_code']}: {constructor}")
        rows.append(
            {
                "profile_code": profile["profile_code"],
                "model_name": profile["model_name"],
                "usb_vid": profile["usb_vid"],
                "usb_pid": profile["usb_pid"],
                "fw_raw_kb_ini": profile["fw_raw_kb_ini"],
                "selector_branch": profile["selector_branch"],
                "descriptor_gate": profile["descriptor_gate"],
                "selector_constructor_or_base_initializer_va": constructor,
                "vtable_install_site_va": f"0x{int(route['install_site']):08X}",
                "family_vtable_va": f"0x{int(route['vtable_va']):08X}",
                "rtti_class": str(route["class_name"]),
                "rtti_base": str(route["base_class"]),
                "class_evidence": str(route["class_evidence"]),
                "protocol_evidence_boundary": str(route["protocol_boundary"]),
                "physical_compatibility_validated": "no",
            }
        )

    if len(rows) != 265 or any(row["direct_pid_profile"] == "false" for row in selector_rows):
        raise SystemExit(f"unexpected selector catalog coverage: {len(rows)} rows")
    counts = Counter(row["rtti_class"] for row in rows)
    expected_counts = Counter({"CDevRKKB": 133, "CDevG5KB": 131, "CDev3632": 1})
    if counts != expected_counts:
        raise SystemExit(f"unexpected route counts: {counts}; expected {expected_counts}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"verified hash {digest}; wrote {len(rows)} profile rows to {args.output}")
    print(", ".join(f"{name}={count}" for name, count in sorted(counts.items())))


if __name__ == "__main__":
    main()
