#!/usr/bin/env python3
"""Statically inspect the UDIF/APFS wrapper and carve validated Mach-O slices.

This script uses Python's standard library only. It never mounts the DMG, runs
vendor code, accesses a device, or writes the reconstructed APFS partition to a
persistent location. The temporary partition image is deleted on exit.

The Mach-O records are physical APFS-block candidates; APFS file paths are not
recovered by this script and must not be inferred from those offsets.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
import plistlib
import struct
import tempfile
import uuid
import zlib
from pathlib import Path
from typing import BinaryIO


AUDIT_DATE = "2026-10-19"
UDIF_RUNS_OFFSET = 0xCC
UDIF_RUN_SIZE = 40
UDIF_TERMINATOR = 0xFFFFFFFF
UDIF_ZLIB = 0x80000005
UDIF_RAW = 0x00000001
UDIF_ZERO = 0x00000002
SECTOR_SIZE = 512

MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe": "<",  # MH_MAGIC_64, little endian
    b"\xfe\xed\xfa\xcf": ">",  # MH_CIGAM_64, big endian
    b"\xce\xfa\xed\xfe": "<",  # MH_MAGIC, little endian
    b"\xfe\xed\xfa\xce": ">",  # MH_CIGAM, big endian
}
FAT_MAGICS = {
    b"\xca\xfe\xba\xbe": (">", False),  # FAT_MAGIC
    b"\xca\xfe\xba\xbf": (">", True),   # FAT_MAGIC_64
}
CPU_NAMES = {
    7: "i386",
    12: "arm",
    0x01000007: "x86_64",
    0x0100000C: "arm64",
    0x0100000D: "arm64_32",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _plist_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return bytes.fromhex(value)
    raise TypeError(f"Unexpected blkx Data value: {type(value).__name__}")


def read_dmg(path: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    size = path.stat().st_size
    with path.open("rb") as stream:
        if size < 512:
            raise ValueError("DMG is shorter than its 512-byte trailer")
        stream.seek(-512, 2)
        trailer = stream.read(512)
        if trailer[:4] != b"koly":
            raise ValueError("Missing UDIF koly trailer")
        version, header_size, flags = struct.unpack_from(">III", trailer, 4)
        data_fork_offset, data_fork_length = struct.unpack_from(">QQ", trailer, 24)
        resource_fork_offset, resource_fork_length = struct.unpack_from(">QQ", trailer, 40)
        segment_number, segment_count = struct.unpack_from(">II", trailer, 56)
        xml_offset, xml_length = struct.unpack_from(">QQ", trailer, 216)
        if xml_offset + xml_length > size - 512:
            raise ValueError("UDIF XML resource fork lies outside the pre-trailer file")
        stream.seek(xml_offset)
        plist_root = plistlib.loads(stream.read(xml_length))

    resource_fork = plist_root.get("resource-fork", {})
    blkx_rows: list[dict[str, object]] = []
    for entry in resource_fork.get("blkx", []):
        data = _plist_bytes(entry["Data"])
        if data[:4] != b"mish":
            raise ValueError(f"Unsupported blkx signature for ID {entry.get('ID')!r}")
        first_sector, sector_count, data_start = struct.unpack_from(">QQQ", data, 8)
        buffer_requested, descriptor = struct.unpack_from(">II", data, 32)
        records: list[tuple[int, int, int, int, int, int]] = []
        offset = UDIF_RUNS_OFFSET
        while offset + UDIF_RUN_SIZE <= len(data):
            record = struct.unpack_from(">IIQQQQ", data, offset)
            records.append(record)
            offset += UDIF_RUN_SIZE
            if record[0] == UDIF_TERMINATOR:
                break
        blkx_rows.append({
            "id": str(entry.get("ID", "")),
            "name": str(entry.get("CFName", "")),
            "data": data,
            "first_sector": first_sector,
            "sector_count": sector_count,
            "data_start": data_start,
            "buffer_requested": buffer_requested,
            "descriptor": descriptor,
            "records": records,
        })

    header = {
        "file_size": size,
        "version": version,
        "header_size": header_size,
        "flags": flags,
        "data_fork_offset": data_fork_offset,
        "data_fork_length": data_fork_length,
        "resource_fork_offset": resource_fork_offset,
        "resource_fork_length": resource_fork_length,
        "segment_number": segment_number,
        "segment_count": segment_count,
        "xml_offset": xml_offset,
        "xml_length": xml_length,
        "plist_keys": sorted(resource_fork.keys()),
    }
    return header, blkx_rows


def write_block_map(rows: list[dict[str, object]], output: Path) -> int:
    fields = [
        "blkx_id", "name", "entry_first_sector", "entry_sector_count",
        "record_index", "record_type", "record_sector_start",
        "record_sector_count", "source_data_offset", "source_data_length",
        "logical_bytes",
    ]
    count = 0
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for entry in rows:
            for index, rec in enumerate(entry["records"]):
                run_type, _reserved, sector, sectors, offset, length = rec
                writer.writerow({
                    "blkx_id": entry["id"],
                    "name": entry["name"],
                    "entry_first_sector": entry["first_sector"],
                    "entry_sector_count": entry["sector_count"],
                    "record_index": index,
                    "record_type": f"0x{run_type:08X}",
                    "record_sector_start": sector,
                    "record_sector_count": sectors,
                    "source_data_offset": offset,
                    "source_data_length": length,
                    "logical_bytes": sectors * SECTOR_SIZE,
                })
                count += 1
    return count


def materialize_partition(
    source: BinaryIO,
    data_fork_offset: int,
    entry: dict[str, object],
    output: BinaryIO,
) -> tuple[int, int]:
    expected_length = int(entry["sector_count"]) * SECTOR_SIZE
    output.truncate(expected_length)
    next_sector = 0
    run_counts = {"zlib": 0, "raw": 0, "zero": 0}
    for run_type, _reserved, sector, sectors, data_offset, data_length in entry["records"]:
        if run_type == UDIF_TERMINATOR:
            break
        logical_length = sectors * SECTOR_SIZE
        if sector != next_sector:
            raise ValueError(f"Non-contiguous APFS block map at sector {sector}; expected {next_sector}")
        if run_type == UDIF_ZLIB:
            source.seek(data_fork_offset + data_offset)
            block = zlib.decompress(source.read(data_length))
            if len(block) != logical_length:
                raise ValueError(f"zlib output size mismatch at sector {sector}")
            output.seek(sector * SECTOR_SIZE)
            output.write(block)
            run_counts["zlib"] += 1
        elif run_type == UDIF_RAW:
            source.seek(data_fork_offset + data_offset)
            block = source.read(data_length)
            if len(block) != logical_length:
                raise ValueError(f"raw output size mismatch at sector {sector}")
            output.seek(sector * SECTOR_SIZE)
            output.write(block)
            run_counts["raw"] += 1
        elif run_type == UDIF_ZERO:
            if data_length != 0:
                raise ValueError(f"Unexpected payload for UDIF type 0x2 at sector {sector}")
            # The already-truncated output file supplies zeros for this sparse run.
            run_counts["zero"] += 1
        else:
            raise ValueError(f"Unsupported APFS block-map run type 0x{run_type:08X}")
        next_sector = sector + sectors
    if next_sector != int(entry["sector_count"]):
        raise ValueError(f"APFS block map ends at {next_sector}, expected {entry['sector_count']}")
    output.flush()
    return expected_length, run_counts["zlib"] + run_counts["raw"] + run_counts["zero"]


def version_string(value: int) -> str:
    return f"{(value >> 16) & 0xFFFF}.{(value >> 8) & 0xFF}.{value & 0xFF}"


def parse_thin_macho(
    image: mmap.mmap,
    offset: int,
    slice_limit: int | None = None,
) -> dict[str, object] | None:
    limit = len(image) if slice_limit is None else min(len(image), slice_limit)
    if offset < 0 or offset + 28 > limit:
        return None
    magic = image[offset:offset + 4]
    endian = MACHO_MAGICS.get(magic)
    if endian is None:
        return None
    is_64 = magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
    header_size = 32 if is_64 else 28
    if offset + header_size > limit:
        return None
    fields = struct.unpack_from(endian + ("8I" if is_64 else "7I"), image, offset)
    _magic, cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags = fields[:7]
    if not (1 <= ncmds <= 2048 and 8 <= sizeofcmds <= 16 * 1024 * 1024):
        return None
    cmd_start = offset + header_size
    cmd_end = cmd_start + sizeofcmds
    if cmd_end > limit:
        return None

    dylibs: list[str] = []
    rpaths: list[str] = []
    minimum_os: list[str] = []
    platform: list[str] = []
    symtab: tuple[int, int, int, int] | None = None
    pos = cmd_start
    for _ in range(ncmds):
        if pos + 8 > cmd_end:
            return None
        command, command_size = struct.unpack_from(endian + "II", image, pos)
        if command_size < 8 or pos + command_size > cmd_end:
            return None
        base_command = command & 0x7FFFFFFF
        if base_command in (0xC, 0xD, 0x18, 0x1F, 0x20, 0x23) and command_size >= 24:
            name_offset = struct.unpack_from(endian + "I", image, pos + 8)[0]
            if 0 <= name_offset < command_size:
                name = image[pos + name_offset:pos + command_size].split(b"\0", 1)[0]
                dylibs.append(name.decode("utf-8", "replace"))
        elif base_command == 0x1C and command_size >= 12:  # LC_RPATH
            name_offset = struct.unpack_from(endian + "I", image, pos + 8)[0]
            if 0 <= name_offset < command_size:
                name = image[pos + name_offset:pos + command_size].split(b"\0", 1)[0]
                rpaths.append(name.decode("utf-8", "replace"))
        elif base_command == 0x32 and command_size >= 24:  # LC_BUILD_VERSION
            build_platform, min_os, sdk, _tools = struct.unpack_from(endian + "IIII", image, pos + 8)
            platform.append(f"platform={build_platform},min={version_string(min_os)},sdk={version_string(sdk)}")
        elif base_command == 0x24 and command_size >= 16:  # LC_VERSION_MIN_MACOSX
            min_os, sdk = struct.unpack_from(endian + "II", image, pos + 8)
            minimum_os.append(f"min={version_string(min_os)},sdk={version_string(sdk)}")
        elif base_command == 0x2 and command_size >= 24:  # LC_SYMTAB
            symtab = struct.unpack_from(endian + "IIII", image, pos + 8)
        pos += command_size
    if pos != cmd_end:
        return None
    if file_type not in range(1, 13):
        return None
    undefined_symbols: list[dict[str, object]] = []
    if symtab is not None:
        symbol_offset, symbol_count, string_offset, string_size = symtab
        entry_size = 16 if is_64 else 12
        table_start = offset + symbol_offset
        table_end = table_start + symbol_count * entry_size
        strings_start = offset + string_offset
        strings_end = strings_start + string_size
        if table_start < offset or table_end > limit or strings_start < offset or strings_end > limit:
            return None
        for index in range(symbol_count):
            entry_offset = table_start + index * entry_size
            if is_64:
                string_index, symbol_type, _section, _desc, _value = struct.unpack_from(
                    endian + "IBBHQ", image, entry_offset
                )
            else:
                string_index, symbol_type, _section, _desc, _value = struct.unpack_from(
                    endian + "IBBHI", image, entry_offset
                )
            # N_UNDF with N_EXT: an externally undefined symbol reference.
            if (symbol_type & 0x0E) != 0 or (symbol_type & 0x01) == 0 or string_index >= string_size:
                continue
            name_offset = strings_start + string_index
            nul = image.find(b"\0", name_offset, strings_end)
            if nul < 0:
                return None
            undefined_symbols.append({
                "symbol_index": index,
                "symbol_table_entry_offset": entry_offset,
                "name": image[name_offset:nul].decode("utf-8", "replace"),
            })
    return {
        "offset": offset,
        "bits": 64 if is_64 else 32,
        "cpu_type": cpu_type,
        "cpu_subtype": cpu_subtype,
        "architecture": CPU_NAMES.get(cpu_type, f"cpu-0x{cpu_type:08x}"),
        "file_type": file_type,
        "ncmds": ncmds,
        "flags": flags,
        "dylibs": dylibs,
        "rpaths": rpaths,
        "minimum_os": minimum_os,
        "platform": platform,
        "symbol_table": symtab,
        "undefined_symbols": undefined_symbols,
    }


def find_universal_macho(image: mmap.mmap) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for magic, (endian, is_64) in FAT_MAGICS.items():
        offset = 0
        while True:
            fat_offset = image.find(magic, offset)
            if fat_offset < 0:
                break
            offset = fat_offset + 1
            if fat_offset + 8 > len(image):
                continue
            _magic, count = struct.unpack_from(endian + "II", image, fat_offset)
            if not (1 <= count <= 32):
                continue
            entry_size = 32 if is_64 else 20
            if fat_offset + 8 + count * entry_size > len(image):
                continue
            slices: list[dict[str, object]] = []
            valid = True
            for index in range(count):
                pos = fat_offset + 8 + index * entry_size
                if is_64:
                    cpu, subtype, relative_offset, size, align, _reserved = struct.unpack_from(endian + "IIQQII", image, pos)
                else:
                    cpu, subtype, relative_offset, size, align = struct.unpack_from(endian + "IIIII", image, pos)
                if align > 31 or size == 0 or relative_offset + size > len(image) - fat_offset:
                    valid = False
                    break
                thin = parse_thin_macho(
                    image,
                    fat_offset + relative_offset,
                    fat_offset + relative_offset + size,
                )
                if thin is None or thin["cpu_type"] != cpu:
                    valid = False
                    break
                thin.update({
                    "fat_offset": fat_offset,
                    "fat_magic": magic.hex(),
                    "fat_arch_count": count,
                    "slice_index": index,
                    "slice_relative_offset": relative_offset,
                    "slice_size": size,
                    "alignment_exponent": align,
                    "slice_offset": fat_offset + relative_offset,
                })
                slices.append(thin)
            if valid and len(slices) == count:
                candidates.append({
                    "fat_offset": fat_offset,
                    "fat_magic": magic.hex(),
                    "fat_arch_count": count,
                    "slices": slices,
                })
    return candidates


def write_slices(candidates: list[dict[str, object]], output: Path) -> int:
    fields = [
        "fat_offset_apfs_partition", "container_block", "fat_magic", "fat_arch_count",
        "slice_index", "architecture", "cpu_type", "cpu_subtype",
        "slice_relative_offset", "slice_offset_apfs_partition", "slice_size",
        "alignment_exponent", "file_type", "load_command_count", "linked_dylibs",
        "rpaths", "minimum_macos", "build_platforms", "undefined_external_symbol_count",
    ]
    count = 0
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for candidate in candidates:
            for item in candidate["slices"]:
                writer.writerow({
                    "fat_offset_apfs_partition": candidate["fat_offset"],
                    "container_block": candidate["fat_offset"] // 4096,
                    "fat_magic": candidate["fat_magic"],
                    "fat_arch_count": candidate["fat_arch_count"],
                    "slice_index": item["slice_index"],
                    "architecture": item["architecture"],
                    "cpu_type": f"0x{item['cpu_type']:08X}",
                    "cpu_subtype": f"0x{item['cpu_subtype']:08X}",
                    "slice_relative_offset": item["slice_relative_offset"],
                    "slice_offset_apfs_partition": item["slice_offset"],
                    "slice_size": item["slice_size"],
                    "alignment_exponent": item["alignment_exponent"],
                    "file_type": item["file_type"],
                    "load_command_count": item["ncmds"],
                    "linked_dylibs": "; ".join(item["dylibs"]),
                    "rpaths": "; ".join(item["rpaths"]),
                    "minimum_macos": "; ".join(item["minimum_os"]),
                    "build_platforms": "; ".join(item["platform"]),
                    "undefined_external_symbol_count": len(item["undefined_symbols"]),
                })
                count += 1
    return count


def write_symbols(candidates: list[dict[str, object]], output: Path) -> int:
    fields = [
        "fat_offset_apfs_partition", "slice_index", "architecture",
        "slice_offset_apfs_partition", "symbol_index",
        "symbol_table_entry_apfs_offset", "symbol",
    ]
    count = 0
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for candidate in candidates:
            for item in candidate["slices"]:
                for symbol in item["undefined_symbols"]:
                    writer.writerow({
                        "fat_offset_apfs_partition": candidate["fat_offset"],
                        "slice_index": item["slice_index"],
                        "architecture": item["architecture"],
                        "slice_offset_apfs_partition": item["slice_offset"],
                        "symbol_index": symbol["symbol_index"],
                        "symbol_table_entry_apfs_offset": symbol["symbol_table_entry_offset"],
                        "symbol": symbol["name"],
                    })
                    count += 1
    return count


def inspect_apfs_partition(
    source_path: Path,
    header: dict[str, object],
    entry: dict[str, object],
) -> dict[str, object]:
    with source_path.open("rb") as source, tempfile.TemporaryFile(mode="w+b") as partition:
        partition_length, supported_run_count = materialize_partition(
            source, int(header["data_fork_offset"]), entry, partition
        )
        partition.seek(0)
        superblock = partition.read(256)
        if superblock[32:36] != b"NXSB":
            raise ValueError("Reconstructed partition does not start with an APFS NXSB superblock")
        block_size = struct.unpack_from("<I", superblock, 36)[0]
        block_count = struct.unpack_from("<Q", superblock, 40)[0]
        features, readonly_compat, incompat = struct.unpack_from("<QQQ", superblock, 48)
        container_uuid = str(uuid.UUID(bytes=superblock[72:88]))
        if block_size == 0 or block_size & (block_size - 1):
            raise ValueError(f"Invalid APFS block size {block_size}")

        digest = hashlib.sha256()
        partition.seek(0)
        for chunk in iter(lambda: partition.read(1024 * 1024), b""):
            digest.update(chunk)

        apsb_blocks: list[int] = []
        partition.seek(0)
        block_index = 0
        for block in iter(lambda: partition.read(block_size), b""):
            if len(block) == block_size and block[32:36] == b"APSB":
                apsb_blocks.append(block_index)
            block_index += 1
        partition.seek(0)
        with mmap.mmap(partition.fileno(), 0, access=mmap.ACCESS_READ) as image:
            fat_candidates = find_universal_macho(image)

        return {
            "partition_bytes": partition_length,
            "partition_sha256": digest.hexdigest(),
            "apfs_magic": "NXSB",
            "apfs_superblock_magic_offset": 32,
            "apfs_block_size": block_size,
            "apfs_block_count": block_count,
            "apfs_features_raw": f"0x{features:X}",
            "apfs_readonly_compat_features_raw": f"0x{readonly_compat:X}",
            "apfs_incompat_features_raw": f"0x{incompat:X}",
            "apfs_container_uuid": container_uuid,
            "aligned_APSB_signature_blocks": apsb_blocks,
            "universal_macho_candidates": fat_candidates,
            "supported_partition_run_count": supported_run_count,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dmg", type=Path, help="path to the official F99 Mac DMG")
    parser.add_argument("--out-dir", type=Path, required=True, help="directory for CSV ledgers")
    args = parser.parse_args()
    source_path = args.dmg.resolve()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    header, entries = read_dmg(source_path)
    block_csv = out_dir / f"rk-f99-macos-dmg-block-map-{AUDIT_DATE}.csv"
    macho_csv = out_dir / f"rk-f99-macos-mach-o-slices-{AUDIT_DATE}.csv"
    symbols_csv = out_dir / f"rk-f99-macos-mach-o-undefined-symbols-{AUDIT_DATE}.csv"
    block_row_count = write_block_map(entries, block_csv)
    apfs_entry = next((entry for entry in entries if "Apple_APFS" in str(entry["name"])), None)
    if apfs_entry is None:
        raise ValueError("No Apple_APFS blkx partition found")
    apfs = inspect_apfs_partition(source_path, header, apfs_entry)
    macho_row_count = write_slices(apfs["universal_macho_candidates"], macho_csv)
    symbol_row_count = write_symbols(apfs["universal_macho_candidates"], symbols_csv)
    summary = {
        "source_name": source_path.name,
        "source_size": header["file_size"],
        "source_sha256": sha256_file(source_path),
        "udif": header,
        "blkx_entry_count": len(entries),
        "block_map_csv": str(block_csv),
        "block_map_rows": block_row_count,
        "apfs_partition": {
            "name": apfs_entry["name"],
            "id": apfs_entry["id"],
            "first_disk_sector": apfs_entry["first_sector"],
            "sector_count": apfs_entry["sector_count"],
            **{key: value for key, value in apfs.items() if key != "universal_macho_candidates"},
        },
        "universal_macho_csv": str(macho_csv),
        "universal_macho_rows": macho_row_count,
        "undefined_symbol_csv": str(symbols_csv),
        "undefined_symbol_rows": symbol_row_count,
        "universal_macho_candidates": [
            {
                "fat_offset_apfs_partition": candidate["fat_offset"],
                "fat_arch_count": candidate["fat_arch_count"],
                "slices": [
                    {
                        "architecture": item["architecture"],
                        "slice_offset_apfs_partition": item["slice_offset"],
                        "slice_size": item["slice_size"],
                        "file_type": item["file_type"],
                        "linked_dylib_count": len(item["dylibs"]),
                        "undefined_external_symbol_count": len(item["undefined_symbols"]),
                    }
                    for item in candidate["slices"]
                ],
            }
            for candidate in apfs["universal_macho_candidates"]
        ],
        "limitations": [
            "The script does not parse APFS B-trees or recover file paths/assets.",
            "Mach-O offsets are physical positions in the reconstructed APFS partition, not file offsets.",
            "Linked dylib load commands do not enumerate dynamically resolved API usage.",
            "Static findings do not establish runtime behavior.",
        ],
    }
    print(json.dumps(summary, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
