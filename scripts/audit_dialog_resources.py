#!/usr/bin/env python3
"""Inventory Win32 dialog-template resources in an RK package snapshot.

This parser reads PE resource bytes only. It never executes an RK binary or
communicates with a keyboard. Requires pefile (see requirements-audit.txt).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import struct
from pathlib import Path
from typing import Any

try:
    import pefile
except ImportError as exc:  # pragma: no cover - environment-specific message
    raise SystemExit("Install audit dependencies with: python -m pip install -r requirements-audit.txt") from exc


RT_DIALOG = 5
DS_SETFONT = 0x00000040
STANDARD_CLASSES = {
    0x80: "BUTTON",
    0x81: "EDIT",
    0x82: "STATIC",
    0x83: "LISTBOX",
    0x84: "SCROLLBAR",
    0x85: "COMBOBOX",
}
PE_NAMES = (
    Path("DeviceDriver.exe"),
    Path("Dev/01AF/Update.exe"),
    Path("InitSetup.dll"),
    Path("unins000.exe"),
    Path("uninstall.dll"),
)


class Cursor:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def _unpack(self, fmt: str) -> tuple[Any, ...]:
        size = struct.calcsize(fmt)
        if self.pos + size > len(self.data):
            raise ValueError(f"truncated template at 0x{self.pos:X}")
        values = struct.unpack_from(fmt, self.data, self.pos)
        self.pos += size
        return values

    def word(self) -> int:
        return self._unpack("<H")[0]

    def dword(self) -> int:
        return self._unpack("<I")[0]

    def short(self) -> int:
        return self._unpack("<h")[0]

    def align(self, boundary: int = 4) -> None:
        self.pos = (self.pos + boundary - 1) & ~(boundary - 1)
        if self.pos > len(self.data):
            raise ValueError("alignment exceeds template size")

    def ordinal_or_string(self) -> str:
        first = self.word()
        if first == 0:
            return ""
        if first == 0xFFFF:
            return f"#{self.word()}"
        units = [first]
        while True:
            unit = self.word()
            if unit == 0:
                break
            units.append(unit)
        return bytes().join(unit.to_bytes(2, "little") for unit in units).decode("utf-16le", errors="replace")


def parse_dialog(data: bytes) -> dict[str, Any]:
    cur = Cursor(data)
    first_word = cur.word()
    second_word = cur.word()
    extended = first_word == 1 and second_word == 0xFFFF
    if extended:
        help_id = cur.dword()
        ex_style = cur.dword()
        style = cur.dword()
        item_count = cur.word()
        rect = [cur.short() for _ in range(4)]
    else:
        cur.pos = 0
        style = cur.dword()
        ex_style = cur.dword()
        item_count = cur.word()
        rect = [cur.short() for _ in range(4)]
        help_id = ""

    menu = cur.ordinal_or_string()
    window_class = cur.ordinal_or_string()
    title = cur.ordinal_or_string()
    font = ""
    if style & DS_SETFONT:
        point_size = cur.word()
        if extended:
            weight = cur.word()
            italic = cur._unpack("<B")[0]
            charset = cur._unpack("<B")[0]
            font_name = cur.ordinal_or_string()
            font = f"{font_name}; pt={point_size}; weight={weight}; italic={italic}; charset={charset}"
        else:
            font_name = cur.ordinal_or_string()
            font = f"{font_name}; pt={point_size}"

    dialog = {
        "extended": extended,
        "help_id": help_id,
        "style": style,
        "ex_style": ex_style,
        "item_count": item_count,
        "rect": rect,
        "menu": menu,
        "window_class": window_class,
        "title": title,
        "font": font,
        "controls": [],
    }

    cur.align()
    for index in range(item_count):
        if extended:
            control_help = cur.dword()
            control_ex_style = cur.dword()
            control_style = cur.dword()
            control_rect = [cur.short() for _ in range(4)]
            control_id = cur.dword()
        else:
            control_style = cur.dword()
            control_ex_style = cur.dword()
            control_rect = [cur.short() for _ in range(4)]
            control_id = cur.word()
            control_help = ""
        control_class = cur.ordinal_or_string()
        if control_class.startswith("#"):
            ordinal = int(control_class[1:])
            control_class = STANDARD_CLASSES.get(ordinal, control_class)
        caption = cur.ordinal_or_string()
        extra_size = cur.word()
        if extra_size:
            if cur.pos + extra_size > len(data):
                raise ValueError(f"control {index} creation data exceeds template")
            cur.pos += extra_size
        dialog["controls"].append({
            "index": index,
            "id": control_id,
            "class": control_class,
            "caption": caption,
            "style": control_style,
            "ex_style": control_ex_style,
            "help_id": control_help,
            "rect": control_rect,
        })
        if index + 1 < item_count:
            cur.align()
    dialog["bytes_consumed"] = cur.pos
    return dialog


def entry_name(entry: Any) -> str:
    return str(entry.name) if entry.name is not None else str(entry.id)


def collect_dialogs(rk_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for relative in PE_NAMES:
        path = rk_root / relative
        if not path.is_file():
            continue
        pe = pefile.PE(str(path), fast_load=False)
        try:
            resource_root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
            if resource_root is None:
                continue
            for type_entry in resource_root.entries:
                if type_entry.id != RT_DIALOG:
                        continue
                for name_entry in type_entry.directory.entries:
                    for language_entry in name_entry.directory.entries:
                        resource = language_entry.data.struct
                        data = pe.get_data(resource.OffsetToData, resource.Size)
                        base = {
                            "binary": str(relative).replace("\\", "/"),
                            "resource_id": entry_name(name_entry),
                            "language_id": language_entry.id,
                        }
                        try:
                            dialog = parse_dialog(data)
                        except (IndexError, ValueError, struct.error) as exc:
                            rows.append({**base, "record_type": "parse_error", "parse_status": str(exc)})
                            continue
                        common = {
                            **base,
                            "dialog_format": "DLGTEMPLATEEX" if dialog["extended"] else "DLGTEMPLATE",
                            "dialog_title": dialog["title"],
                            "dialog_window_class": dialog["window_class"],
                            "dialog_style_hex": f"0x{dialog['style']:08X}",
                            "dialog_ex_style_hex": f"0x{dialog['ex_style']:08X}",
                            "dialog_rect": ",".join(map(str, dialog["rect"])),
                            "dialog_font": dialog["font"],
                            "declared_control_count": dialog["item_count"],
                            "parse_status": f"parsed {len(dialog['controls'])} controls; consumed {dialog['bytes_consumed']}/{len(data)} bytes",
                        }
                        if not dialog["controls"]:
                            rows.append({**common, "record_type": "dialog"})
                        for control in dialog["controls"]:
                            rows.append({
                                **common,
                                "record_type": "control",
                                "control_index": control["index"],
                                "control_id_hex": f"0x{control['id']:08X}",
                                "control_class": control["class"],
                                "caption": control["caption"],
                                "control_style_hex": f"0x{control['style']:08X}",
                                "control_ex_style_hex": f"0x{control['ex_style']:08X}",
                                "control_rect": ",".join(map(str, control["rect"])),
                                "control_help_id": control["help_id"],
                            })
        finally:
            pe.close()
    return rows


def verify_manifest_inputs(rk_root: Path, manifest_path: Path, parser: argparse.ArgumentParser) -> None:
    with manifest_path.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        parser.error(f"manifest has no file rows: {manifest_path}")
    path_field = "path" if "path" in rows[0] else "relative_path"
    if path_field not in rows[0] or not {"size_bytes", "sha256"}.issubset(rows[0]):
        parser.error("manifest must contain path or relative_path, size_bytes, and sha256 columns")

    expected = {
        row[path_field].replace("\\", "/").casefold(): row
        for row in rows
    }
    for relative in PE_NAMES:
        path = rk_root / relative
        if not path.is_file():
            continue
        name = relative.as_posix()
        candidates = (name.casefold(), f"app/{name}".casefold())
        matches = [expected[key] for key in candidates if key in expected]
        if len(matches) != 1:
            parser.error(f"expected exactly one manifest row for {name}, found {len(matches)}")
        row = matches[0]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if path.stat().st_size != int(row["size_bytes"]):
            parser.error(f"size mismatch for {name}: {path.stat().st_size} != {row['size_bytes']}")
        if digest.casefold() != row["sha256"].casefold():
            parser.error(f"SHA-256 mismatch for {name}")
        print(f"Verified manifest input: {name} ({digest})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rk-root", type=Path, required=True, help="package directory containing the named PE files")
    parser.add_argument("--manifest", type=Path, help="optional package hash manifest for the PE inputs")
    parser.add_argument("--output", type=Path, required=True, help="Output CSV path")
    args = parser.parse_args()
    if args.manifest:
        verify_manifest_inputs(args.rk_root, args.manifest, parser)
    rows = collect_dialogs(args.rk_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "binary", "resource_id", "language_id", "record_type", "dialog_format",
        "dialog_title", "dialog_window_class", "dialog_style_hex", "dialog_ex_style_hex",
        "dialog_rect", "dialog_font", "declared_control_count", "control_index",
        "control_id_hex", "control_class", "caption", "control_style_hex",
        "control_ex_style_hex", "control_rect", "control_help_id", "parse_status",
    ]
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} dialog/control rows to {args.output}")


if __name__ == "__main__":
    main()
