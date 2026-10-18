#!/usr/bin/env python3
"""Verify and classify resources in the extracted RK 4.6-labeled package.

The script reads only the extracted package, its hash manifest, and the
source-free profile catalog. It verifies the manifest against disk, then
writes aggregate file-group and per-profile asset inventories. It does not
launch RK executables or access a device.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath


GROUP_INFO = {
    "Application root and configuration": (
        "Top-level app configuration, native executables/libraries, icon, and data files.",
        "Path and extension; Cfg.ini and PE roles are cross-referenced by the package audit.",
        "The extracted package filename says V4.6 while app/Cfg.ini declares Ver=0x406; do not infer a new runtime version from the filename.",
    ),
    "Font files": (
        "Bundled font files kept outside the app subtree.",
        "Path and TTF file metadata.",
        "Exact control-to-font usage is not mapped.",
    ),
    "Extracted localappdata seed": (
        "A small localappdata/RKKB/lang.ini file is included in the extracted tree.",
        "Path and filename only.",
        "Whether this file is installer seed data, test residue, or consumed at install time is unresolved.",
    ),
    "UI skins and chrome": (
        "Skin and interface artwork resources under app/skins.",
        "Path, file type, and prior 4.06 resource-family evidence.",
        "The 4.6 runtime use of each individual skin asset is not mapped.",
    ),
    "UI localization and text resources": (
        "Localized UI text dictionaries and related text resources under app/Text.",
        "Path, XML/text format, and per-version localization comparison.",
        "Runtime reachability for every string/control remains incomplete.",
    ),
    "Global ET effect patterns": (
        "Global ET pattern files outside a model profile directory.",
        "Path and extension; pattern structure is separately described in the 4.06 resource audit.",
        "The 4.6 runtime binding from numeric folders to UI effects is unresolved.",
    ),
    "Global Cartoon animation patterns": (
        "Global Cartoon pattern files outside a model profile directory.",
        "Path and extension.",
        "Individual animation semantics and UI reachability are not mapped.",
    ),
    "Generic localized LED labels": (
        "Generic language-specific LED label XML below app/Dev.",
        "Path shape Dev/<locale>/led.xml and XML extension.",
        "Exact pairing between each generic dictionary and profile-specific LED slots is not fully mapped.",
    ),
    "Per-profile KB.ini configuration": (
        "One KB.ini configuration file in a recognized model profile directory.",
        "The extracted catalog and exact relative path.",
        "Stored values are configuration evidence, not proof of physical model support.",
    ),
    "Per-profile keyboard artwork": (
        "Profile-local keyimg.png and kbled.png keyboard diagrams.",
        "Profile path and image filenames.",
        "Pixel regions are not exhaustively linked to runtime controls or key actions.",
    ),
    "Per-profile side-light artwork": (
        "Profile-local sideled.png artwork.",
        "Profile path and filename.",
        "A ShowSideLED option does not prove that an image exists or that the feature is reachable.",
    ),
    "Per-profile LED label XML": (
        "Profile-local language-specific LED label dictionaries.",
        "Profile path and locale/led.xml filename.",
        "Labels do not establish tuple semantics or a particular device command.",
    ),
    "Per-profile SideLed resources": (
        "Profile-local SideLed artwork, localization, or other resources.",
        "Profile path and SideLed directory name; locale XMLs are counted separately.",
        "The 0258 profile advertises ShowSideLED but has no SideLed directory in this package; runtime fallback behavior is unresolved.",
    ),
    "Per-profile ET effect patterns": (
        "Profile-local ET pattern files.",
        "Profile path and ET directory name.",
        "Pattern-to-effect control bindings and exact runtime use are incomplete.",
    ),
    "Per-profile Cartoon animation patterns": (
        "Profile-local Cartoon pattern files.",
        "Profile path and Cartoon directory name.",
        "Pattern-to-animation controls and exact runtime use are incomplete.",
    ),
    "Per-profile screen and GIF resources": (
        "Profile-local screen GIFs, decoded PNG frame assets, and delay/cache files.",
        "Profile path and screen/GIF-related filenames.",
        "Presence does not establish a complete import/conversion-to-device path or hardware acceptance.",
    ),
    "Per-profile updater and firmware package files": (
        "Profile-local updater executable, update manifest, and firmware-package files.",
        "Profile path, updater/package extension, and exact package hash manifest.",
        "A bundled package is host-side updater input; it is not a device firmware dump and is not validated by this inventory.",
    ),
    "Other profile-local resources": (
        "Files under recognized model profile directories that do not fit a named resource class.",
        "Profile directory membership and file path.",
        "Role is intentionally left unassigned pending content/code analysis.",
    ),
    "Other app resources": (
        "Files under app/ not assigned to another path class.",
        "Path and extension.",
        "Role is intentionally unresolved.",
    ),
    "Other extracted package resources": (
        "Files outside the app, fonts, or localappdata groups.",
        "Top-level path and file metadata.",
        "Role is intentionally unresolved.",
    ),
}


ASSET_FIELDS = [
    "profile_code",
    "model_name_from_catalog",
    "listed_in_cfg_ini",
    "kb_ini",
    "keyimg_png",
    "kbled_png",
    "sideled_png",
    "screen_gif",
    "screen_frame_png_count",
    "gif_delay_file_count",
    "localized_led_xml_locales",
    "side_led_xml_locales",
    "side_led_other_file_count",
    "et_pattern_files",
    "cartoon_pattern_files",
    "model_update_exe",
    "update_version_xml",
    "firmware_upf_files",
    "other_profile_file_count",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def normalized_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe manifest path: {value!r}")
    return path.as_posix()


def classify(path: str, profile_codes: set[str]) -> tuple[str, str]:
    parts = PurePosixPath(path).parts
    lower = tuple(part.casefold() for part in parts)
    name = lower[-1]

    if parts[0].casefold() == "fonts":
        return "Font files", "fonts/*"
    if parts[0].casefold() == "localappdata":
        return "Extracted localappdata seed", "localappdata/RKKB/*"
    if parts[0].casefold() != "app":
        return "Other extracted package resources", f"{parts[0]}/*"

    if len(parts) == 2:
        if name == "cfg.ini" or Path(name).suffix.casefold() in {".exe", ".dll", ".dat", ".ico"}:
            return "Application root and configuration", "app/<root configuration, executable, or resource>"
        return "Other app resources", "app/<root file>"

    sub = lower[1:]
    if sub[0] == "skins":
        return "UI skins and chrome", "app/skins/*"
    if sub[0] == "text":
        return "UI localization and text resources", "app/Text/<locale>/*"
    if sub[0] == "et":
        return "Global ET effect patterns", "app/ET/<pattern-group>/*"
    if sub[0] == "cartoon":
        return "Global Cartoon animation patterns", "app/Cartoon/<pattern-group>/*"
    if sub[0] != "dev":
        return "Other app resources", "app/<other resource path>"

    if len(parts) == 4 and parts[1].casefold() == "dev" and name == "led.xml" and parts[2].upper() not in profile_codes:
        return "Generic localized LED labels", "app/Dev/<locale>/led.xml"
    if len(parts) < 3:
        return "Other app resources", "app/Dev/<other resource path>"

    code = parts[2].upper()
    if code not in profile_codes:
        return "Other app resources", "app/Dev/<non-catalog path>"
    rest = lower[3:]
    if len(rest) == 1 and name == "kb.ini":
        return "Per-profile KB.ini configuration", "app/Dev/<profile>/KB.ini"
    if name in {"update.exe", "update_version.xml"} or name.endswith(".upf"):
        return "Per-profile updater and firmware package files", "app/Dev/<profile>/{Update.exe,update_version.xml,*.upf}"
    if rest and rest[0] == "sideled":
        return "Per-profile SideLed resources", "app/Dev/<profile>/SideLed/<locale>/*"
    if name == "sideled.png":
        return "Per-profile side-light artwork", "app/Dev/<profile>/sideled.png"
    if name in {"keyimg.png", "kbled.png"}:
        return "Per-profile keyboard artwork", "app/Dev/<profile>/{keyimg.png,kbled.png}"
    if name == "screen.gif" or name == "gif_delay.gcc" or name.startswith("screen_img"):
        return "Per-profile screen and GIF resources", "app/Dev/<profile>/{screen.gif,screen_img*,gif_delay.gcc}"
    if rest and rest[0] == "et":
        return "Per-profile ET effect patterns", "app/Dev/<profile>/ET/*"
    if rest and rest[0] == "cartoon":
        return "Per-profile Cartoon animation patterns", "app/Dev/<profile>/Cartoon/*"
    if len(rest) == 2 and name == "led.xml":
        return "Per-profile LED label XML", "app/Dev/<profile>/<locale>/led.xml"
    return "Other profile-local resources", "app/Dev/<profile>/<other path>"


def profile_asset_rows(
    root: Path,
    profiles: list[dict[str, object]],
    cfg_codes: set[str],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    dev = root / "app" / "Dev"
    for profile in profiles:
        code = str(profile["code"]).upper()
        profile_dir = dev / code
        files = [p for p in profile_dir.rglob("*") if p.is_file()] if profile_dir.is_dir() else []
        rels = [p.relative_to(profile_dir).as_posix() for p in files]
        localized_led = sorted({
            PurePosixPath(rel).parts[0]
            for rel in rels
            if len(PurePosixPath(rel).parts) == 2
            and PurePosixPath(rel).name.casefold() == "led.xml"
        })
        side_led_xml = sorted({
            PurePosixPath(rel).parts[1]
            for rel in rels
            if len(PurePosixPath(rel).parts) == 3
            and PurePosixPath(rel).parts[0].casefold() == "sideled"
            and PurePosixPath(rel).name.casefold() == "led.xml"
        })
        side_led_other = sum(
            1 for rel in rels
            if PurePosixPath(rel).parts
            and PurePosixPath(rel).parts[0].casefold() == "sideled"
            and PurePosixPath(rel).name.casefold() != "led.xml"
        )
        categorized = {
            "kb.ini", "keyimg.png", "kbled.png", "sideled.png", "screen.gif", "gif_delay.gcc",
        }
        other = 0
        for rel in rels:
            parts = tuple(p.casefold() for p in PurePosixPath(rel).parts)
            name = parts[-1]
            if name in categorized or name.startswith("screen_img"):
                continue
            if name in {"update.exe", "update_version.xml"} or name.endswith(".upf"):
                continue
            if parts[0] in {"et", "cartoon", "sideled"}:
                continue
            if len(parts) == 2 and name == "led.xml":
                continue
            other += 1

        rows.append({
            "profile_code": code,
            "model_name_from_catalog": str(profile.get("name", "")),
            "listed_in_cfg_ini": "yes" if code in cfg_codes else "no",
            "kb_ini": "yes" if (profile_dir / "KB.ini").is_file() else "no",
            "keyimg_png": "yes" if (profile_dir / "keyimg.png").is_file() else "no",
            "kbled_png": "yes" if (profile_dir / "kbled.png").is_file() else "no",
            "sideled_png": "yes" if (profile_dir / "sideled.png").is_file() else "no",
            "screen_gif": "yes" if (profile_dir / "screen.gif").is_file() else "no",
            "screen_frame_png_count": sum(
                1 for rel in rels if PurePosixPath(rel).name.casefold().startswith("screen_img")
                and PurePosixPath(rel).suffix.casefold() == ".png"
            ),
            "gif_delay_file_count": sum(1 for rel in rels if PurePosixPath(rel).name.casefold() == "gif_delay.gcc"),
            "localized_led_xml_locales": ";".join(localized_led) if localized_led else "none",
            "side_led_xml_locales": ";".join(side_led_xml) if side_led_xml else "none",
            "side_led_other_file_count": side_led_other,
            "et_pattern_files": sum(1 for rel in rels if PurePosixPath(rel).parts[0].casefold() == "et") if rels else 0,
            "cartoon_pattern_files": sum(1 for rel in rels if PurePosixPath(rel).parts[0].casefold() == "cartoon") if rels else 0,
            "model_update_exe": "yes" if (profile_dir / "Update.exe").is_file() else "no",
            "update_version_xml": "yes" if (profile_dir / "update_version.xml").is_file() else "no",
            "firmware_upf_files": sum(1 for rel in rels if PurePosixPath(rel).suffix.casefold() == ".upf"),
            "other_profile_file_count": other,
        })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="extracted package root containing app/, fonts/, and localappdata/")
    parser.add_argument("--manifest", type=Path, required=True, help="path/size/SHA-256 package manifest")
    parser.add_argument("--catalog", type=Path, required=True, help="source-free models-4.6.json catalog")
    parser.add_argument("--groups-output", type=Path, required=True)
    parser.add_argument("--profiles-output", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve(strict=True)
    if not root.is_dir():
        parser.error(f"not a directory: {root}")
    manifest_rows: dict[str, dict[str, str]] = {}
    with args.manifest.open("r", encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            rel = normalized_path(row["path"])
            if rel in manifest_rows:
                parser.error(f"duplicate manifest path: {rel}")
            manifest_rows[rel] = row

    disk_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }
    if disk_paths != set(manifest_rows):
        parser.error(
            f"manifest/disk path mismatch: missing={sorted(set(manifest_rows)-disk_paths)[:5]}, "
            f"unlisted={sorted(disk_paths-set(manifest_rows))[:5]}"
        )
    for rel, row in manifest_rows.items():
        path = root.joinpath(*PurePosixPath(rel).parts)
        size = path.stat().st_size
        if size != int(row["size_bytes"]):
            parser.error(f"size mismatch for {rel}: manifest={row['size_bytes']}, disk={size}")
        digest = sha256(path)
        if digest.upper() != row["sha256"].upper():
            parser.error(f"SHA-256 mismatch for {rel}: manifest={row['sha256']}, disk={digest}")

    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    profiles = catalog["models"]
    if int(catalog.get("profileCount", -1)) != len(profiles):
        parser.error("catalog profileCount does not equal models array length")
    profile_codes = {str(profile["code"]).upper() for profile in profiles}
    profile_dirs = {
        PurePosixPath(path).parts[2].upper()
        for path in disk_paths
        if len(PurePosixPath(path).parts) >= 4
        and PurePosixPath(path).parts[0].casefold() == "app"
        and PurePosixPath(path).parts[1].casefold() == "dev"
        and PurePosixPath(path).name.casefold() == "kb.ini"
    }
    if profile_dirs != profile_codes:
        parser.error(
            f"profile catalog/disk mismatch: missing_catalog={sorted(profile_dirs-profile_codes)}, "
            f"missing_KB_ini={sorted(profile_codes-profile_dirs)}"
        )

    cfg_path = root / "app" / "Cfg.ini"
    cfg_bytes = cfg_path.read_bytes()
    cfg_encoding = "utf-16" if cfg_bytes.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    cfg_text = cfg_bytes.decode(cfg_encoding, errors="replace")
    cfg_codes = {
        line.split("=", 1)[1].split(",", 1)[0].strip().upper()
        for line in cfg_text.splitlines()
        if line.strip().casefold().startswith("devname") and "=" in line
    }
    if cfg_codes != profile_codes:
        parser.error(
            f"Cfg.ini/profile catalog mismatch: cfg_only={sorted(cfg_codes-profile_codes)}, "
            f"catalog_only={sorted(profile_codes-cfg_codes)}"
        )

    groups: dict[str, list[str]] = defaultdict(list)
    bytes_by_group: Counter[str] = Counter()
    examples: dict[str, list[str]] = defaultdict(list)
    for rel, row in manifest_rows.items():
        group, pattern = classify(rel, profile_codes)
        groups[group].append(rel)
        bytes_by_group[group] += int(row["size_bytes"])
        if pattern not in examples[group]:
            examples[group].append(pattern)

    groups_path = args.groups_output
    groups_path.parent.mkdir(parents=True, exist_ok=True)
    with groups_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(("resource_group", "file_count", "bytes", "extensions", "path_examples_or_pattern", "role_and_support", "confidence_basis", "unresolved_or_exception"))
        for group in sorted(groups, key=str.casefold):
            ext_counts = Counter(
                PurePosixPath(rel).suffix.casefold() or "(none)"
                for rel in groups[group]
            )
            ext_text = ";".join(
                f"{ext}={count}"
                for ext, count in sorted(ext_counts.items(), key=lambda item: (item[0] != "(none)", item[0]))
            )
            role, basis, unresolved = GROUP_INFO[group]
            writer.writerow((
                group,
                len(groups[group]),
                bytes_by_group[group],
                ext_text,
                "; ".join(examples[group][:4]),
                role,
                basis,
                unresolved,
            ))

    profile_rows = profile_asset_rows(root, profiles, cfg_codes)
    profiles_path = args.profiles_output
    profiles_path.parent.mkdir(parents=True, exist_ok=True)
    with profiles_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=ASSET_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(profile_rows)

    print(f"Verified {len(manifest_rows)} paths, sizes, and SHA-256 values against the extracted package manifest.")
    print(f"Matched {len(profile_codes)} catalog profiles to Cfg.ini DevName records and profile KB.ini files.")
    print(f"Classified all {sum(len(paths) for paths in groups.values())} files into {len(groups)} resource groups.")
    print(f"Wrote aggregate resource groups: {groups_path}")
    print(f"Wrote per-profile asset inventory: {profiles_path}")
    print("Static package inventory only; no RK executable or device interface was used.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
