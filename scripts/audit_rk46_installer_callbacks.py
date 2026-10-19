#!/usr/bin/env python3
"""Recreate a static evidence ledger for RK Keyboard Software 4.6 Inno callbacks.

This script does not launch vendor code or interact with a keyboard. It invokes
innounp only to unpack two named files, then invokes ifpsdasm on the extracted
Pascal bytecode. Inputs and intermediate artifacts are SHA-256 pinned.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PINNED = {
    "setup": "47a1fc21c3af548b93fa40d499584abecb3341e62b15948ae537b78ca987aad8",
    "nupkg": "c8dc71bfdda39c44a8c962721a32f09339b0095f29e8fe619f5627f287e8c26d",
    "innounp": "9b72ad9f93d167652a0e2bf3921abdfd3e6747c5e718461a2e58b9dfacd31f4c",
    "ifpsdasm": "115b85d2bcea1b2c41199e3fda686de0bb87a62c6cba59208abe28e71b635773",
    "compiled_code": "14289e06e226ea346521af11519286a38482a58eac11e9cc36b556144e50b981",
    "disassembly": "778c9641535017fbc735f8a3647f4a2b942ab7303616f2a310c54c69a22b65f9",
    "reconstructed_iss": "c1d3d2dcea25790cd8264f19d60c39a4c12d122f6b1799a1a878d647ed8a98a1",
}

CALLBACK_FIELDS = [
    "callback",
    "evidence_id",
    "source_line_start",
    "source_line_end",
    "static_observation",
    "status",
    "interpretation_limit",
]

ACTION_FIELDS = [
    "section",
    "source_line",
    "action_type",
    "source_or_key",
    "destination_or_value",
    "flags_or_metadata",
    "status",
    "interpretation_limit",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(path: Path, key: str) -> None:
    if not path.is_file():
        raise RuntimeError(f"missing {key} input: {path}")
    actual = sha256(path)
    expected = PINNED[key]
    if actual != expected:
        raise RuntimeError(f"{key} SHA-256 mismatch: {actual} != {expected}")


def run_static_extract(innounp: Path, setup: Path, destination: Path) -> None:
    command = [
        str(innounp),
        "-x",
        "-m",
        "-b",
        "-q",
        "-y",
        f"-d{destination}",
        str(setup),
        "embedded\\CompiledCode.bin",
        "install_script.iss",
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            "innounp static extraction failed (exit "
            f"{result.returncode}): {result.stderr or result.stdout}"
        )


def run_disassembler(ifpsdasm: Path, compiled_code: Path) -> Path:
    result = subprocess.run(
        [str(ifpsdasm), str(compiled_code)],
        cwd=compiled_code.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "ifpsdasm failed (exit "
            f"{result.returncode}): {result.stderr or result.stdout}"
        )
    disassembly = compiled_code.with_suffix(".txt")
    if not disassembly.is_file():
        raise RuntimeError(f"ifpsdasm did not create expected output: {disassembly}")
    return disassembly


def function_spans(lines: list[str]) -> dict[str, tuple[int, int]]:
    boundaries = [index for index, line in enumerate(lines, 1) if line.startswith(".function(")]
    exports: list[tuple[int, str]] = []
    for index, line in enumerate(lines, 1):
        match = re.match(r"\.function\(export\).*?\s([A-Z!][A-Z0-9!]*)\s*\(", line)
        if match:
            exports.append((index, match.group(1)))
    spans: dict[str, tuple[int, int]] = {}
    for start, name in exports:
        next_functions = [line for line in boundaries if line > start]
        end = next_functions[0] - 1 if next_functions else len(lines)
        spans[name] = (start, end)
    return spans


def first_line(lines: list[str], start: int, end: int, pattern: str) -> int | None:
    expression = re.compile(pattern)
    for number in range(start, end + 1):
        if expression.search(lines[number - 1]):
            return number
    return None


def window_action_range(lines: list[str], start: int, end: int, title: str) -> tuple[int, int]:
    title_line = first_line(lines, start, end, re.escape(f'String_3("{title}")'))
    if title_line is None:
        raise RuntimeError(f"title not found in callback: {title}")
    send_line = first_line(lines, title_line, end, r"call SENDMESSAGE")
    if send_line is None:
        raise RuntimeError(f"SENDMESSAGE not found after window title: {title}")
    sleep_line = first_line(lines, send_line, end, r"call SLEEP")
    if sleep_line is None:
        raise RuntimeError(f"SLEEP not found after SENDMESSAGE: {title}")
    finish_line = first_line(lines, sleep_line, end, r"pop ; StackCount = 0")
    return title_line, finish_line or sleep_line


def add_callback(callback_rows: list[dict[str, str]], name: str, evidence_id: str,
                 span: tuple[int, int], observation: str, status: str,
                 limit: str) -> None:
    callback_rows.append({
        "callback": name,
        "evidence_id": evidence_id,
        "source_line_start": str(span[0]),
        "source_line_end": str(span[1]),
        "static_observation": observation,
        "status": status,
        "interpretation_limit": limit,
    })


def build_callback_rows(disassembly: str) -> list[dict[str, str]]:
    lines = disassembly.splitlines()
    spans = function_spans(lines)
    required = ["!MAIN", "INITIALIZESETUP", "MYAFTERINSTALL", "MYAFTERINSTALL2",
                "CURUNINSTALLSTEPCHANGED", "INITIALIZEUNINSTALLPROGRESSFORM"]
    missing = [name for name in required if name not in spans]
    if missing:
        raise RuntimeError(f"expected exported callback(s) missing: {', '.join(missing)}")

    rows: list[dict[str, str]] = []
    main_span = spans["!MAIN"]
    add_callback(rows, "!MAIN", "CB-001", main_span,
                 "Exported entry point contains only ret.", "proven",
                 "Disassembly establishes its body; it does not establish all installer engine startup behavior.")

    setup_span = spans["INITIALIZESETUP"]
    for index, title in enumerate(("RK Keyboard", "RK RGB Keyboard"), 1):
        evidence_range = window_action_range(lines, *setup_span, title)
        add_callback(rows, "INITIALIZESETUP", f"CB-01{index}", evidence_range,
                     f'Looks up a window titled "{title}"; if the lookup result is nonzero, prepares SENDMESSAGE with the returned handle, message value 16, and two zero values, then calls SLEEP with 1000.',
                     "proven",
                     "The bytecode proves the title lookups, conditional path, values, and delay. Mapping 16 to WM_CLOSE follows the Win32 constant; runtime window presence and message delivery were not observed.")
    add_callback(rows, "INITIALIZESETUP", "CB-013", setup_span,
                 "Returns BOOLEAN(1) after the conditional window-close paths.", "proven",
                 "Static callback return only; no installer run was performed.")

    install_span = spans["MYAFTERINSTALL"]
    add_callback(rows, "MYAFTERINSTALL", "CB-020", install_span,
                 'Expands "{localappdata}\\RKKB" and passes the result to the delayed external import InitSetup.dll!SetupInit.',
                 "proven",
                 "The call site and argument are proven. The helper behavior is analyzed separately; callback dispatch and resulting filesystem changes were not observed in an installation.")

    lang_span = spans["MYAFTERINSTALL2"]
    language_map = re.findall(
        r'eq Var1, Global3, String_3\("([^"]+)"\).*?\n\s*sfz Var1\s*\n\s*pop ; StackCount = 0\s*\n\s*jf [^\n]+\s*\n\s*assign Global2, S32\((\d+)\)',
        "\n".join(lines[lang_span[0] - 1:lang_span[1]]),
        re.S,
    )
    if sorted(language_map) != sorted([("en", "1"), ("sc", "0"), ("tw", "2"),
                                      ("Russian", "3"), ("Turkish", "4"),
                                      ("Japanese", "5"), ("Korean", "6")]):
        raise RuntimeError(f"language mapping mismatch in callback disassembly: {language_map}")
    map_line = first_line(lines, *lang_span, r'eq Var1, Global3, String_3\("en"\)')
    add_callback(rows, "MYAFTERINSTALL2", "CB-030", (map_line or lang_span[0], lang_span[1]),
                 "Initializes the index to 0; maps en=1, sc=0, tw=2, Russian=3, Turkish=4, Japanese=5, Korean=6; expands {localappdata}\\RKKB\\lang.ini; calls SETINIINT for section OPT, key LangIndex, with the selected integer.",
                 "proven",
                 "The bytecode has no else branch beyond the default 0. Installer language selection, callback dispatch, and final INI contents were not observed at runtime.")

    uninstall_step_span = spans["CURUNINSTALLSTEPCHANGED"]
    add_callback(rows, "CURUNINSTALLSTEPCHANGED", "CB-040", uninstall_step_span,
                 "Exported callback body contains only ret; its event argument is unused.", "proven",
                 "Only this callback body is covered; uninstaller engine behavior and other uninstall artifacts are out of scope.")

    uninstall_span = spans["INITIALIZEUNINSTALLPROGRESSFORM"]
    for index, title in enumerate(("RK Keyboard", "RK RGB Keyboard"), 1):
        evidence_range = window_action_range(lines, *uninstall_span, title)
        add_callback(rows, "INITIALIZEUNINSTALLPROGRESSFORM", f"CB-05{index}", evidence_range,
                     f'Looks up a window titled "{title}"; if found, prepares SENDMESSAGE with message value 16 and two zero values, then sleeps 1000.',
                     "proven",
                     "Static body only. The uninstall callback invocation and message delivery were not observed.")
    return rows


def parse_properties(line: str) -> dict[str, str]:
    """Parse simple Inno key/value rows while preserving quoted semicolons."""
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    for char in line:
        if char == '"':
            quoted = not quoted
        if char == ";" and not quoted:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current).strip())
    properties: dict[str, str] = {}
    for part in parts:
        if not part or part.startswith(";") or not re.search(r"[:=]", part):
            continue
        key, value = re.split(r"\s*[:=]\s*", part, maxsplit=1)
        properties[key.strip()] = value.strip().strip('"')
    return properties


def parse_iss(iss: str) -> list[dict[str, str]]:
    lines = iss.splitlines()
    section = ""
    rows: list[dict[str, str]] = []
    found_sections: set[str] = set()
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]") and len(stripped) > 2:
            section = stripped[1:-1]
            found_sections.add(section)
            continue
        if not stripped or stripped.startswith(";"):
            continue
        props = parse_properties(stripped)
        if section == "Files" and props:
            metadata = "; ".join(f"{key}={value}" for key, value in props.items()
                                 if key not in ("Source", "DestDir"))
            callback = props.get("AfterInstall", "")
            rows.append({
                "section": section,
                "source_line": str(number),
                "action_type": "file-copy",
                "source_or_key": props.get("Source", stripped),
                "destination_or_value": props.get("DestDir", ""),
                "flags_or_metadata": metadata,
                "status": "proven",
                "interpretation_limit": (f"Reconstructed descriptor row; AfterInstall={callback} is metadata, not an observed callback invocation." if callback else "Reconstructed descriptor row; not evidence that a package installation ran."),
            })
        elif section == "Dirs" and props:
            rows.append({
                "section": section,
                "source_line": str(number),
                "action_type": "directory-entry",
                "source_or_key": props.get("Name", stripped),
                "destination_or_value": props.get("Name", ""),
                "flags_or_metadata": "; ".join(f"{key}={value}" for key, value in props.items() if key != "Name"),
                "status": "proven",
                "interpretation_limit": "Recovered installer descriptor; execution and created-directory state are unobserved.",
            })
        elif section == "Run" and props:
            rows.append({
                "section": section,
                "source_line": str(number),
                "action_type": "run-entry",
                "source_or_key": props.get("Filename", stripped),
                "destination_or_value": props.get("Description", ""),
                "flags_or_metadata": "; ".join(f"{key}={value}" for key, value in props.items() if key not in ("Filename", "Description")),
                "status": "proven",
                "interpretation_limit": "Run-section descriptor only. Whether the user selected this post-install action or the process started is unknown.",
            })
        elif section == "Icons" and props:
            rows.append({
                "section": section,
                "source_line": str(number),
                "action_type": "shortcut-entry",
                "source_or_key": props.get("Name", stripped),
                "destination_or_value": props.get("Filename", ""),
                "flags_or_metadata": "; ".join(f"{key}={value}" for key, value in props.items() if key not in ("Name", "Filename")),
                "status": "proven",
                "interpretation_limit": "Shortcut descriptor only; shortcut creation was not observed.",
            })
        elif section == "Setup" and "=" in stripped:
            key, value = stripped.split("=", 1)
            rows.append({
                "section": section,
                "source_line": str(number),
                "action_type": "setup-directive",
                "source_or_key": key.strip(),
                "destination_or_value": value.strip(),
                "flags_or_metadata": "",
                "status": "proven",
                "interpretation_limit": "Reconstructed setup directive; no installer execution was performed.",
            })

    for absent in ("Registry", "InstallDelete", "UninstallDelete", "UninstallRun"):
        if absent not in found_sections:
            rows.append({
                "section": absent,
                "source_line": "",
                "action_type": "absence-observation",
                "source_or_key": "section not reconstructed",
                "destination_or_value": "",
                "flags_or_metadata": "",
                "status": "bounded negative",
                "interpretation_limit": "The generated ISS recovered by innounp has no such section. This does not rule out installer-engine behavior, generated uninstaller state, or unrecovered script content.",
            })
    return rows


def write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", type=Path, default=ROOT / ".research/RK_Keyboard_Software_Setup_V4.6_20261015_N87rjnh.exe")
    parser.add_argument("--nupkg", type=Path, default=ROOT / ".research/innounp-0.50.nupkg")
    parser.add_argument("--innounp", type=Path, default=ROOT / ".research/innounp-0.50-package/tools/innounp.exe")
    parser.add_argument("--ifpsdasm", type=Path, default=ROOT.parent / ".research/ifpstools-net_v2.0.5/ifpsdasm.exe")
    parser.add_argument("--callback-csv", type=Path, default=ROOT / "docs/rk-v4.6-installer-callback-evidence-2026-10-20.csv")
    parser.add_argument("--action-csv", type=Path, default=ROOT / "docs/rk-v4.6-installer-action-evidence-2026-10-20.csv")
    args = parser.parse_args()

    try:
        verify(args.setup, "setup")
        verify(args.nupkg, "nupkg")
        verify(args.innounp, "innounp")
        verify(args.ifpsdasm, "ifpsdasm")
        with tempfile.TemporaryDirectory(prefix="rk46-inno-static-") as temp:
            extracted = Path(temp) / "extract"
            extracted.mkdir()
            run_static_extract(args.innounp, args.setup, extracted)
            compiled_code = extracted / "embedded" / "CompiledCode.bin"
            iss_file = extracted / "install_script.iss"
            verify(compiled_code, "compiled_code")
            verify(iss_file, "reconstructed_iss")
            disassembly_path = run_disassembler(args.ifpsdasm, compiled_code)
            verify(disassembly_path, "disassembly")
            disassembly = disassembly_path.read_text(encoding="utf-8", errors="strict")
            iss = iss_file.read_text(encoding="utf-8-sig", errors="replace")
            callback_rows = build_callback_rows(disassembly)
            action_rows = parse_iss(iss)

        file_rows = [row for row in action_rows if row["action_type"] == "file-copy"]
        after_install_rows = [row for row in file_rows if "AfterInstall=" in row["flags_or_metadata"]]
        if len(file_rows) != 1249:
            raise RuntimeError(f"expected 1,249 reconstructed file rows, found {len(file_rows)}")
        if len(after_install_rows) != 2:
            raise RuntimeError(f"expected two AfterInstall associations, found {len(after_install_rows)}")

        write_csv(args.callback_csv, CALLBACK_FIELDS, callback_rows)
        write_csv(args.action_csv, ACTION_FIELDS, action_rows)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"audit failed: {error}", file=sys.stderr)
        return 1

    print(f"callback evidence rows: {len(callback_rows)} -> {args.callback_csv}")
    print(f"installer action rows: {len(action_rows)} -> {args.action_csv}")
    print("reconstructed ISS counts: 1,249 file rows, 2 AfterInstall associations")
    print("input and intermediate SHA-256 checks: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
