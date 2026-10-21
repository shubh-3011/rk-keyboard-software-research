#!/usr/bin/env python3
"""Hash-pinned, root-seeded CFG and direct-call audit for RK 4.6 DeviceDriver.

The traversal starts only from the PE entrypoint, structurally recovered MFC
message handlers, and proven entries in three audited 4.6 device-family
vtables. It follows decoded conditional branches and direct calls. This is a
bounded static graph, not a complete function map, CFG, or runtime trace.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import capstone
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

import audit_rk46_mfc_message_maps as mfc_maps


EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
EXPECTED_SIZE = 2_418_176
IMAGE_BASE = 0x00400000
VTABLE_FILES = (
    "rk-v4.6-cdevg5-vtable-map.csv",
    "rk-v4.6-cdevrkbb-vtable-map.csv",
    "rk-v4.6-cdev3632-vtable-map.csv",
)
EXPECTED_VTABLE_HASHES = {
    "rk-v4.6-cdevg5-vtable-map.csv": "6c994b3f91c0d40e4302e9e29d2e9e5da4a0d74b82635662a579e86ae71384e1",
    "rk-v4.6-cdevrkbb-vtable-map.csv": "7086073683dd51e8531ca607ab3afa9b1a7508fed4e46e964a40fd8af42bd862",
    "rk-v4.6-cdev3632-vtable-map.csv": "9f51961237cee31fce47d174ce0872b66569ab87ff6bb5697771fa5d33f16f1a",
}


@dataclass(frozen=True)
class Section:
    name: str
    start: int
    end: int
    file_offset: int
    raw_size: int
    executable: bool


@dataclass(frozen=True)
class Instruction:
    address: int
    size: int
    mnemonic: str
    operands: str
    encoded: bytes
    capstone_instruction: Any


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hx(value: int | None) -> str:
    return "" if value is None else f"0x{value:08X}"


def write_csv(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


class RootedCFG:
    def __init__(self, image_path: Path, data: bytes, roots: dict[int, set[str]]) -> None:
        self.image_path = image_path
        self.data = data
        self.roots = roots
        self.pe = pefile.PE(data=data, fast_load=False)
        self.image_base = int(self.pe.OPTIONAL_HEADER.ImageBase)
        self.sections: list[Section] = []
        for section in self.pe.sections:
            va = self.image_base + int(section.VirtualAddress)
            raw_size = len(section.get_data())
            self.sections.append(
                Section(
                    section.Name.rstrip(b"\0").decode("ascii", "replace"),
                    va,
                    va + raw_size,
                    int(section.PointerToRawData),
                    raw_size,
                    bool(int(section.Characteristics) & 0x20000000),
                )
            )
        self.exec_sections = [section for section in self.sections if section.executable]
        self.decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        self.decoder.detail = True
        self.instruction_cache: dict[int, Instruction | None] = {}
        self.imports = self._imports()
        self.functions: dict[int, dict[str, Any]] = {}
        self.edges: set[tuple[Any, ...]] = set()
        self.blocks: set[tuple[Any, ...]] = set()
        self.instruction_owners: dict[int, set[int]] = defaultdict(set)
        self.function_queue: deque[int] = deque(sorted(roots))
        self.queued = set(roots)
        self.max_functions = 50_000
        self.max_blocks_per_function = 100_000

    def section_for(self, va: int) -> Section | None:
        return next((section for section in self.sections if section.start <= va < section.end), None)

    def executable(self, va: int) -> bool:
        section = self.section_for(va)
        return section is not None and section.executable

    def file_offset(self, va: int) -> int | None:
        section = self.section_for(va)
        if section is None:
            return None
        delta = va - section.start
        if delta >= section.raw_size:
            return None
        offset = section.file_offset + delta
        return offset if offset < len(self.data) else None

    def decode(self, va: int) -> Instruction | None:
        if va in self.instruction_cache:
            return self.instruction_cache[va]
        section = self.section_for(va)
        offset = self.file_offset(va)
        if section is None or not section.executable or offset is None:
            self.instruction_cache[va] = None
            return None
        chunk = self.data[offset : min(offset + 15, section.file_offset + section.raw_size)]
        decoded = next(self.decoder.disasm(chunk, va, count=1), None)
        if decoded is None or decoded.size < 1:
            self.instruction_cache[va] = None
            return None
        result = Instruction(
            int(decoded.address), int(decoded.size), decoded.mnemonic, decoded.op_str,
            bytes(decoded.bytes), decoded
        )
        self.instruction_cache[va] = result
        return result

    def _imports(self) -> dict[int, str]:
        result: dict[int, str] = {}
        for directory_name in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for descriptor in getattr(self.pe, directory_name, []):
                dll = getattr(descriptor, "dll", b"?").decode("ascii", "replace")
                for entry in getattr(descriptor, "imports", []):
                    name = entry.name.decode("ascii", "replace") if entry.name else f"ordinal_{entry.ordinal}"
                    result[int(entry.address)] = f"{dll}!{name}"
        return result

    def direct_target(self, instruction: Instruction) -> int | None:
        cap = instruction.capstone_instruction
        if cap.operands and cap.operands[0].type == X86_OP_IMM:
            return int(cap.operands[0].imm) & 0xFFFFFFFF
        return None

    def import_target(self, instruction: Instruction) -> int | None:
        cap = instruction.capstone_instruction
        if not cap.operands or cap.operands[0].type != X86_OP_MEM:
            return None
        mem = cap.operands[0].mem
        if mem.base == 0 and mem.index == 0:
            address = int(mem.disp) & 0xFFFFFFFF
            return address if address in self.imports else None
        return None

    def has_frame_prologue(self, va: int) -> bool:
        offset = self.file_offset(va)
        section = self.section_for(va)
        if offset is None or section is None or not section.executable:
            return False
        raw = self.data[offset : min(offset + 8, section.file_offset + section.raw_size)]
        return raw.startswith((b"\x55\x8b\xec", b"\x55\x89\xe5", b"\x8b\xff\x55\x8b\xec"))

    def add_root(self, va: int, source: str) -> None:
        if not self.executable(va):
            return
        self.roots.setdefault(va, set()).add(source)
        if va not in self.queued and va not in self.functions:
            self.queued.add(va)
            self.function_queue.append(va)

    def add_edge(self, caller: int, site: int, target: int | None, kind: str,
                 symbol: str = "", confidence: str = "decoded_instruction",
                 note: str = "") -> None:
        self.edges.add((caller, site, target, kind, symbol, confidence, note))

    def process_function(self, root: int) -> None:
        if root in self.functions:
            return
        block_queue: deque[int] = deque([root])
        seen_blocks: set[int] = set()
        seen_instructions: set[int] = set()
        fn_counters: Counter[str] = Counter()
        terminal_counts: Counter[str] = Counter()
        maxed = False

        while block_queue:
            if len(seen_blocks) >= self.max_blocks_per_function:
                maxed = True
                terminal_counts["block_limit"] += 1
                break
            block_start = block_queue.popleft() & 0xFFFFFFFF
            if block_start in seen_blocks:
                continue
            seen_blocks.add(block_start)
            if not self.executable(block_start):
                terminal_counts["non_executable_successor"] += 1
                continue
            if block_start != root and block_start in self.roots:
                terminal_counts["entered_other_root"] += 1
                continue

            current = block_start
            block_count = 0
            block_last: Instruction | None = None
            block_term = "fallthrough_limit"
            block_successors: list[int] = []
            while block_count < 20_000:
                if current in seen_instructions:
                    block_term = "already_visited_instruction"
                    break
                if current != root and current in self.roots:
                    block_term = "other_seed_boundary"
                    terminal_counts["entered_other_root"] += 1
                    break
                instruction = self.decode(current)
                if instruction is None:
                    block_term = "decode_or_section_boundary"
                    terminal_counts[block_term] += 1
                    break
                seen_instructions.add(current)
                self.instruction_owners[current].add(root)
                fn_counters["instructions"] += 1
                block_count += 1
                block_last = instruction
                cap = instruction.capstone_instruction
                next_va = current + instruction.size
                is_call = cap.group(capstone.CS_GRP_CALL)
                is_jump = cap.group(capstone.CS_GRP_JUMP)
                is_return = cap.group(capstone.CS_GRP_RET) or instruction.mnemonic.lower().startswith(("ret", "iret"))

                if is_call:
                    target = self.direct_target(instruction)
                    iat = self.import_target(instruction)
                    if target is not None:
                        target_section = self.section_for(target)
                        if target == next_va:
                            fn_counters["call_to_fallthrough_sites"] += 1
                            self.add_edge(root, current, target, "call_to_fallthrough_candidate",
                                          confidence="decoded_direct_call",
                                          note="Call-to-next-instruction idiom; treated as intra-function flow, not a new function root.")
                        else:
                            fn_counters["direct_call_sites"] += 1
                            self.add_edge(root, current, target, "direct_call",
                                          confidence="decoded_direct_call",
                                          note="Target is an internal transfer candidate; call reachability is not runtime evidence.")
                            if target_section is not None and target_section.executable:
                                self.add_root(target, "direct-call target")
                            else:
                                fn_counters["direct_calls_outside_executable"] += 1
                    elif iat is not None:
                        fn_counters["import_call_sites"] += 1
                        self.add_edge(root, current, iat, "import_call", self.imports[iat],
                                      confidence="static_IAT_operand",
                                      note="Absolute memory operand matches this PE's import table.")
                    else:
                        fn_counters["indirect_call_sites"] += 1
                        cap_operand = cap.op_str
                        self.add_edge(root, current, None, "unresolved_indirect_call", "",
                                      confidence="unresolved",
                                      note=f"Operand {cap_operand!r}; register/vtable/callback target not resolved here.")
                    current = next_va
                    continue

                if is_jump:
                    target = self.direct_target(instruction)
                    if target is None:
                        iat = self.import_target(instruction)
                        if iat is not None:
                            fn_counters["import_tail_jump_sites"] += 1
                            self.add_edge(root, current, iat, "import_tail_jump", self.imports[iat],
                                          confidence="static_IAT_operand",
                                          note="Absolute memory operand matches this PE's import table.")
                            block_term = "import_tail_jump"
                        else:
                            fn_counters["indirect_jump_sites"] += 1
                            self.add_edge(root, current, None, "unresolved_indirect_jump", "",
                                          confidence="unresolved",
                                          note=f"Operand {cap.op_str!r}; computed dispatch target not resolved here.")
                            block_term = "indirect_jump"
                        break
                    if instruction.mnemonic.lower() == "jmp":
                        if not self.executable(target):
                            self.add_edge(root, current, target, "direct_jump_outside_executable",
                                          confidence="decoded_direct_jump")
                            block_term = "direct_jump_outside_executable"
                            break
                        if target != root and (target in self.roots or self.has_frame_prologue(target)):
                            self.add_edge(root, current, target, "tail_jump_candidate",
                                          confidence="candidate",
                                          note="Unconditional jump reaches another seed or common x86 frame prologue; tail-call interpretation is not proven.")
                            self.add_root(target, "unconditional-jump target candidate")
                            fn_counters["tail_jump_candidates"] += 1
                            block_term = "tail_jump_candidate"
                            break
                        self.add_edge(root, current, target, "intra_function_jump_candidate",
                                      confidence="decoded_direct_branch",
                                      note="Followed as a CFG successor; function boundary is heuristic.")
                        block_successors.append(target)
                        block_queue.append(target)
                        block_term = "direct_unconditional_branch"
                        break

                    fn_counters["conditional_branch_sites"] += 1
                    self.add_edge(root, current, target, "conditional_branch",
                                  confidence="decoded_direct_branch",
                                  note="Both target and fallthrough are explored; branch condition is not evaluated.")
                    block_successors.append(target)
                    if self.executable(target):
                        if target != root and target in self.roots:
                            fn_counters["cross_root_branch_candidates"] += 1
                        else:
                            block_queue.append(target)
                    self.add_edge(root, current, next_va, "conditional_fallthrough",
                                  confidence="decoded_direct_branch",
                                  note="Both target and fallthrough are explored; branch condition is not evaluated.")
                    block_successors.append(next_va)
                    if self.executable(next_va):
                        if next_va == root or next_va not in self.roots:
                            block_queue.append(next_va)
                    block_term = "conditional_branch"
                    break

                if is_return:
                    fn_counters["return_sites"] += 1
                    terminal_counts["return"] += 1
                    block_term = "return"
                    break

                current = next_va
            else:
                block_term = "block_instruction_limit"
                terminal_counts[block_term] += 1

            self.blocks.add((root, block_start, block_last.address if block_last else None,
                             block_count, block_term, ";".join(hx(v) for v in block_successors)))

        self.functions[root] = {
            "root_va": root,
            "root_sources": ";".join(sorted(self.roots.get(root, set()))),
            "instruction_count": fn_counters["instructions"],
            "block_count": len(seen_blocks),
            "direct_call_sites": fn_counters["direct_call_sites"],
            "call_to_fallthrough_sites": fn_counters["call_to_fallthrough_sites"],
            "direct_calls_outside_executable": fn_counters["direct_calls_outside_executable"],
            "import_call_sites": fn_counters["import_call_sites"],
            "import_tail_jump_sites": fn_counters["import_tail_jump_sites"],
            "unresolved_indirect_call_sites": fn_counters["indirect_call_sites"],
            "unresolved_indirect_jump_sites": fn_counters["indirect_jump_sites"],
            "conditional_branch_sites": fn_counters["conditional_branch_sites"],
            "return_sites": fn_counters["return_sites"],
            "tail_jump_candidates": fn_counters["tail_jump_candidates"],
            "other_seed_boundaries": terminal_counts["entered_other_root"],
            "decode_or_section_boundaries": terminal_counts["decode_or_section_boundary"],
            "truncated": str(maxed).lower(),
            "coverage_note": "Rooted recursive CFG candidate; not a validated complete function body or runtime-reachable path.",
        }

    def run(self) -> None:
        while self.function_queue:
            root = self.function_queue.popleft()
            if root in self.functions:
                continue
            if len(self.functions) >= self.max_functions:
                break
            self.process_function(root)


def discover_roots(image_path: Path, docs_dir: Path) -> tuple[dict[int, set[str]], dict[str, int]]:
    parsed_image = mfc_maps.PEImage(image_path)
    maps = mfc_maps.discover_maps(parsed_image)
    roots: dict[int, set[str]] = defaultdict(set)
    source_counts: Counter[str] = Counter()
    mfc_handler_roots: set[int] = set()
    vtable_target_roots: set[int] = set()
    entrypoint_va = IMAGE_BASE + int(pefile.PE(str(image_path), fast_load=True).OPTIONAL_HEADER.AddressOfEntryPoint)
    roots[entrypoint_va].add("PE entrypoint")
    source_counts["PE entrypoint"] = 1
    for record in maps:
        owners = record["owner_evidence"]
        owner_names = ",".join(item[0] for item in owners) if owners else "owner-unresolved"
        for index, entry in enumerate(record["entries"]):
            source = (
                f"MFC handler accessor={hx(int(record['accessor_va']))}"
                f" owner={owner_names} entry={index} message={hx(entry.message)}"
                        f" code={hx(entry.code)} id_range={hx(entry.first_id)}-{hx(entry.last_id)}"
                        f" map_entry_va={hx(entry.va)}"
            )
            roots[entry.handler].add(source)
            mfc_handler_roots.add(entry.handler)
            source_counts["MFC message-map rows"] += 1
    vtable_rows = 0
    vtable_input_hashes: dict[str, str] = {}
    for filename in VTABLE_FILES:
        path = docs_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"required hash-pinned vtable evidence is missing: {path}")
        csv_hash = sha256(path.read_bytes())
        expected_hash = EXPECTED_VTABLE_HASHES[filename]
        if csv_hash != expected_hash:
            raise ValueError(f"Refusing unrecognized {filename}: sha256={csv_hash}; expected {expected_hash}")
        vtable_input_hashes[filename] = csv_hash
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            for row in csv.DictReader(stream):
                if row.get("status", "").lower() != "proven":
                    continue
                try:
                    target = int(row["target_va"], 16)
                except (KeyError, ValueError):
                    continue
                source = f"proven vtable target {filename} slot={row.get('slot_index','?')} role={row.get('role','?')}"
                roots[target].add(source)
                vtable_target_roots.add(target)
                vtable_rows += 1
    source_counts["proven vtable entries"] = vtable_rows
    source_counts["unique initial roots"] = len(roots)
    source_counts["unique MFC handler roots"] = len(mfc_handler_roots)
    source_counts["unique proven vtable target roots"] = len(vtable_target_roots)
    source_counts["validated MFC maps"] = len(maps)
    source_counts["validated MFC entries"] = sum(len(record["entries"]) for record in maps)
    return dict(roots), dict(source_counts), vtable_input_hashes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Hash-matched 4.6 DeviceDriver.exe")
    parser.add_argument("--docs-dir", type=Path, default=Path("docs"), help="Repository docs directory")
    parser.add_argument("--output-dir", type=Path, default=Path("docs"), help="Output directory")
    args = parser.parse_args()
    image_path = args.image.resolve()
    data = image_path.read_bytes()
    digest = sha256(data)
    if len(data) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        print(f"Refusing unexpected input: size={len(data)} sha256={digest}", file=sys.stderr)
        return 2
    pe = pefile.PE(data=data, fast_load=False)
    if int(pe.FILE_HEADER.Machine) != 0x14C or int(pe.OPTIONAL_HEADER.Magic) != 0x10B:
        print("Refusing unexpected architecture; expected x86 PE32", file=sys.stderr)
        return 2

    roots, seed_counts, vtable_input_hashes = discover_roots(image_path, args.docs_dir.resolve())
    analyzer = RootedCFG(image_path, data, roots)
    analyzer.run()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)

    function_rows = [analyzer.functions[key] for key in sorted(analyzer.functions)]
    for row in function_rows:
        row["root_va"] = hx(int(row["root_va"]))
    edge_rows = [
        {
            "caller_root_va": hx(caller), "site_va": hx(site), "target_va": hx(target),
            "edge_kind": kind, "import_symbol": symbol, "confidence": confidence,
            "note": note if kind in {"unresolved_indirect_call", "unresolved_indirect_jump", "tail_jump_candidate"} else "",
        }
        for caller, site, target, kind, symbol, confidence, note in sorted(
            analyzer.edges, key=lambda edge: (edge[0], edge[1], edge[3], edge[2] or 0)
        )
    ]
    block_rows = [
        {
            "function_root_va": hx(root), "block_start_va": hx(start), "last_instruction_va": hx(last),
            "instruction_count": count, "terminator": term, "successor_vas": successors,
        }
        for root, start, last, count, term, successors in sorted(
            analyzer.blocks, key=lambda block: (block[0], block[1])
        )
    ]
    write_csv(out / "rk-v4.6-rooted-cfg-functions.csv", list(function_rows[0].keys()) if function_rows else ["root_va"], function_rows)
    write_csv(out / "rk-v4.6-rooted-cfg-edges.csv",
              ["caller_root_va", "site_va", "target_va", "edge_kind", "import_symbol", "confidence", "note"], edge_rows)
    write_csv(out / "rk-v4.6-rooted-cfg-blocks.csv",
              ["function_root_va", "block_start_va", "last_instruction_va", "instruction_count", "terminator", "successor_vas"], block_rows)

    edge_counts = Counter(row["edge_kind"] for row in edge_rows)
    unique_edge_sites: dict[str, set[tuple[str, str | None, str]]] = defaultdict(set)
    api_sites: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for row in edge_rows:
        unique_edge_sites[row["edge_kind"]].add((row["site_va"], row["target_va"], row["import_symbol"]))
        if row["edge_kind"] in {"import_call", "import_tail_jump"}:
            api_sites[row["import_symbol"]].add((row["site_va"], row["edge_kind"]))
    overlaps = {va: owners for va, owners in analyzer.instruction_owners.items() if len(owners) > 1}
    reached_code_bytes: set[int] = set()
    for va in analyzer.instruction_owners:
        instruction = analyzer.instruction_cache.get(va)
        if instruction is not None:
            reached_code_bytes.update(range(va, va + instruction.size))
    executable_raw_bytes = sum(section.raw_size for section in analyzer.exec_sections)
    summary = {
        "analysis": "root-seeded recursive CFG and call-edge candidate scan",
        "completeness_label": "bounded static CFG candidates; not a complete function map, CFG, or call graph",
        "input": {"filename": image_path.name, "size_bytes": len(data), "sha256": digest,
                  "image_base": hx(int(pe.OPTIONAL_HEADER.ImageBase)),
                  "entrypoint_va": hx(int(pe.OPTIONAL_HEADER.ImageBase) + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint))},
        "analysis_script_sha256": sha256(Path(__file__).read_bytes()),
        "seed_counts": seed_counts,
        "supporting_vtable_csv_sha256": vtable_input_hashes,
        "mfc_scanner_sha256": sha256(Path(mfc_maps.__file__).read_bytes()),
        "results": {
            "processed_function_roots": len(function_rows),
            "decoded_instruction_instances": sum(int(row["instruction_count"]) for row in function_rows),
            "unique_decoded_instruction_addresses": len(analyzer.instruction_owners),
            "unique_instruction_bytes_covered": len(reached_code_bytes),
            "executable_section_raw_bytes": executable_raw_bytes,
            "executable_section_byte_coverage_percent": round(100 * len(reached_code_bytes) / executable_raw_bytes, 2),
            "instruction_addresses_claimed_by_multiple_roots": len(overlaps),
            "basic_blocks": len(block_rows),
            "edge_context_rows_by_kind": dict(sorted(edge_counts.items())),
            "unique_instruction_edges_by_kind": {key: len(value) for key, value in sorted(unique_edge_sites.items())},
            "unique_imported_api_transfer_sites": sum(len(value) for value in api_sites.values()),
            "unique_import_symbols": len(api_sites),
            "import_symbols_with_rooted_sites": {key: len(value) for key, value in sorted(api_sites.items())},
            "functions_truncated_by_limits": sum(row["truncated"] == "true" for row in function_rows),
        },
        "tooling": {"python": sys.version.split()[0], "pefile": getattr(pefile, "__version__", "unknown"),
                    "capstone": capstone.__version__, "decoder": "Capstone x86-32, recursive branch traversal"},
        "generated_ledger_sha256": {
            "rk-v4.6-rooted-cfg-functions.csv": sha256((out / "rk-v4.6-rooted-cfg-functions.csv").read_bytes()),
            "rk-v4.6-rooted-cfg-edges.csv": sha256((out / "rk-v4.6-rooted-cfg-edges.csv").read_bytes()),
            "rk-v4.6-rooted-cfg-blocks.csv": sha256((out / "rk-v4.6-rooted-cfg-blocks.csv").read_bytes()),
        },
        "limits": [
            "Roots are the PE entrypoint, structurally validated MFC message handlers, proven entries in three audited device-family vtables, and internal direct-call targets discovered from them.",
            "Conditional branches are followed both ways without evaluating flags; branch reachability is not established.",
            "A decoded direct-call target is a function-entry candidate, not independently validated as a function boundary.",
            "Unconditional jumps into another root or a common frame prologue are recorded as tail-jump candidates; other unconditional jumps are followed as intra-function branches.",
            "Computed/register/vtable/callback/COM/dynamic targets remain unresolved unless an exact IAT memory operand identifies the imported API.",
            "This scan does not cover code that is not reached from the selected static roots, and static control flow does not prove runtime reachability or behavior.",
            "The target was not executed; no device interface was opened and no HID/serial/Bluetooth operation was performed.",
        ],
    }
    (out / "rk-v4.6-rooted-cfg-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    console_summary = {
        "input": summary["input"],
        "seed_counts": summary["seed_counts"],
        "results": {key: value for key, value in summary["results"].items()
                    if key != "import_symbols_with_rooted_sites"},
        "import_symbol_count": len(api_sites),
    }
    print(json.dumps(console_summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
