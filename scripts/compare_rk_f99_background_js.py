#!/usr/bin/env python3
"""Compare the hash-pinned F99 macOS and Windows background.js members.

The scanner reads archive members in memory, splits the Webpack-style module
factory array using a conservative JavaScript lexer, records exact-content
module matches across array indexes, and aligns changed blocks only in the
common entry's direct changed child. It writes offset/hash evidence only. It
never executes target JavaScript or writes extracted member source files.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
import re
import sys
import tempfile
from bisect import bisect_left
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from audit_rk_f99_macos_dmg import materialize_partition, read_dmg  # noqa: E402
from compare_rk_f99_asar_members import (  # noqa: E402
    DEFAULT_MAC_ASAR_OFFSET,
    inspect_archive,
)


PINNED = {
    "dmg": "d0f624aab5caf23c008c0024a63c3c438c9d5c3340503dc770f4957bae2e1951",
    "windows_asar": "38ebbf1416050d9ab36eee4910ec86130a0919b69334ec3751378f7f00ff2bdf",
    "mac_asar_extent": "a6b3783602040407932e95e9237cbabb774690bad515d51c21fd59c9f74279db",
    "mac_background_js": "7d24ec44fde96911790ed9578bdec76943868a30b5b2a0b63dbe23bad6c5ab30",
    "windows_background_js": "8db60b45ce93fc20f68950ebb97db0640d6384c3808b06e43c332d8ef4183277",
}


@dataclass(frozen=True)
class Token:
    start: int
    end: int
    raw: bytes
    kind: str


def sha256(data: bytes | mmap.mmap) -> str:
    digest = hashlib.sha256()
    view = memoryview(data)
    for start in range(0, len(view), 1024 * 1024):
        digest.update(view[start:start + 1024 * 1024])
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_hash(label: str, actual: str) -> None:
    expected = PINNED[label]
    if actual != expected:
        raise ValueError(f"{label} SHA-256 mismatch: {actual} != {expected}")


def is_ident_start(value: int) -> bool:
    return value == 36 or value == 95 or value >= 128 or 65 <= value <= 90 or 97 <= value <= 122


def is_ident_part(value: int) -> bool:
    return is_ident_start(value) or 48 <= value <= 57


def scan_quoted(source: bytes, index: int, quote: int) -> int:
    index += 1
    while index < len(source):
        value = source[index]
        if value == 92:
            index += 2
        elif value == quote:
            return index + 1
        else:
            index += 1
    return len(source)


def scan_template(source: bytes, index: int) -> int:
    index += 1
    while index < len(source):
        value = source[index]
        if value == 92:
            index += 2
        elif value == 96:
            return index + 1
        else:
            index += 1
    return len(source)


def scan_regex(source: bytes, index: int) -> int:
    index += 1
    in_class = False
    while index < len(source):
        value = source[index]
        if value in (10, 13):
            return index
        if value == 92:
            index += 2
            continue
        if value == 91:
            in_class = True
        elif value == 93:
            in_class = False
        elif value == 47 and not in_class:
            index += 1
            while index < len(source) and is_ident_part(source[index]):
                index += 1
            return index
        index += 1
    return index


REGEX_PREFIXES = {
    b"(", b"[", b"{", b",", b";", b":", b"=", b"!", b"?", b"~",
    b"+", b"-", b"*", b"%", b"&", b"|", b"^", b"<", b">", b"=>",
    b"&&", b"||", b"??", b"return", b"throw", b"case", b"delete",
    b"void", b"typeof", b"new", b"in", b"of", b"yield", b"await",
}


def iter_js_tokens(source: bytes, start: int = 0, end: int | None = None):
    if end is None:
        end = len(source)
    i = start
    punctuators = (b"===", b"!==", b">>>", b"**=", b"...", b"=>", b"==", b"!=", b"<=", b">=", b"++", b"--", b"&&", b"||", b"??", b"?.", b"+=", b"-=", b"*=", b"/=", b"%=", b"<<", b">>", b"**")
    previous: Token | None = None

    while i < end:
        value = source[i]
        if value <= 32:
            i += 1
            continue
        if source.startswith(b"//", i):
            newline = source.find(b"\n", i + 2, end)
            i = end if newline < 0 else newline + 1
            continue
        if source.startswith(b"/*", i):
            close = source.find(b"*/", i + 2, end)
            i = end if close < 0 else close + 2
            continue
        if value in (34, 39):
            finish = min(scan_quoted(source, i, value), end)
            token = Token(i, finish, source[i:finish], "string")
        elif value == 96:
            finish = min(scan_template(source, i), end)
            token = Token(i, finish, source[i:finish], "template")
        elif value == 47:
            previous_value = previous.raw if previous else b""
            regex_allowed = previous is None or previous_value in REGEX_PREFIXES or previous.kind == "operator"
            if regex_allowed:
                finish = min(scan_regex(source, i), end)
                token = Token(i, finish, source[i:finish], "regex")
            else:
                token = Token(i, i + 1, b"/", "operator")
        elif is_ident_start(value):
            finish = i + 1
            while finish < end and is_ident_part(source[finish]):
                finish += 1
            token = Token(i, finish, source[i:finish], "identifier")
        elif 48 <= value <= 57:
            finish = i + 1
            while finish < end and (is_ident_part(source[finish]) or source[finish] in b"._"):
                finish += 1
            token = Token(i, finish, source[i:finish], "number")
        else:
            found = next((item for item in punctuators if source.startswith(item, i) and i + len(item) <= end), None)
            if found:
                finish = i + len(found)
                token = Token(i, finish, found, "operator")
            else:
                finish = i + 1
                token = Token(i, finish, source[i:finish], "punctuation")
        yield token
        previous = token
        i = token.end


def lex_js(source: bytes, start: int = 0, end: int | None = None) -> list[Token]:
    return list(iter_js_tokens(source, start, end))


def find_bundle_array(source: bytes) -> tuple[int, int]:
    match = re.search(rb"n\(\s*n\.s\s*=\s*(\d+)\s*\)\}\s*\(", source)
    if not match:
        raise ValueError("could not locate webpack entry dispatch n(n.s=<id>)")
    entry_id = int(match.group(1))
    opening = match.end()
    while opening < len(source) and source[opening] <= 32:
        opening += 1
    if opening >= len(source) or source[opening] != 91:
        raise ValueError("webpack entry dispatch is not followed by a module array")
    return entry_id, opening


def split_modules(source: bytes) -> tuple[int, list[tuple[int, int, bytes]]]:
    entry_id, opening = find_bundle_array(source)
    tokens = iter_js_tokens(source, opening, len(source))
    first = next(tokens, None)
    if first is None or first.raw != b"[":
        raise ValueError("module array opening token not lexed")
    stack = [b"["]
    matching = {b")": b"(", b"]": b"[", b"}": b"{"}
    modules: list[tuple[int, int, bytes]] = []
    module_start = first.end
    for token in tokens:
        if token.raw in (b"(", b"[", b"{"):
            stack.append(token.raw)
        elif token.raw in matching:
            if not stack or stack[-1] != matching[token.raw]:
                raise ValueError(f"unbalanced JavaScript delimiter at byte {token.start}")
            if len(stack) == 1 and token.raw == b"]":
                if source[module_start:token.start].strip():
                    modules.append((module_start, token.start, source[module_start:token.start].strip()))
                return entry_id, modules
            stack.pop()
        elif token.raw == b"," and len(stack) == 1:
            chunk = source[module_start:token.start].strip()
            if chunk:
                leading = len(source[module_start:token.start]) - len(source[module_start:token.start].lstrip())
                trailing = len(source[module_start:token.start]) - len(source[module_start:token.start].rstrip())
                actual_start = module_start + leading
                actual_end = token.start - trailing
                modules.append((actual_start, actual_end, source[actual_start:actual_end]))
            module_start = token.end
    raise ValueError("unterminated webpack module array")


def module_require_parameter(module: bytes) -> bytes | None:
    match = re.match(rb"\s*function\s*\(([^)]*)\)", module)
    if not match:
        return None
    params = [part.strip() for part in match.group(1).split(b",")]
    if len(params) < 3 or not re.fullmatch(rb"[A-Za-z_$][A-Za-z0-9_$]*", params[2]):
        return None
    return params[2]


def module_requires(module: bytes) -> list[int]:
    require_name = module_require_parameter(module)
    if not require_name:
        return []
    tokens = lex_js(module)
    edges: set[int] = set()
    for index in range(len(tokens) - 3):
        if (tokens[index].raw == require_name and tokens[index + 1].raw == b"("
                and tokens[index + 2].kind == "number" and tokens[index + 3].raw == b")"):
            try:
                edges.add(int(tokens[index + 2].raw, 0))
            except ValueError:
                pass
    return sorted(edges)


def find_functions(source: bytes, module_start: int, module_end: int) -> list[tuple[int, int, str]]:
    tokens = lex_js(source, module_start, module_end)
    matching = {b")": b"(", b"]": b"[", b"}": b"{"}

    def closing(open_index: int, opening_value: bytes) -> int | None:
        close_value = {b"(": b")", b"[": b"]", b"{": b"}"}[opening_value]
        depth = 0
        for cursor in range(open_index, len(tokens)):
            if tokens[cursor].raw == opening_value:
                depth += 1
            elif tokens[cursor].raw == close_value:
                depth -= 1
                if depth == 0:
                    return cursor
            elif tokens[cursor].raw in matching and tokens[cursor].raw != close_value:
                if cursor and tokens[cursor].raw == b"}":
                    continue
        return None

    functions: list[tuple[int, int, str]] = []
    for index, token in enumerate(tokens):
        if token.raw != b"function":
            continue
        cursor = index + 1
        if cursor < len(tokens) and tokens[cursor].raw == b"*":
            cursor += 1
        name = "anonymous"
        if cursor < len(tokens) and tokens[cursor].kind == "identifier":
            name = tokens[cursor].raw.decode("utf-8", "replace")
            cursor += 1
        if cursor >= len(tokens) or tokens[cursor].raw != b"(":
            continue
        params_end = closing(cursor, b"(")
        if params_end is None or params_end + 1 >= len(tokens) or tokens[params_end + 1].raw != b"{":
            continue
        body_end = closing(params_end + 1, b"{")
        if body_end is None:
            continue
        functions.append((token.start, tokens[body_end].end, name))
    return functions


def function_context(functions: list[tuple[int, int, str]], start: int, end: int) -> str:
    candidates = [item for item in functions if item[0] <= start and item[1] >= end]
    candidates.sort(key=lambda item: item[1] - item[0])
    names = [item[2] for item in candidates[:4]]
    return ";".join(names) if names else "no single enclosing function range"


def token_range(tokens: list[Token], first: int, last: int, module_start: int) -> tuple[int, int]:
    if first < last:
        return tokens[first].start, tokens[last - 1].end
    if first < len(tokens):
        return tokens[first].start, tokens[first].start
    if tokens:
        return tokens[-1].end, tokens[-1].end
    return module_start, module_start


def unique_token_anchors(left: list[Token], right: list[Token], width: int = 10) -> list[tuple[int, int]]:
    """Return an ordered set of exact common token-window starts.

    Only windows unique on both sides are candidates. A longest-increasing
    subsequence of their right-side indexes gives a deterministic monotone
    alignment without the quadratic worst case of SequenceMatcher on large,
    highly similar minified bundles.
    """
    if len(left) < width or len(right) < width:
        return []

    def windows(tokens: list[Token]) -> dict[bytes, tuple[int, int]]:
        found: dict[bytes, tuple[int, int]] = {}
        for index in range(len(tokens) - width + 1):
            digest = hashlib.blake2s(digest_size=12)
            for token in tokens[index:index + width]:
                digest.update(len(token.raw).to_bytes(4, "little"))
                digest.update(token.raw)
            key = digest.digest()
            previous = found.get(key)
            found[key] = (2, -1) if previous is not None else (1, index)
        return found

    left_windows = windows(left)
    right_windows = windows(right)
    candidates: list[tuple[int, int]] = []
    for key, (left_count, left_index) in left_windows.items():
        right_value = right_windows.get(key)
        if left_count != 1 or left_index < 0 or right_value is None or right_value[0] != 1:
            continue
        right_index = right_value[1]
        # A digest is a compact index only; confirm exact token equality.
        if all(left[left_index + offset].raw == right[right_index + offset].raw for offset in range(width)):
            candidates.append((left_index, right_index))
    candidates.sort()

    tails: list[int] = []
    tail_candidate_indices: list[int] = []
    previous_candidate = [-1] * len(candidates)
    for candidate_index, (_, right_index) in enumerate(candidates):
        slot = bisect_left(tails, right_index)
        if slot == len(tails):
            tails.append(right_index)
            tail_candidate_indices.append(candidate_index)
        else:
            tails[slot] = right_index
            tail_candidate_indices[slot] = candidate_index
        if slot:
            previous_candidate[candidate_index] = tail_candidate_indices[slot - 1]

    if not tail_candidate_indices:
        return []
    selected: list[tuple[int, int]] = []
    cursor = tail_candidate_indices[-1]
    while cursor >= 0:
        selected.append(candidates[cursor])
        cursor = previous_candidate[cursor]
    selected.reverse()
    return selected


def anchored_opcodes(left: list[Token], right: list[Token], width: int = 10) -> list[tuple[str, int, int, int, int]]:
    """Produce coarse replace/insert/delete spans bounded by common anchors."""
    anchors = unique_token_anchors(left, right, width)
    matched: list[tuple[int, int, int, int]] = []
    for left_start, right_start in anchors:
        candidate = (left_start, left_start + width, right_start, right_start + width)
        if matched and candidate[0] <= matched[-1][1] and candidate[2] <= matched[-1][3]:
            old = matched[-1]
            if candidate[0] - old[0] == candidate[2] - old[2]:
                matched[-1] = (old[0], max(old[1], candidate[1]), old[2], max(old[3], candidate[3]))
                continue
        if matched and (candidate[0] < matched[-1][1] or candidate[2] < matched[-1][3]):
            continue
        matched.append(candidate)

    opcodes: list[tuple[str, int, int, int, int]] = []
    left_cursor = right_cursor = 0
    for left_start, left_end, right_start, right_end in matched:
        if left_start > left_cursor or right_start > right_cursor:
            kind = "replace" if left_start > left_cursor and right_start > right_cursor else (
                "delete" if left_start > left_cursor else "insert"
            )
            opcodes.append((kind, left_cursor, left_start, right_cursor, right_start))
        left_cursor = left_end
        right_cursor = right_end
    if left_cursor < len(left) or right_cursor < len(right):
        kind = "replace" if left_cursor < len(left) and right_cursor < len(right) else (
            "delete" if left_cursor < len(left) else "insert"
        )
        opcodes.append((kind, left_cursor, len(left), right_cursor, len(right)))
    if not opcodes and (left or right):
        # No common unique windows; retain a transparent whole-module span.
        opcodes.append(("replace", 0, len(left), 0, len(right)))
    return opcodes


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def content_identity_rows(module_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    groups: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for row in module_rows:
        for platform in ("mac", "windows"):
            digest = row[f"{platform}_sha256"]
            group = groups.setdefault(digest, {"mac": [], "windows": []})
            group[platform].append({"module_id": int(row["module_id"]), "bytes": int(row[f"{platform}_bytes"])})

    identity_rows: list[dict[str, Any]] = []
    exact_pair_count = 0
    shared_digest_count = 0
    duplicate_shared_digest_count = 0
    same_slot_exact_count = 0
    mac_unmatched = 0
    windows_unmatched = 0
    for digest in sorted(groups):
        mac_items = groups[digest]["mac"]
        windows_items = groups[digest]["windows"]
        shared = bool(mac_items and windows_items)
        same_slot = sorted(item["module_id"] for item in mac_items
                           if any(other["module_id"] == item["module_id"] for other in windows_items))
        if shared:
            shared_digest_count += 1
            exact_pair_count += min(len(mac_items), len(windows_items))
            same_slot_exact_count += len(same_slot)
            if len(mac_items) > 1 or len(windows_items) > 1:
                duplicate_shared_digest_count += 1
            classification = (
                "shared exact bytes; duplicate module IDs make mapping ambiguous"
                if len(mac_items) > 1 or len(windows_items) > 1
                else "shared exact bytes; module array ID may differ"
            )
        else:
            classification = "no exact-content peer in opposite module array"
            mac_unmatched += len(mac_items)
            windows_unmatched += len(windows_items)
        identity_rows.append({
            "content_sha256": digest,
            "mac_module_ids": ";".join(str(item["module_id"]) for item in mac_items),
            "mac_bytes": ";".join(str(item["bytes"]) for item in mac_items),
            "windows_module_ids": ";".join(str(item["module_id"]) for item in windows_items),
            "windows_bytes": ";".join(str(item["bytes"]) for item in windows_items),
            "same_numeric_id_exact_match_ids": ";".join(str(item) for item in same_slot),
            "classification": classification,
            "evidence_limit": "exact factory bytes are matched by SHA-256; byte identity does not establish semantic identity when duplicate factories exist",
        })
    return identity_rows, {
        "content_hash_groups_shared": shared_digest_count,
        "exact_content_pair_count_lower_bound": exact_pair_count,
        "same_numeric_id_exact_matches": same_slot_exact_count,
        "possible_exact_content_relocations_lower_bound": exact_pair_count - same_slot_exact_count,
        "shared_duplicate_hash_groups": duplicate_shared_digest_count,
        "mac_modules_without_any_exact_hash_peer": mac_unmatched,
        "windows_modules_without_any_exact_hash_peer": windows_unmatched,
    }


def graph_paths(entry_id: int, graph: dict[int, list[int]], targets: set[int]) -> dict[int, str]:
    paths = {entry_id: str(entry_id)}
    pending = deque([entry_id])
    while pending:
        parent = pending.popleft()
        for child in graph.get(parent, []):
            if child not in paths:
                paths[child] = paths[parent] + ">" + str(child)
                if child in targets and targets.issubset(paths.keys()):
                    return paths
                pending.append(child)
    return paths


def extract_member(archive: dict[str, Any], path: str) -> bytes:
    entry = archive["entries"].get(path)
    if not entry or entry["kind"] != "file":
        raise ValueError(f"archive member missing or not a packed file: {path}")
    meta = entry["metadata"]
    start = archive["payload_start"] + int(meta["offset"])
    size = int(meta["size"])
    data = bytes(archive["image"][start:start + size])
    expected = archive["hashes"].get(path)
    actual = hashlib.sha256(data).hexdigest()
    if expected and actual != expected:
        raise ValueError(f"member hash mismatch for {path}: {actual} != {expected}")
    return data


def compare_member_modules(mac_source: bytes, windows_source: bytes, include_blocks: bool = True) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    mac_entry_id, mac_modules = split_modules(mac_source)
    win_entry_id, win_modules = split_modules(windows_source)
    if mac_entry_id != win_entry_id:
        raise ValueError(f"bundle entry IDs differ: macOS={mac_entry_id}, Windows={win_entry_id}")
    if len(mac_modules) != len(win_modules):
        raise ValueError(f"module counts differ: macOS={len(mac_modules)}, Windows={len(win_modules)}")

    module_rows: list[dict[str, Any]] = []
    changed_ids: set[int] = set()
    graph: dict[int, list[int]] = {}
    module_context: dict[int, dict[str, Any]] = {}
    keyword_rows: list[dict[str, Any]] = []
    for module_id, (mac_range, win_range) in enumerate(zip(mac_modules, win_modules)):
        ms, me, mb = mac_range
        ws, we, wb = win_range
        mh, wh = hashlib.sha256(mb).hexdigest(), hashlib.sha256(wb).hexdigest()
        mac_edges = module_requires(mb)
        win_edges = module_requires(wb)
        graph[module_id] = sorted(set(mac_edges) | set(win_edges))
        changed = mh != wh
        if changed:
            changed_ids.add(module_id)
        module_context[module_id] = {
            "mac_start": ms, "mac_end": me, "win_start": ws, "win_end": we,
            "mac": mb, "windows": wb, "mac_edges": mac_edges, "win_edges": win_edges,
        }
        module_rows.append({
            "module_id": module_id,
            "status": "changed" if changed else "identical",
            "mac_bundle_offset_start": ms,
            "mac_bundle_offset_end": me,
            "mac_bytes": len(mb),
            "mac_sha256": mh,
            "windows_bundle_offset_start": ws,
            "windows_bundle_offset_end": we,
            "windows_bytes": len(wb),
            "windows_sha256": wh,
            "mac_static_require_ids": json.dumps(mac_edges, separators=(",", ":")),
            "windows_static_require_ids": json.dumps(win_edges, separators=(",", ":")),
            "static_require_edges_changed": "yes" if mac_edges != win_edges else "no",
        })
        for platform, data, start in (("macOS", mb, ms), ("Windows", wb, ws)):
            for marker in (b"mi-hid", b"hidapi", b"node/hid", b"IOHID", b"HidD_"):
                occurrences = [m.start() for m in re.finditer(re.escape(marker), data)]
                if occurrences:
                    keyword_rows.append({
                        "platform": platform,
                        "module_id": module_id,
                        "marker": marker.decode("ascii"),
                        "module_relative_occurrences": json.dumps(occurrences, separators=(",", ":")),
                        "bundle_absolute_offsets": json.dumps([start + pos for pos in occurrences], separators=(",", ":")),
                        "module_sha256": mh if platform == "macOS" else wh,
                        "evidence_limit": "literal string/identifier bytes in module; does not by itself prove invocation or device access",
                    })

    mac_entry_edges = set(module_requires(module_context[mac_entry_id]["mac"]))
    win_entry_edges = set(module_requires(module_context[win_entry_id]["windows"]))
    direct_entry_module_ids = sorted(mac_entry_edges & win_entry_edges)
    entry_paths = graph_paths(mac_entry_id, graph, set(direct_entry_module_ids))
    block_rows: list[dict[str, Any]] = []
    focused_block_ids = sorted(set(direct_entry_module_ids) & changed_ids) if include_blocks else []
    for module_id in focused_block_ids:
        context = module_context[module_id]
        mb = context["mac"]
        wb = context["windows"]
        ms = int(context["mac_start"])
        ws = int(context["win_start"])
        mac_tokens = lex_js(mb)
        win_tokens = lex_js(wb)
        opcodes = anchored_opcodes(mac_tokens, win_tokens)
        mac_functions = find_functions(mb, 0, len(mb))
        win_functions = find_functions(wb, 0, len(wb))
        hunk_index = 0
        for opcode, mi1, mi2, wi1, wi2 in opcodes:
            hunk_index += 1
            mstart, mend = token_range(mac_tokens, mi1, mi2, 0)
            wstart, wend = token_range(win_tokens, wi1, wi2, 0)
            mspan = mb[mstart:mend]
            wspan = wb[wstart:wend]
            block_rows.append({
                "module_id": module_id,
                "hunk_id": hunk_index,
                "change_kind": opcode,
                "entry_to_module_static_path": entry_paths.get(module_id, "not reachable by literal require edges"),
                "mac_bundle_start": ms + mstart,
                "mac_bundle_end_exclusive": ms + mend,
                "mac_bytes": len(mspan),
                "mac_sha256": hashlib.sha256(mspan).hexdigest(),
                "windows_bundle_start": ws + wstart,
                "windows_bundle_end_exclusive": ws + wend,
                "windows_bytes": len(wspan),
                "windows_sha256": hashlib.sha256(wspan).hexdigest(),
                "mac_enclosing_function_candidates": function_context(mac_functions, mstart, mend),
                "windows_enclosing_function_candidates": function_context(win_functions, wstart, wend),
                "mac_changed_token_count": mi2 - mi1,
                "windows_changed_token_count": wi2 - wi1,
                "evidence_limit": "span between unique common 10-token anchors; exact byte offsets/hash, coarse and not a minimal edit script or proof of runtime reachability",
            })

    worker_literal_rows: list[dict[str, Any]] = []
    worker_literal_hashes: dict[str, str] = {}
    if 607 in module_context:
        for platform, source_key, start_key in (("macOS", "mac", "mac_start"), ("Windows", "windows", "win_start")):
            context = module_context[607]
            data = context[source_key]
            module_start = int(context[start_key])
            tokens = lex_js(data)
            for index in range(len(tokens) - 2):
                if (tokens[index].raw == b"Worker" and tokens[index + 1].raw == b"("
                        and tokens[index + 2].kind == "string"
                        and b"hidName = workerData.hidName" in tokens[index + 2].raw):
                    literal = tokens[index + 2]
                    literal_hash = hashlib.sha256(literal.raw).hexdigest()
                    worker_literal_hashes[platform] = literal_hash
                    worker_literal_rows.append({
                        "platform": platform,
                        "module_id": 607,
                        "marker": "hid-worker-source-string-literal",
                        "module_relative_occurrences": json.dumps([literal.start], separators=(",", ":")),
                        "bundle_absolute_offsets": json.dumps([module_start + literal.start], separators=(",", ":")),
                        "module_sha256": hashlib.sha256(data).hexdigest(),
                        "literal_raw_bytes": len(literal.raw),
                        "literal_raw_sha256": literal_hash,
                        "evidence_limit": "escaped JavaScript string token contains a worker script with dynamic require and HID constructor; token equality is static, not execution",
                    })
    keyword_rows.extend(worker_literal_rows)
    worker_literal_same = (
        worker_literal_hashes.get("macOS") is not None
        and worker_literal_hashes.get("macOS") == worker_literal_hashes.get("Windows")
    )

    identity_rows, identity_summary = content_identity_rows(module_rows)
    summary = {
        "entry_id": mac_entry_id,
        "module_count": len(mac_modules),
        "same_numeric_id_changed_module_count": len(changed_ids),
        "same_numeric_id_identical_module_count": len(mac_modules) - len(changed_ids),
        "changed_block_count": len(block_rows),
        "direct_entry_module_ids_in_both_builds": direct_entry_module_ids,
        "focused_changed_block_module_ids": focused_block_ids,
        "native_marker_modules": sorted({row["module_id"] for row in keyword_rows if row["marker"] == "mi-hid"}),
        "keyword_rows": len(keyword_rows),
        "hid_worker_source_literal_same_raw_token": worker_literal_same,
        "hid_worker_source_literal_sha256": worker_literal_hashes.get("macOS"),
        "hid_worker_source_literal_rows": len(worker_literal_rows),
        **identity_summary,
    }
    return module_rows, block_rows, {"summary": summary, "keyword_rows": keyword_rows, "identity_rows": identity_rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dmg", type=Path, nargs="?", default=ROOT.parent / ".research/rk-selector-software-2026-10-19/RK-3.2.2-universal.dmg")
    parser.add_argument("windows_asar", type=Path, nargs="?", default=ROOT.parent / ".research/F99_3.2.2_static/selected/resources/app.asar")
    parser.add_argument("--mac-asar-offset", type=lambda value: int(value, 0), default=DEFAULT_MAC_ASAR_OFFSET)
    parser.add_argument("--blocks-csv", type=Path, default=ROOT / "docs/rk-f99-background-js-change-blocks-2026-10-20.csv")
    parser.add_argument("--modules-csv", type=Path, default=ROOT / "docs/rk-f99-background-js-module-diff-2026-10-20.csv")
    parser.add_argument("--markers-csv", type=Path, default=ROOT / "docs/rk-f99-background-js-static-boundary-markers-2026-10-20.csv")
    parser.add_argument("--identity-csv", type=Path, default=ROOT / "docs/rk-f99-background-js-content-identity-map-2026-10-20.csv")
    parser.add_argument("--modules-only", action="store_true", help="skip token-aligned changed-block output for a quick module inventory")
    args = parser.parse_args()
    dmg_path, windows_path = args.dmg.resolve(), args.windows_asar.resolve()
    verify_hash("dmg", sha256_file(dmg_path))
    verify_hash("windows_asar", sha256_file(windows_path))

    dmg_header, entries = read_dmg(dmg_path)
    apfs_entry = next((entry for entry in entries if "Apple_APFS" in str(entry["name"])), None)
    if apfs_entry is None:
        raise ValueError("DMG has no Apple_APFS block map")

    with dmg_path.open("rb") as dmg_stream, tempfile.TemporaryFile(mode="w+b") as partition:
        materialize_partition(dmg_stream, int(dmg_header["data_fork_offset"]), apfs_entry, partition)
        partition.flush()
        with mmap.mmap(partition.fileno(), 0, access=mmap.ACCESS_READ) as mac_image:
            mac_archive = inspect_archive(mac_image, args.mac_asar_offset, "macOS")
            verify_hash("mac_asar_extent", mac_archive["extent_sha256"])
            with windows_path.open("rb") as windows_stream, mmap.mmap(windows_stream.fileno(), 0, access=mmap.ACCESS_READ) as windows_image:
                win_archive = inspect_archive(windows_image, 0, "Windows")
                mac_meta = mac_archive["package"]
                win_meta = win_archive["package"]
                for platform, metadata in (("macOS", mac_meta), ("Windows", win_meta)):
                    if (metadata.get("name"), metadata.get("version"), metadata.get("main")) != ("RK", "3.2.2", "background.js"):
                        raise ValueError(f"{platform} ASAR package identity mismatch: {metadata}")
                mac_source = extract_member(mac_archive, "background.js")
                windows_source = extract_member(win_archive, "background.js")

    verify_hash("mac_background_js", hashlib.sha256(mac_source).hexdigest())
    verify_hash("windows_background_js", hashlib.sha256(windows_source).hexdigest())
    if len(mac_source) != 2_835_847 or len(windows_source) != 2_835_093:
        raise ValueError(f"unexpected background.js sizes: macOS={len(mac_source)}, Windows={len(windows_source)}")

    module_rows, block_rows, boundary = compare_member_modules(mac_source, windows_source, include_blocks=not args.modules_only)
    mac_map_members = [path for path, entry in mac_archive["entries"].items() if path.endswith(".map") and entry["kind"] == "file"]
    win_map_members = [path for path, entry in win_archive["entries"].items() if path.endswith(".map") and entry["kind"] == "file"]
    write_csv(args.modules_csv.resolve(), [
        "module_id", "status", "mac_bundle_offset_start", "mac_bundle_offset_end", "mac_bytes", "mac_sha256",
        "windows_bundle_offset_start", "windows_bundle_offset_end", "windows_bytes", "windows_sha256",
        "mac_static_require_ids", "windows_static_require_ids", "static_require_edges_changed",
    ], module_rows)
    write_csv(args.blocks_csv.resolve(), [
        "module_id", "hunk_id", "change_kind", "entry_to_module_static_path",
        "mac_bundle_start", "mac_bundle_end_exclusive", "mac_bytes", "mac_sha256",
        "windows_bundle_start", "windows_bundle_end_exclusive", "windows_bytes", "windows_sha256",
        "mac_enclosing_function_candidates", "windows_enclosing_function_candidates",
        "mac_changed_token_count", "windows_changed_token_count", "evidence_limit",
    ], block_rows)
    write_csv(args.markers_csv.resolve(), [
        "platform", "module_id", "marker", "module_relative_occurrences", "bundle_absolute_offsets",
        "module_sha256", "literal_raw_bytes", "literal_raw_sha256", "evidence_limit",
    ], boundary["keyword_rows"])
    write_csv(args.identity_csv.resolve(), [
        "content_sha256", "mac_module_ids", "mac_bytes", "windows_module_ids", "windows_bytes",
        "same_numeric_id_exact_match_ids", "classification", "evidence_limit",
    ], boundary["identity_rows"])

    print(json.dumps({
        "inputs": {
            "dmg_sha256": PINNED["dmg"],
            "windows_asar_sha256": PINNED["windows_asar"],
            "mac_asar_offset": args.mac_asar_offset,
            "mac_asar_extent_bytes": mac_archive["extent_length"],
            "mac_asar_extent_sha256": mac_archive["extent_sha256"],
            "mac_background_js_bytes": len(mac_source),
            "mac_background_js_sha256": hashlib.sha256(mac_source).hexdigest(),
            "windows_background_js_bytes": len(windows_source),
            "windows_background_js_sha256": hashlib.sha256(windows_source).hexdigest(),
            "mac_asar_source_map_member_count": len(mac_map_members),
            "windows_asar_source_map_member_count": len(win_map_members),
            "mac_background_sourceMappingURL_occurrences": mac_source.count(b"sourceMappingURL"),
            "windows_background_sourceMappingURL_occurrences": windows_source.count(b"sourceMappingURL"),
            "background_js_map_member_present": any(Path(path).name == "background.js.map" for path in mac_map_members + win_map_members),
        },
        **boundary["summary"],
        "outputs": {
            "module_ledger": str(args.modules_csv.resolve()),
            "changed_block_ledger": str(args.blocks_csv.resolve()),
            "static_boundary_marker_ledger": str(args.markers_csv.resolve()),
            "content_identity_map": str(args.identity_csv.resolve()),
        },
        "limitations": [
            "The byte arrays were read from validated ASAR payload ranges; the APFS pathname of the macOS ASAR remains unresolved.",
            "Module IDs are positional indexes in the top-level Webpack factory array; exact SHA-256 matches can move between indexes, and unmatched hashes do not prove added or removed features.",
            "Literal require edges are static syntax candidates and do not prove runtime loading or execution.",
            "Changed spans are limited to module IDs directly required by the unchanged entry factory in both builds; their exact offsets are supported by the same entry-to-module literal edge.",
            "Token anchors are ten-token windows unique on both sides; repeated or highly divergent regions can collapse into broad spans.",
            "Marker strings only locate possible JS-to-native package references; module 607 also contains a packaged-path expression, but successful loading and device access are not observed.",
        ],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
