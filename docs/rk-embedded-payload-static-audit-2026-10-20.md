# Embedded updater payload static audit — 2026-10-20

## Scope and handling

This pass examined three payloads embedded in the eight hash-pinned CLR updater packages identified by `docs/rk-firmware-clr-profile-inventory-2026-10-20.csv`: the Westberry V0.0.5 helper executable, `libhidapi-0.dll`, and `libusb-1.0.dll`. The scanner verifies each parent package hash, reads each CLI resource range directly into memory, validates the resource length prefix, hashes the child byte range, and parses that byte range in memory. It does not write or extract payload bytes, load or execute an assembly or native image, contact a keyboard, or invoke an updater.

Each child hash is identical across all eight parent packages, giving 24 parent-to-child links and three distinct payloads. All links, manifest tokens, resource offsets, payload offsets, lengths, and parent/child hashes are recorded in the parent-child ledger. For reference, the representative parent is `20260701135217_3418.exe`, SHA-256 `392b0ed26d6105e2bae7995c835eca6ebd699d3bfc7d2f57fdadf7706b1a4732`.

## Verified PE inventory

| Payload | Child SHA-256 | Size | PE profile | Imports | Exports | PE resources |
|---|---|---:|---|---:|---:|---:|
| `wb32_f022_hid_dfu_updater_V0.0.5.exe` | `e98cb301502891f6b5c37c4fb8fe8a05893ad1fac6def0d49676b5198f46d819` | 248,048 | x86-64, PE32+, entry RVA `0x13F0`, 20 sections | 100 symbols / 12 DLLs | 0 | 1 |
| `libhidapi-0.dll` | `8d672ce45d76682a5cbe2b80ab6d65f96fa9cb4b46f3d3773df91f76fcf7088d` | 66,967 | x86-64, PE32+, entry RVA `0x1330`, 12 sections | 61 symbols / 2 DLLs | 25 | 1 |
| `libusb-1.0.dll` | `d439b7b6bf3bcf1defd3651e6d062513886cf13d25a2a4731e7654eb44419f35` | 223,179 | x86-64, PE32+, entry RVA `0x1330`, 12 sections | 102 symbols / 2 DLLs | 154 | 1 |

The helper's PE import table declares imports from both embedded libraries: nine HIDAPI functions (`hid_close`, `hid_enumerate`, `hid_error`, `hid_exit`, `hid_free_enumeration`, `hid_init`, `hid_open_path`, `hid_read`, and `hid_write`) and 21 libusb functions, including device enumeration, descriptor retrieval, interface claim, control/bulk/interrupt transfers, and open/close. These are import declarations, which establish a static dependency but do not by themselves prove that a function is called on a particular execution path.

The helper's printable strings include DFU/HID diagnostics such as “No APP capable USB device available”, “No DFU capable USB device available”, “Failed to write to hid device”, and “Opening DFU capable USB device ...”. Strings are evidence of embedded text, not proof of runtime behavior. The resource ledger records one resource directory entry per PE and hashes its range in memory; resource bytes were not extracted.

## Call candidates and evidence level

With Capstone 5.0.7, a bounded instruction sweep across executable sections yielded 6,523 call/jump candidates: 1,115 in the helper, 1,286 in HIDAPI, and 4,122 in libusb. For the helper, it found 11 IAT-call candidates targeting `KERNEL32.dll`, plus 9 IAT-jump candidates for `libhidapi-0.dll` and 21 for `libusb-1.0.dll`. The IAT jumps may be import-thunk entries; they are not evidence that the helper called those APIs. Every record is explicitly marked `linear-sweep-only`: instruction boundaries may be desynchronized by starting at section byte zero, and no control-flow graph, function-boundary validation, or reachability analysis was performed. These are not validated callers or execution paths. The calls ledger keeps direct, indirect, and IAT candidates separate and includes exact child offsets, representative parent offsets, instruction bytes, and operands.

## Reproduction

From the repository root, run:

```powershell
python scripts/audit_rk_embedded_payloads_static.py
```

The research cache defaults to the sibling `.research` directory and can be overridden with `--research-root`. The script uses the Python standard library for parsing and hashing; Capstone is optional and only enables the candidate sweep. Without Capstone, PE inventory remains available and the call-candidate ledger is empty with status `capstone-unavailable`. The scanner refuses to continue if a selected parent package hash or embedded resource length check fails.

## Outputs

- `scripts/audit_rk_embedded_payloads_static.py` — reproducible, in-memory parser and ledger generator.
- `docs/rk-embedded-payload-parent-child-ledger-2026-10-20.csv` — all 24 parent/resource/child links and hashes.
- `docs/rk-embedded-payload-image-summary-2026-10-20.csv` — one PE profile per unique child payload.
- `docs/rk-embedded-payload-section-ledger-2026-10-20.csv` — 44 PE sections.
- `docs/rk-embedded-payload-import-ledger-2026-10-20.csv` — 263 import declarations.
- `docs/rk-embedded-payload-export-ledger-2026-10-20.csv` — 179 export declarations.
- `docs/rk-embedded-payload-resource-ledger-2026-10-20.csv` — three in-memory resource range hashes.
- `docs/rk-embedded-payload-string-ledger-2026-10-20.csv` — 30,874 printable ASCII/UTF-16LE candidates with offsets and heuristic tags.
- `docs/rk-embedded-payload-linear-call-candidates-2026-10-20.csv` — 6,523 unvalidated linear-sweep candidates.
- `docs/rk-embedded-payload-parse-issues-2026-10-20.csv` — empty issue ledger for this run.

The scanner reported 24 parent links, three unique payload hashes, three parsed PE images, and zero parse issues. All usage/behavior claims remain bounded to static file metadata and bytes; runtime paths and protocol semantics are open work.
