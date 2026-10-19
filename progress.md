# Reverse-engineering progress

**Snapshot date:** 2026-10-20  
**Repository:** [`shubh-3011/rk-keyboard-software-research`](https://github.com/shubh-3011/rk-keyboard-software-research)  
**Local path:** `C:\Users\shubh\Downloads\sshorcale\rk-keyboard-software-research`  
**Branch:** `main`

## Status

The research is paused at this snapshot. The whole Royal Kludge software suite has **not** been reverse engineered. There is no defensible overall completion percentage: the universe of current, historical, regional, model-specific, and revision-specific RK packages is not fully known, and the available evidence is uneven. The coverage ledger and gap matrix are the best measures of completed work and remaining gaps.

This repository contains both the research record and reconstruction-related directories (`rebuild/` and `workbench/`). The research reports describe observed package contents and static analysis; they do not establish that every feature has been reproduced or that a keyboard accepts any particular command.

## Latest recorded work

- **4.6 `DeviceDriver.exe`:** A bounded root-seeded static control-flow pass covers 580,139 bytes, or 33.66% of the executable `.text` section. It records 3,433 candidate roots, 31,520 basic blocks, 13,652 direct-call edges, 3,019 exact IAT calls, and 73 IAT tail jumps. A manual follow-up resolves four indirect calls in `WM_DEVICECHANGE`: two logging callbacks and two `SetTimer` calls. The statically inferred timer path reaches the HID enumerator, but no runtime event or enumeration was observed. There are still 3,533 unresolved indirect-call candidates, 123 indirect jumps, 147 possible tail transfers, and 66.34% of `.text` outside the selected paths. See [`docs/rk-v4.6-rooted-cfg-callgraph-audit.md`](docs/rk-v4.6-rooted-cfg-callgraph-audit.md).
- **Embedded updater payloads:** 24 resource links across eight hash-pinned packages reduce to three unique payloads: the Westberry updater helper, `libhidapi-0.dll`, and `libusb-1.0.dll`. Their PE structures, imports, exports, resources, and strings were inventoried. 6,523 linear-sweep call/jump candidates are not validated control flow; there is no payload CFG/reachability proof and no payload was executed. See [`docs/rk-embedded-payload-static-audit-2026-10-20.md`](docs/rk-embedded-payload-static-audit-2026-10-20.md).
- **Wider catalog:** Existing reports document bounded package catalogs and targeted analyses for Windows, macOS, firmware/updater families, selector packages, and web configurators. These are package-specific samples and paths, not complete maps of all RK products or every software API/system call. See [`COVERAGE.md`](COVERAGE.md), [`docs/reverse-engineering-gap-matrix-2026-10-19.md`](docs/reverse-engineering-gap-matrix-2026-10-19.md), and [`SOFTWARE-DIRECTORY.md`](SOFTWARE-DIRECTORY.md).

## Hardware and firmware boundary

No keyboard firmware was removed or overwritten. This research snapshot does not establish a safe, complete firmware-readback method. A static HID import or call path is not proof of a successful device transaction. Do not infer that the keyboard was tested from the static reports.

The active research constraint remains: do not open the keyboard HID interface, send device reports or commands, run an RK updater, enter a bootloader, or write firmware. Any future change to this boundary requires a separate, explicit user decision and a review of the concrete operation first.

## Checkpoint and resume

The latest committed checkpoint before this snapshot was `1fd73be` (`Trace 4.6 timer path into HID enumeration`). This snapshot adds the manual callsite follow-up and the pause documents. To resume, start with the remaining tasks in [`docs/reverse-engineering-gap-matrix-2026-10-19.md`](docs/reverse-engineering-gap-matrix-2026-10-19.md), update this file with new evidence, and keep static conclusions separate from runtime observations.
