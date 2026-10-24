# Research goal

## Objective

Build an evidence-backed, reproducible map of Royal Kludge keyboard software and related package families, then use that research to inform an independently maintained, source-available reconstruction. The scope includes identifying software/package families and versions; cataloging models and revisions; documenting UI-to-device and updater paths, APIs, system interactions, and configuration behavior; and clearly labeling what is proven, inferred, unresolved, or only observed at runtime.

The goal is **not complete**. “All RK software” has no established finite denominator yet: public catalogs, retired releases, regional downloads, model revisions, and private or unavailable packages may be missing. Do not describe any bounded catalog or sample as a complete reverse engineering of the entire RK suite.

## Workstreams

1. **Research:** Acquire and hash-pin available packages; inventory files and resources; trace native, managed, web, installer, updater, and firmware-related code; map model/version routes; maintain reproducible scripts, evidence, and an explicit gap matrix.
2. **Reconstruction:** Continue the separate open-source alternative in `rebuild/` and `workbench/`. It is an independent implementation, not an exact reproduction of RK's proprietary assets or proof of protocol compatibility. Keep capabilities and hardware support tied to documented evidence.

## Evidence rules

- Preserve hashes, provenance, package versions, and reproducible scripts for analyzed inputs.
- Distinguish static strings/imports/linear sweeps from validated control flow, reachable behavior, and runtime observations.
- Do not claim that a model or firmware revision is supported solely because it appears in a catalog or package.
- Keep official assets and behavior descriptions attributable to their source; do not imply official RK endorsement.
- Track unresolved rows in `COVERAGE.md` and the gap matrix; report percentages only where the denominator and measurement are explicit.

## Hardware boundary

The present scope is static and non-invasive. Do not open the keyboard HID interface, intercept or alter live device communication, send reports or commands, run RK updater software, enter bootloader mode, or write firmware. Do not attempt a firmware dump unless a complete, non-destructive read path has first been established from reliable evidence and explicitly reviewed with the user. Preserve the keyboard's existing firmware and configuration.

## Current state

Resumed at the user's request on 2026-10-21 and continued on 2026-10-22 and 2026-10-24. The 4.06 bounded 90-pattern census now has seven earlier classifications, 78 local text-adapter resolutions, and five resolutions on listed caller paths; alternate receivers of the latter remain unproved. Further 4.6 work maps CMenuHash cleanup, text-macro picker/selection paths, report-to-SendInput behavior, and mapping-list lifecycle. The picker normal close now traces through `EndDialog` to its parent's result check; the eligible follow-up copies a selected 16-byte keymap row, updates its row-state marker, invalidates the associated HWND, and saves `pro.dct`; a guarded queue notification reaches a worker waiting on two handles, while queue item meanings and full virtual dispatch remain unresolved; one later branch may post `WM_CLOSE` to a host window found by `FindWindowW`; the TLS null/failure route raises a C++ exception beyond the immediate picker frames, with higher-level recovery open. A separate CClrPanelDlg dispatch resolves one indirect callback to a CAfxStringMgr reference-count helper, but not its feature meaning. Four SHAppBarMessage edges are classified, leaving 3,558 unresolved indirect-call contexts (3,554 sites) in the bounded root-seeded 4.6 graph; 66.20% of `.text` remains outside the selected paths. S98's 01BF image now has three bounded HidD_GetFeature consumers, including a read-to-command path that forwards four response bytes into a later 05 77 feature report; Thai has static counterparts for the earlier verification and status-query routines. No arbitrary firmware export is established. Runtime outcomes, list payload identity/completeness, physical report meaning, remaining callers, and broad package-family gaps stay unresolved. This does not close the overall goal or establish a G5 data-read caller. See [`progress.md`](progress.md) for the current snapshot, findings, limitations, and resume checkpoint.
