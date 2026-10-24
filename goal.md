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

Resumed at the user's request on 2026-10-21 and continued on 2026-10-22, 2026-10-24, and 2026-10-25. The 4.06 bounded 90-pattern census now has seven earlier classifications, 78 local text-adapter resolutions, and five resolutions on listed caller paths; alternate receivers of the latter remain unproved. Further 4.6 work maps CMenuHash cleanup, text-macro picker/selection paths, report-to-SendInput behavior, and mapping-list lifecycle. The picker normal close now traces through `EndDialog` to its parent's result check; the eligible follow-up copies a selected 16-byte keymap row, updates its row-state marker, invalidates the associated HWND, and saves `pro.dct`; a guarded queue notification reaches a worker waiting on two handles, while queue item meanings and full virtual dispatch remain unresolved; one later branch may post `WM_CLOSE` to a host window found by `FindWindowW`; the TLS null/failure route raises a C++ exception beyond the immediate picker frames, with higher-level recovery open. A separate CClrPanelDlg dispatch resolves one indirect callback to a CAfxStringMgr reference-count helper, but not its feature meaning. Four SHAppBarMessage edges are classified, leaving a conservative 3,558 indirect-call contexts (3,554 sites) unresolved in the bounded root-seeded 4.6 graph. A 2026-10-25 correction now verifies the direct startup → config-loader → callback-initializer chain at `0x00448188`, `0x00456520`, and `0x00456597`; the selector is loaded from `[OPT] Debug` and stored at `0x0063BE28`. Package `Cfg.ini` has `Debug=0`, but runtime file selection and callback value remain unknown, so the callback calls stay conservatively unresolved as conditional targets. The targeted decode also proves the prior linear-sweep negative claim and its 14-reference selector census were incomplete. Selected root-seeded paths visit 33.80% of the 4.6 driver's `.text`; 66.20% remains outside those paths. S98's 01BF image now has three bounded HidD_GetFeature consumers, including a read-to-command path that forwards four response bytes into a later 05 77 feature report; Thai has static counterparts for the earlier verification and status-query routines. No arbitrary firmware export is established. Runtime outcomes, list payload identity/completeness, physical report meaning, remaining callers, and broad package-family gaps stay unresolved. This does not close the overall goal or establish a G5 data-read caller. See [`progress.md`](progress.md) for the current snapshot, findings, limitations, and resume checkpoint.

The follow-up also resolves the logger's static file sink: selector 2 reaches a CRT-style open helper and a conditional stream-flush path through `CreateFileW` and `WriteFile`. The initializer asks `SHGetSpecialFolderPathW` for CSIDL 0, which Microsoft identifies as the virtual Desktop, and ignores the API return; the actual output path and successful file creation are therefore not established. The executable-directory prefix used for `cfg.ini` is statically reconstructed from `GetModuleFileNameW` through path-splitting and joining helpers, while the actual runtime config file remains unknown. The static verifier checks the direct calls, imports, package binary hash, and `Cfg.ini` hash. No runtime or device I/O was used.

A separate 01BF updater follow-up extends the All Start UI/worker chain to a conditional host-image transfer routine at `0x00402C90`, which builds `05 57` / `06 77` reports and sends up to `0x800` staged bytes per report through `HidD_SetFeature`; a successful return reaches the existing `05 52` / `06 72` readback verifier. This is host-to-device static call/data-flow evidence only. No updater was run, no HID was opened, and it does not establish device acceptance, persistence, arbitrary firmware export, or coverage of other packages.
