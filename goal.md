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

Paused at the user's request on 2026-10-21. No further reverse-engineering work should continue until the user resumes it. See [`progress.md`](progress.md) for the saved snapshot, findings, limitations, and resume checkpoint.
