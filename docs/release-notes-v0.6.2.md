# RK Rebuild 0.6.2 — device detection and accessible lighting reads

**Developer preview, not yet a usable general RK replacement.** General lighting
editing, key remapping, macro transfer and display controls remain incomplete.
This release fixes concrete device-discovery presentation and access problems;
it does not turn catalogue entries into supported keyboards.

## Changes

- Start on the Device page instead of the compatibility catalogue.
- Automatically inspect live HID metadata alongside Windows PnP discovery.
- Show a detected receiver/device even when its USB identity matches multiple
  models. Manual reference-profile selection stays separate from detection.
- Show detection status and discovery failures instead of a permanent LOCAL MODE
  label or silently suppressed scan exceptions.
- Put **Rescan devices** and **Read current lighting** directly on Device and
  Lighting pages, rather than behind Compatibility's manual inspection flow.
- Reuse the existing explicit G5/20-byte readers. Multiple matching query
  interfaces are blocked, and fresh endpoint validation still occurs before I/O.
- Display read success/failure in place, with optional report saving afterward.
- Retain only the existing exact-fingerprint experimental wireless Off/first-effect
  writes; no general brightness, color, effect, keymap or firmware writes enabled.
- Include the independently drawn narrow navigation rail introduced after 0.6.0.

## Observed locally

The published EXE displayed `258A:0150` and its read button in the running WPF
Device page. The same build's CLI successfully obtained a complete 128-byte
lighting block with trailer `5A A5` and no settings write. This receiver ID has
46 candidate model labels; its physical model was not inferred from the ID.
The UI confirmation automation did not pass, so this is not a full UI-interaction
certification. See `docs/runtime-evidence/native-0.6.2-device-read-check-2026-10-27.json`.

All 18 native regression projects and the published nine-page offline rendering
smoke passed locally. The Windows CI workflow separately gates package publication
with the disposable standard-user installer lifecycle.

## Downloads

Use `RK-Rebuild.exe` for the portable self-contained Windows x64 build, or
`RK-Rebuild-0.6.2-win-x64-experimental.msi` for the per-user installation.
Both are unsigned; `.sha256` files verify integrity, not publisher identity.
Close the vendor utility normally before using a lighting query. A detected
receiver does not prove an awake keyboard; failed queries remain visible.
