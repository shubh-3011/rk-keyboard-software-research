# RK Rebuild 0.6.0 — native Windows experimental preview

An independently authored, open-source Windows application for Royal Kludge
keyboard research and configuration. This is a native self-contained x64 preview,
not a complete replacement for the vendor software and not a universal hardware
support claim.

## Improvements

- Native WPF application with nine pages and no dependency on vendor resources.
- A 444-entry compatibility reference catalogue, with ambiguous identities kept
  visible. Catalogue entries do not imply tested hardware support.
- Hardware-validated wired G5 lighting-configuration reading using fresh HID
  descriptor report identities and bounded, isolated query workers.
- An experimental wireless mode-only operation restricted to exact observed
  endpoint metadata and configuration fingerprints, with baseline and readback
  verification. This is not a general lighting writer.
- Local lighting and macro drafts, plus deliberately partial offline ordinary
  key-action encoding. Hardware keymap, layer and macro writes are not enabled.
- A per-user MSI alongside the portable EXE, with no service, startup task,
  vendor firmware, automatic launch or driver installation.

## Downloads and installation

- `RK-Rebuild-0.6.0-win-x64-experimental.msi`: per-user installer.
- `RK-Rebuild.exe`: portable self-contained Windows x64 application.
- Corresponding `.sha256` files: integrity checks, not publisher signatures.

Both binaries are **unsigned**. Windows may show SmartScreen or publisher
warnings. Do not bypass organizational installation policies. There is no need
to install locally to inspect the source or run the pure regression tests.

## Validation boundaries

The release workflow builds and inspects the packages and requires a disposable
GitHub-hosted Windows standard-user lifecycle: previous installation, upgrade,
rejected downgrade, repair, installed 444-entry catalogue export, all nine pages
rendered offline, and uninstall. Scope is verified with Windows Installer's
current-user unmanaged context and token SID, not inferred from the uninstall
registry hive. Page rendering is not full interaction or performance testing.

Hardware validation is limited to documented endpoints and operations. General
brightness/color/effect writes, keymaps, layers, macros, displays/GIFs, HE
controls, other protocol families/transports and broad device validation remain
incomplete. No firmware flashing or factory resets are provided by this preview.

The project aims for one application across RK models, revisions and transports;
unsupported or ambiguous devices must fail safely rather than inherit write
permissions from a similar model name or VID/PID.
