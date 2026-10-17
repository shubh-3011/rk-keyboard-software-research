# Open-Source RK Keyboard Software and Research

Open-source Royal Kludge (RK) keyboard software? Start with this
community directory and research archive. It points to independent web and
desktop configurators, then provides a reproducible static audit of the RK
Windows 4.06 package installed on this PC. The goal is to make existing open
projects and the evidence easier to find, compare, and extend.

This repository brings together versioned evidence, reproducible catalog
tools, detailed software audits, and a source-built Windows research
workbench so contributors can inspect how the examined RK package is
organized and continue the analysis.

The archive includes model profiles, installed-file hashes, localization and
dialog-resource inventories, profile-to-driver maps, native API and
updater-path crosswalks, and a downloadable Windows app. It documents a
complete installed-file snapshot of RK 4.06 and a separately sourced static
snapshot of the official Windows 4.6 Hub Driver package. These are bounded
software snapshots, not a universal inventory of every RK release or keyboard;
the workbench is not a feature-complete replacement for the vendor utility.

**Get the Windows app:** [latest RK Research Workbench release](https://github.com/shubh-3011/rk-keyboard-software-research/releases/latest)
· **Browse the source:** [`workbench/`](workbench/) · **Audit scope:** [coverage and open work](COVERAGE.md)

This is independent community research, not the official RK software, and it
is not affiliated with RK. No vendor executable, DLL, installer, firmware
image, or copied artwork is included. The separate `workbench/` app is an
original, open-source profile editor and does not implement vendor hardware
writes. This archive does not claim that every RK model or revision has been
reverse-engineered.

## Our two open-source projects

| Project | Best for | Available today |
| --- | --- | --- |
| [Keydeck RK Studio](https://github.com/shubh-3011/keydeck-rk-studio) | A user-facing web app and native Windows profile editor | Local model layouts, profile editing, and JSON import/export. Its hosted web app is at [keydeck-rk-s98.vercel.app](https://keydeck-rk-s98.vercel.app/). |
| This research archive | Studying RK Windows software and building on documented evidence | Static audits, source scripts, versioned 4.06 and 4.6 profile catalogs, package manifests, and a downloadable source-built research workbench. |

Both projects are independent and open source. Neither currently sends
settings, lighting, macro, screen, or firmware writes to a keyboard. The
research workbench is a reference and profile editor, not a fully compatible
hardware clone of the RK utility. See [coverage status](COVERAGE.md) for the
confirmed findings and open questions.

**Product distinction:** the currently released research EXE is a Python
PyInstaller + WebView2 profile-editor prototype. It is not the native
reverse-built RK application and has no tray, autostart, or hardware-write
implementation. The intended clean-room native reconstruction is a separate,
unfinished deliverable tracked in [`REBUILD-ROADMAP.md`](REBUILD-ROADMAP.md).

For a broader, regularly maintained list of community projects and their
documented scope, see the [open-source RK software directory](SOFTWARE-DIRECTORY.md).

## Coverage

The installed **RK Keyboard Software 4.06** baseline contains **188 named
profiles** and **189 `KB.ini` files**, including the unregistered profile
`01C7`. Its manifest records 810 installed files by relative path, size, and
SHA-256. [`models.json`](models.json) preserves its decoded profile metadata.
A static extraction of the official Windows **4.6 Hub Driver** package adds a
separate 265-profile catalog and full 1,249-file package manifest; see the
[4.6 package snapshot](docs/rk-v4.6-package-snapshot.md) and its
[version delta](docs/rk-profile-catalog-v4.6-delta.md). Keep version-specific
claims tied to their own binary hashes and reports. Neither profile-to-driver
map proves compatibility with every physical revision sold under a family.

This is complete coverage of the model entries found in that one software
snapshot, not a claim to cover every keyboard RK has ever released. Regional
catalogs, other utility versions, later models, and models absent from this
package may differ. Current product listings are useful discovery sources,
but a product page does not establish compatibility with the 4.06 profiles or
native protocol. See [coverage status](COVERAGE.md) before treating a mapping
as confirmed.

## Start here

- [Main static reverse-engineering report](docs/reverse-engineering.md)
- [Official RK Web, Hub, model-selected driver, firmware, and QMK/VIA distribution paths](docs/rk-official-driver-distribution-audit.md)
- [Model profile and `KB.ini` schema audit](docs/rk-profile-schema-audit.md)
- [Static profile-to-family and protocol coverage](docs/rk-profile-family-protocol-coverage.md)
- [Confidence-ranked profile tuple semantics](docs/rk-profile-tuple-semantics.md)
- [RKKB keymap tuple translation audit](docs/rk-keymap-translation-audit.md)
- [Keymap profile-to-UI and serializer path audit](docs/rk-keymap-ui-path-audit.md)
- [Macro file, persistence, and serializer audit](docs/rk-macro-format-and-path-audit.md)
- [Macro editor and physical-input capture gap audit](docs/rk-macro-capture-path-audit.md)
- [Audio-reactive capture and output-path audit](docs/rk-audio-reactive-path-audit.md)
- [Lighting profile options to runtime records and UI](docs/rk-lighting-profile-record-path-audit.md)
- [Keyboard LED brightness UI and unresolved apply path](docs/rk-lighting-brightness-ui-handler-audit.md)
- [Profile-to-driver-family map](docs/rk-profile-driver-family-map.csv)
- [Machine-readable 188-profile catalog](models.json)
- [Installed package manifest](docs/rk-installed-package-manifest.csv)
- [Official Windows 4.6 package snapshot and provenance](docs/rk-v4.6-package-snapshot.md)
- [RK Drive Web App bundle, model registry, and feature audit](docs/rk-drive-web-app-audit.md)
- [RK Drive keyboard descriptor catalog](docs/rk-drive-keyboard-catalog.csv)
- [RK Drive image URL references](docs/rk-drive-image-references.csv)
- [Full 4.6 extracted package manifest](docs/rk-4.6-package-manifest.csv)
- [4.06-to-4.6 application file delta](docs/rk-package-file-delta-v4.06-v4.6.md)
- [4.06-to-4.6 path/hash comparison CSV](docs/rk-file-manifest-delta-v4.06-v4.6.csv)
- [4.06-to-4.6 localization delta](docs/rk-localization-delta-v4.06-v4.6.md)
- [4.06-to-4.6 localization key/resource CSV](docs/rk-localization-delta-v4.06-v4.6.csv)
- [4.6 profile catalog and comparison](docs/rk-profile-catalog-v4.6-delta.md)
- [4.6 projected profile-to-family map](docs/rk-profile-driver-family-map-v4.6-projected.csv)
- [4.6 driver profile selector and Fw=3 path](docs/rk-v4.6-profile-selector-audit.md)
- [4.6 row-level selector map](docs/rk-v4.6-profile-selector-map.csv)
- [4.6 Fw=3 `CDev3632` vtable and transport audit](docs/rk-v4.6-fw3-cdev3632-vtable-audit.md)
- [4.6 `CDev3632` frame, response queue, and selector audit](docs/rk-v4.6-cdev3632-frame-and-selector-audit.md)
- [4.6 Side LED profile, UI, and report-builder audit](docs/rk-v4.6-side-led-static-audit.md)
- [4.6 Side LED message-map and selection-state follow-up](docs/rk-v4.6-side-led-message-map-follow-up.md)
- [4.6 screen/GIF UI-to-transport trace](docs/rk-v4.6-screen-gif-ui-transport-audit.md)
- [4.6 native binary/API delta](docs/rk-v4.6-native-binary-delta-audit.md)
- [4.6 imported API callsite audit and limits](docs/rk-v4.6-native-api-call-path-audit.md)
- [4.6 import callsite ledger](docs/rk-v4.6-native-api-call-sites.csv)
- [4.6 follow-up for unresolved import references](docs/rk-v4.6-unresolved-api-reference-audit.md)
- [4.6 unresolved import reference ledger](docs/rk-v4.6-unresolved-api-references.csv)
- [4.6 text-macro local persistence path](docs/rk-v4.6-textmacro-path-audit.md)
- [4.6 text-macro evidence ledger](docs/rk-v4.6-textmacro-path-evidence.csv)
- [Resource and localization audit](docs/rk-resource-localization-audit.md)
- [PE dialog-resource and selected updater control audit](docs/rk-dialog-resource-audit.md)
- [Main UI label, control, handler, and action crosswalk](docs/rk-ui-control-command-crosswalk.md)
- [General settings UI and host-persistence audit](docs/rk-general-settings-ui-persistence-audit.md)
- [Recovered MFC message-map arrays and system-message routes](docs/rk-mfc-message-map-audit.md)
- [HID enumeration and hot-plug notification audit](docs/rk-device-enumeration-notification-audit.md)
- [Native API import, callsite, and syscall crosswalk](docs/rk-system-api-crosswalk.md)
- [Indirect API call and callback follow-up](docs/rk-native-api-indirect-call-audit.md)
- [Remaining unresolved native API invocation paths](docs/rk-remaining-native-api-path-audit.md)
- [Deep scan of remaining 4.06 API reference gaps](docs/rk-remaining-native-api-gap-deep-scan.md)
- [Remaining API reference scan evidence](docs/rk-remaining-api-reference-scan.csv)
- [Dynamic API resolution paths](docs/rk-dynamic-api-resolution-audit.md)
- [Dynamic API export and cached-pointer consumer follow-up](docs/rk-dynamic-api-consumer-gap-audit.md)
- [Updater UART receive state machine](docs/rk-updater-uart-state-machine.md)
- [One-click updater command `0x0419` static UI-to-worker trace](docs/rk-updater-command-0419-static-path-audit.md)
- [Updater UART file-sink direct-reference and initialization audit](docs/rk-uart-file-sink-reachability-audit.md)
- [3632 request/response framing and retry audit](docs/rk-3632-response-semantics-audit.md)
- [Updater and firmware readback audit](docs/rk-firmware-readback-audit.md)
- [Updater UART chunk paths, byte order, and firmware-read gaps](docs/rk-uart-firmware-path-semantics-audit.md)
- [Screen/GIF and frame/page payload audit](docs/rk-screen-gif-payload-audit.md)
- [Screen image conversion and worker path audit](docs/rk-screen-image-conversion-path-audit.md)
- [Lighting, RGB, and color payload audit](docs/rk-rgb-lighting-color-payload-audit.md)
- [Settings serializer and command paths](docs/rk-setting-serializer-audit.md)
- [Settings Apply signaling, worker, and family dispatch](docs/rk-settings-apply-worker-audit.md)
- [Reset, periodic system-parameter worker, and stop-event paths](docs/rk-reset-and-system-parameter-path-audit.md)
- [Recovered Apply signal callsites and masks](docs/rk-apply-signal-callers.csv)
- [UI event and device worker path audit](docs/rk-ui-event-worker-path-audit.md)
- [Installer and uninstaller script audit](docs/rk-installer-uninstaller-script-audit.md)
- [Host update/download and installer path audit](docs/rk-host-update-install-path-audit.md)
- [Dated public model list compared with the 4.06 profile catalog](docs/rk-public-model-coverage-gaps.md)
- [Dated storefront model list and profile-name crosswalk](docs/rk-storefront-model-crosswalk.csv)
- [All audit documents and evidence tables](docs/)

## Open-source Windows workbench

This is the current research prototype, not the native reconstruction target
([status and parity gates](REBUILD-ROADMAP.md)).

The [`workbench/` source](workbench/) packages the profile studio as a
standalone Windows desktop app. It includes the same 188-profile catalog,
local keymap, lighting, macro and display-profile editing, and JSON
import/export. User data stays in the local Windows profile. The executable
runs in its own WebView2 window and serves its bundled files only on loopback.

This is an open-source implementation of safe profile-editing
workflows, not a feature-complete clone of RK's hardware utility. It can
identify an authorized device by USB/HID descriptor when the embedded runtime
supports WebHID, but it does not open HID reports or write to the keyboard.
Lighting, macros, screen transfers, firmware tools, and hardware writes are
not implemented. The keyboard remains untouched. The app's limits and build
steps are in [`workbench/README.md`](workbench/README.md).

The reports distinguish statically proven observations, inferences, and
unresolved questions. Import presence, strings, byte patterns, profile labels,
and callsite candidates are not presented as proof of runtime behavior.

## Rebuild the profile catalog

The Python scripts read an installed RK package and write derived profile
metadata, CSV ledgers, and dialog-resource inventories. They do not launch RK
software or communicate with a keyboard. From the repository root on Windows
with Python 3.10 or newer:

```powershell
python scripts/extract_rk_catalog.py `
  --rk-root "C:\Program Files (x86)\RK Keyboard Software" `
  --output models.json `
  --driver-map-output docs/rk-profile-driver-family-map.csv

python scripts/audit_profile_schema.py `
  --rk-root "C:\Program Files (x86)\RK Keyboard Software" `
  --repo .

python scripts/compare_storefront_models.py

python -m pip install -r requirements-audit.txt
python scripts/audit_dialog_resources.py `
  --rk-root "C:\Program Files (x86)\RK Keyboard Software" `
  --output docs/rk-dialog-resource-controls.csv
```

For reproducibility, compare the package version and file hashes in
[`rk-installed-package-manifest.csv`](docs/rk-installed-package-manifest.csv)
with the source package before interpreting address-level findings. The
native reports are tied to specific PE hashes and version-specific addresses.
To verify every installed path, size, and SHA-256 against that manifest, run:

```powershell
python scripts/verify_installed_manifest.py `
  --rk-root "C:\Program Files (x86)\RK Keyboard Software" `
  --manifest docs/rk-installed-package-manifest.csv
```

## Research boundary

All findings are static. The RK application and updater were not launched;
the keyboard HID interface was not opened; and no keyboard report, command,
firmware write, or bootloader operation was performed. Static traces do
identify code paths that can write to a keyboard if the vendor application
runs them. They are documented as findings, not recommendations to replay.

## Sources

- [RK official website](https://en.rkgaming.com/)
- [RK official keyboard catalog](https://rkgamingstore.com/collections/rk-keyboard)
- [RK official web configurator](https://drive.rkgaming.com/)
- [KludgeKnight open-source RK configurator](https://github.com/vinc3m1/kludgeknight)

## Open-source RK software directory

This repository is intended as a clear starting point for finding open-source
RK software. The [directory](SOFTWARE-DIRECTORY.md) compares the projects by
platform, purpose, and author-documented support. It separates projects that
edit local profiles from projects that communicate with keyboards, and keeps
their model-support claims attached to their original sources.

For the installed Windows suite's static inventory—profiles, resources,
imports, callsite candidates, update paths, and evidence gaps—start with this
repository's [coverage ledger](COVERAGE.md) and
[main report](docs/reverse-engineering.md). No single package snapshot here
establishes compatibility with every RK model or revision.

The catalog and product names are RK trademarks. Research notes and scripts
are licensed under MIT; see [LICENSE](LICENSE) and
[data provenance](DATA-PROVENANCE.md).

The [Keydeck RK Studio project](https://github.com/shubh-3011/keydeck-rk-studio)
is the companion web and Windows profile editor. This repository is the
standalone research archive and also publishes a source-built Windows
research workbench with its source and build instructions. That executable
is a profile editor, not a complete hardware-compatible replacement for the
vendor software; see the directory for community projects that document
hardware configuration support.
