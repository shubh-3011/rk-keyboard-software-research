# Open-Source RK Keyboard Software and Research

Open-source Royal Kludge (RK) keyboard software? Start with this
community directory and research archive. It points to independent web and
desktop configurators, then provides a reproducible static audit of the RK
Windows 4.06 package installed on this PC. The goal is to make existing open
projects and the evidence easier to find, compare, and extend.

This repository brings together versioned evidence, reproducible catalog
tools, detailed software audits, and the source for an early native Windows
reconstruction. It also retains an older profile-editor prototype so
contributors can distinguish its limits from the current rebuild.

The archive includes model profiles, installed-file hashes, localization and
dialog-resource inventories, profile-to-driver maps, native API and
updater-path crosswalks, and source for an early native Windows rebuild. It
documents a complete installed-file snapshot of RK 4.06 and a separately
sourced static snapshot of the official Windows 4.6 Hub Driver package. These
are bounded software snapshots, not a universal inventory of every RK release
or keyboard; the native rebuild is not a feature-complete replacement for the
vendor utility.

**Native rebuild source:** [`rebuild/windows/`](rebuild/windows/) · **Rebuild status:** [roadmap](REBUILD-ROADMAP.md) · **Audit scope:** [coverage and open work](COVERAGE.md)

This is independent community research, not the official RK software, and it
is not affiliated with RK. No vendor executable, DLL, installer, firmware
image, or copied artwork is included. The new native app is an early local
profile/layout browser with a separate RK Drive keyboard directory, automatic
photo matching by profile and layout region, selectable photos for ambiguous
IDs, and an S98 finish-photo gallery using RK-hosted thumbnails. It does not
implement vendor hardware writes. The older `workbench/` prototype is a Python/WebView
profile editor. Neither is a feature-complete RK replacement. This archive
does not claim that every RK model or revision has been reverse-engineered.

## Our two open-source projects

| Project | Best for | Available today |
| --- | --- | --- |
| [Keydeck RK Studio](https://github.com/shubh-3011/keydeck-rk-studio) | A user-facing web app plus a Python/PyInstaller desktop wrapper using WebView2 | Local model layouts, profile editing, and JSON import/export. Its hosted web app is at [keydeck-rk-s98.vercel.app](https://keydeck-rk-s98.vercel.app/). |
| This research archive and native rebuild | Studying RK Windows software and reconstructing documented workflows in a separate Windows app | Static audits, source scripts, versioned catalogs/manifests, and a native C# WPF rebuild with the RK skin loaded from the local installation, profile art, local drafts, tray behavior, and opt-in startup. |

Both projects are independent and open source. Neither currently sends
settings, lighting, macro, screen, or firmware writes to a keyboard. Keydeck's
Windows EXE is a local WebView2 wrapper. The research repo's new C# WPF app is
a native Windows process, but it is an early reconstruction milestone, not a
fully compatible hardware clone. See [coverage status](COVERAGE.md) for the
confirmed findings and open questions.

**Important: the released EXE is not a reverse-built copy of RK software.**
The old downloadable `RK-Research-Workbench.exe` is a limited Python
profile-editor prototype packaged with PyInstaller and shown in WebView2. The
new native reconstruction is separate source in [`rebuild/windows/`](rebuild/windows/)
and builds as a self-contained C# WPF app. It provides local profile browsing,
a separate RK Drive keyboard directory, official model-photo links, a manual
S98 finish-photo gallery, read-only Windows Plug and Play identification,
key-label drafts, macro notes, tray
restore/exit, and opt-in startup. It does not yet implement HID communication
or full RK workflows. The
Windows rebuild reads RK's skin, fonts, and installed profile artwork locally;
those assets are not included in the repo or executable. Feature-control
placement is reconstructed because complete runtime coordinates are not
present in the static resources. Exact feature parity is not established. See the
[`REBUILD-ROADMAP.md`](REBUILD-ROADMAP.md) and
[`rebuild/windows/README.md`](rebuild/windows/README.md).

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
- [Coverage status and unresolved subsystems](COVERAGE.md)
- [Prioritized full-suite reverse-engineering gap matrix](docs/reverse-engineering-gap-matrix-2026-10-19.md)
- [Installed 4.06 skin assets and 4.6 delta](docs/rk-skin-asset-metadata-followup.md)
- [How the 4.06 app loads its skin and profile art](docs/rk-skin-loader-static-followup.md)
- [Package-wide `mak.skn` format/consumer scan](docs/rk-mak-skn-package-scan-followup.md)
- [HID feature-read request paths and firmware sink assessment](docs/rk-hid-read-request-and-firmware-sink-audit.md)
- [4.06 native system-call candidate boundary audit](docs/rk-406-system-call-byte-audit.md)
- [Uninstaller conditional `SetLastError` call](docs/rk-unins000-third-e8-candidate-audit.md)
- [Follow-up on the ten unresolved imported API rows](docs/rk-unresolved-native-api-relative-reference-followup.md)
- [4.06 brightness UI path and unresolved writer boundary](docs/rk-406-brightness-handler-field-boundary.md)
- [Official RK Web, Hub, model-selected driver, firmware, and QMK/VIA distribution paths](docs/rk-official-driver-distribution-audit.md)
- [Model profile and `KB.ini` schema audit](docs/rk-profile-schema-audit.md)
- [Static profile-to-family and protocol coverage](docs/rk-profile-family-protocol-coverage.md)
- [4.06 wireless profile `Psd` load and six-byte comparison dataflow](docs/rk-wireless-profile-psd-static-dataflow-audit.md)
- [Confidence-ranked profile tuple semantics](docs/rk-profile-tuple-semantics.md)
- [RKKB keymap tuple translation audit](docs/rk-keymap-translation-audit.md)
- [Keymap profile-to-UI and serializer path audit](docs/rk-keymap-ui-path-audit.md)
- [Macro file, persistence, and serializer audit](docs/rk-macro-format-and-path-audit.md)
- [Macro editor and physical-input capture gap audit](docs/rk-macro-capture-path-audit.md)
- [Audio-reactive capture and output-path audit](docs/rk-audio-reactive-path-audit.md)
- [Audio UI page-state and capture lifecycle follow-up](docs/rk-audio-ui-control-followup.md)
- [Lighting profile options to runtime records and UI](docs/rk-lighting-profile-record-path-audit.md)
- [4.06 LED label/control candidates by profile](docs/rk-led-control-candidates-4.06.md)
- [4.06 English LED candidate crosswalk](docs/rk-led-control-candidates-4.06-en.csv)
- [4.06 LED labels joined to `LedOptN` across all five installed locales](docs/rk-406-led-label-profile-tuple-crosswalk.md)
- [4.06 all-locales LED label/profile tuple CSV](docs/rk-406-led-label-profile-tuple-crosswalk-4.06-all-locales.csv)
- [Keyboard LED brightness UI and unresolved apply path](docs/rk-lighting-brightness-ui-handler-audit.md)
- [Profile-to-driver-family map](docs/rk-profile-driver-family-map.csv)
- [Machine-readable 188-profile catalog](models.json)
- [Installed package manifest](docs/rk-installed-package-manifest.csv)
- [Official Windows 4.6 package snapshot and provenance](docs/rk-v4.6-package-snapshot.md)
- [RK Drive Web App bundle, model registry, and feature audit](docs/rk-drive-web-app-audit.md)
- [RK Drive feature gates, mouse registry, and RK68 HE checks](docs/rk-drive-feature-gate-and-mouse-audit-2026-10-18.md)
- [RK Drive RK68 HE lighting UI-to-service/protocol crosswalk](docs/rk-drive-rk68-he-lighting-ui-protocol-crosswalk-2026-10-18.md)
- [RK Drive keymap, macro, and display static crosswalk](docs/rk-drive-keymap-macro-display-crosswalk-2026-10-18.md)
- [RK Drive keyboard descriptor catalog](docs/rk-drive-keyboard-catalog.csv)
- [RK Drive specialized keyboard profiles](docs/rk-drive-specialized-keyboard-profiles.csv)
- [RK Drive mouse registry](docs/rk-drive-mouse-registry.csv)
- [RK Drive image URL references](docs/rk-drive-image-references.csv)
- [Full 4.6 extracted package manifest](docs/rk-4.6-package-manifest.csv)
- [4.06-to-4.6 application file delta](docs/rk-package-file-delta-v4.06-v4.6.md)
- [4.06-to-4.6 path/hash comparison CSV](docs/rk-file-manifest-delta-v4.06-v4.6.csv)
- [4.06-to-4.6 localization delta](docs/rk-localization-delta-v4.06-v4.6.md)
- [4.06-to-4.6 localization key/resource CSV](docs/rk-localization-delta-v4.06-v4.6.csv)
- [4.6 profile catalog and comparison](docs/rk-profile-catalog-v4.6-delta.md)
- [Historical 4.06-rule projection for 4.6 profiles (superseded by the RTTI map)](docs/rk-profile-driver-family-map-v4.6-projected.csv)
- [4.6 driver profile selector and Fw=3 path](docs/rk-v4.6-profile-selector-audit.md)
- [4.6 row-level selector map](docs/rk-v4.6-profile-selector-map.csv)
- [4.6 profile-to-class routes verified through RTTI](docs/rk-v4.6-profile-family-rtti-audit.md)
- [4.6 row-level RTTI-verified family map](docs/rk-v4.6-profile-family-rtti-map.csv)
- [4.6 HID eligibility callers linked to profile rows and driver-family routes](docs/rk-v4.6-hid-profile-caller-bridge-audit.md)
- [4.6 G5 vtable, ApplySetting and command paths](docs/rk-v4.6-cdevg5-settings-and-vtable-audit.md)
- [4.6 G5 29-slot method evidence map](docs/rk-v4.6-cdevg5-vtable-map.csv)
- [4.6 Fw=3 `CDev3632` vtable and transport audit](docs/rk-v4.6-fw3-cdev3632-vtable-audit.md)
- [4.6 `CDev3632` RTTI-verified vtable root map](docs/rk-v4.6-cdev3632-vtable-map.csv)
- [4.6 root-seeded CFG/call-edge audit](docs/rk-v4.6-rooted-cfg-callgraph-audit.md)
- [4.6 `CDev3632` frame, response queue, and selector audit](docs/rk-v4.6-cdev3632-frame-and-selector-audit.md)
- [4.6 Side LED profile, UI, and report-builder audit](docs/rk-v4.6-side-led-static-audit.md)
- [4.6 Side LED message-map and selection-state follow-up](docs/rk-v4.6-side-led-message-map-follow-up.md)
- [4.6 `CLedDlg` message map and position-selection worker path](docs/rk-v4.6-cleddlg-message-map-and-selection-worker-audit.md)
- [4.6 MFC message-map inventory: 145 candidates and 1,214 entries](docs/rk-v4.6-mfc-message-map-inventory.md)
- [4.6 private `0x0477` shared-popup sender and page fanout](docs/rk-v4.6-private-message-0477-popup-fanout.md)
- [4.6 screen/GIF UI-to-transport trace](docs/rk-v4.6-screen-gif-ui-transport-audit.md)
- [4.6 native binary/API delta](docs/rk-v4.6-native-binary-delta-audit.md)
- [4.6 imported API callsite audit and limits](docs/rk-v4.6-native-api-call-path-audit.md)
- [4.6 CMenuHash temporary-handle release, app-exit path, and replacement-failure candidate](docs/rk-v4.6-temp-registry-lifecycle.md)
- [4.6 HID interface enumeration and device-change rescan path](docs/rk-v4.6-hid-interface-enumeration-rescan-audit.md)
- [4.6 HID record construction and VID/PID/capability eligibility gates](docs/rk-v4.6-hid-record-to-interface-eligibility-audit.md)
- [4.6 import callsite ledger](docs/rk-v4.6-native-api-call-sites.csv)
- [4.6 follow-up for unresolved import references](docs/rk-v4.6-unresolved-api-reference-audit.md)
- [4.6 unresolved import reference ledger](docs/rk-v4.6-unresolved-api-references.csv)
- [4.6 text-macro local persistence path](docs/rk-v4.6-textmacro-path-audit.md)
- [4.6 text-macro picker command, Apply caption, and selection-save/load bridge](docs/rk-v4.6-textmacro-command-bridge.md)
- [4.6 text-macro evidence ledger](docs/rk-v4.6-textmacro-path-evidence.csv)
- [Resource and localization audit](docs/rk-resource-localization-audit.md)
- [PE dialog-resource and selected updater control audit](docs/rk-dialog-resource-audit.md)
- [Main UI label, control, handler, and action crosswalk](docs/rk-ui-control-command-crosswalk.md)
- [Tray icon Configuration/Exit workflow and command handlers](docs/rk-tray-icon-menu-workflow-audit.md)
- [General settings UI and host-persistence audit](docs/rk-general-settings-ui-persistence-audit.md)
- [Recovered MFC message-map arrays and system-message routes](docs/rk-mfc-message-map-audit.md)
- [CLedDlg key-position mapping message follow-up](docs/rk-led-key-position-message-followup.md)
- [Key-position mapping data through conditional color serializers](docs/rk-key-position-to-color-serializer-followup.md)
- [CLedDlg selector-message sender follow-up](docs/rk-led-selector-message-sender-followup.md)
- [4.06 LED selection UI-to-worker and conditional G5 serializer path](docs/rk-406-led-selection-ui-to-worker-followup.md)
- [4.06 LED `0x0594` parameters and generated-row mapping](docs/rk-406-led-0594-parameter-and-generated-row-audit.md)
- [4.06 LED tree control, posted ID, and localized row-token follow-up](docs/rk-406-led-0594-tree-control-row-token-followup.md)
- [4.06 five-locale LED labels joined to profile `LedOptN` tuples](docs/rk-406-led-label-profile-tuple-crosswalk.md)
- [4.06 all-locales label/profile `LedOptN` crosswalk CSV](docs/rk-406-led-label-profile-tuple-crosswalk-4.06-all-locales.csv)
- [4.06 English-only label/profile `LedOptN` crosswalk CSV](docs/rk-406-led-label-profile-tuple-crosswalk-4.06-en.csv)
- [4.06 language-module loader API follow-up](docs/rk-v406-language-satellite-loader-api-followup.md)
- [4.06 Startup shortcut integration audit](docs/rk-v406-startup-shortcut-integration-audit.md)
- [HID enumeration and hot-plug notification audit](docs/rk-device-enumeration-notification-audit.md)
- [4.06 G5 active-object holder and bounded GetRealData caller scope](docs/rk-406-cdevg5-active-object-caller-scope.md)
- [4.06 stack-offset correction and six local text-dispatch resolutions](docs/rk-406-stack-alias-corrections.md)
- [4.06 five forwarded text receivers and their concrete caller paths](docs/rk-406-forwarded-text-receivers.md)
- [Native API import, callsite, and syscall crosswalk](docs/rk-system-api-crosswalk.md)
- [Indirect API call and callback follow-up](docs/rk-native-api-indirect-call-audit.md)
- [Remaining unresolved native API invocation paths](docs/rk-remaining-native-api-path-audit.md)
- [Deep scan of remaining 4.06 API reference gaps](docs/rk-remaining-native-api-gap-deep-scan.md)
- [4.06 DeviceDriver 32-row import-gap revalidation](docs/rk-406-native-api-gap-revalidation-follow-up.md)
- [4.06 DeviceDriver import-gap machine-readable evidence](docs/rk-406-native-api-gap-revalidation.csv)
- [Installer-helper five-row import-gap reconciliation](docs/rk-installer-helper-no-direct-call-import-followup.md)
- [Updater 12-row native import-gap reconciliation](docs/rk-updater-native-import-gap-reconciliation.md)
- [Remaining API reference scan evidence](docs/rk-remaining-api-reference-scan.csv)
- [Dynamic API resolution paths](docs/rk-dynamic-api-resolution-audit.md)
- [Dynamic API export and cached-pointer consumer follow-up](docs/rk-dynamic-api-consumer-gap-audit.md)
- [Updater UART receive state machine](docs/rk-updater-uart-state-machine.md)
- [Updater low `WM_TIMER` producer follow-up](docs/rk-updater-low-timer-producer-followup.md)
- [One-click updater command `0x0419` static UI-to-worker trace](docs/rk-updater-command-0419-static-path-audit.md)
- [4.6 mode-3 updater HID preflight and fallback path](docs/rk-v4.6-update-mode3-hid-preflight-audit.md)
- [4.6 mode-3 status response to section-transfer worker](docs/rk-v4.6-mode3-status-to-transfer-worker-followup.md)
- [Updater dongle-pairing checkbox state and direct-reference audit](docs/rk-updater-dongle-pairing-option-audit.md)
- [Updater UART file-sink direct-reference and initialization audit](docs/rk-uart-file-sink-reachability-audit.md)
- [Updater UART file-open path crosswalk](docs/rk-uart-file-open-path-crosswalk.md)
- [3632 request/response framing and retry audit](docs/rk-3632-response-semantics-audit.md)
- [Updater and firmware readback audit](docs/rk-firmware-readback-audit.md)
- [Updater UART chunk paths, byte order, and firmware-read gaps](docs/rk-uart-firmware-path-semantics-audit.md)
- [Screen/GIF and frame/page payload audit](docs/rk-screen-gif-payload-audit.md)
- [Screen image conversion and worker path audit](docs/rk-screen-image-conversion-path-audit.md)
- [4.06 screen editor to modal and worker boundary](docs/rk-406-screen-ui-to-worker-modal-follow-up.md)
- [Lighting, RGB, and color payload audit](docs/rk-rgb-lighting-color-payload-audit.md)
- [Settings serializer and command paths](docs/rk-setting-serializer-audit.md)
- [Settings Apply signaling, worker, and family dispatch](docs/rk-settings-apply-worker-audit.md)
- [4.06 selected-profile Apply dispatch and conditional S98 path](docs/rk-406-active-profile-apply-dispatch-follow-up.md)
- [Reset, periodic system-parameter worker, and stop-event paths](docs/rk-reset-and-system-parameter-path-audit.md)
- [Recovered Apply signal callsites and masks](docs/rk-apply-signal-callers.csv)
- [UI event and device worker path audit](docs/rk-ui-event-worker-path-audit.md)
- [Installer and uninstaller script audit](docs/rk-installer-uninstaller-script-audit.md)
- [4.6 Inno overlay and PascalScript recovery follow-up](docs/rk-v4.6-inno-overlay-static-recovery-followup.md)
- [4.6 knob signal to G5 command-4 follow-up](docs/rk-v4.6-knob-signal-to-g5-command04-follow-up.md)
- [4.6 knob-option popup origin and message-argument gap](docs/rk-v4.6-knob-popup-origin-partial-audit.md)
- [Host update/download and installer path audit](docs/rk-host-update-install-path-audit.md)
- [Dated public model list compared with the 4.06 profile catalog](docs/rk-public-model-coverage-gaps.md)
- [Dated storefront model list and profile-name crosswalk](docs/rk-storefront-model-crosswalk.csv)
- [All audit documents and evidence tables](docs/)

## Native Windows rebuild

The [`rebuild/windows/` source](rebuild/windows/) is the native C# WPF
reconstruction. It builds as a self-contained Windows executable, uses the
265-profile catalog, reads Windows USB/HID Plug and Play records to identify
catalogued VID/PID pairs from Windows' present-device list, shows corresponding
official model photos from RK's host, saves local-only key-label/macro drafts,
supports tray restore/exit, and offers opt-in start-with-Windows. PnP discovery
does not open a keyboard interface or read live lighting state. Its feature boundaries and build
steps are in [`rebuild/windows/README.md`](rebuild/windows/README.md).

The older [`workbench/`](workbench/) prototype remains for reference. Its
downloadable EXE uses Python/PyInstaller, a loopback HTTP server, and WebView2;
it is not the native rebuild. See [`workbench/README.md`](workbench/README.md).

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

Most findings are static. The RK application and updater were not launched.
A read-only live check opened shared read-access handles for the present
`258A:0150` HID collections and decoded their collection/report descriptors;
an additional inventory mapped ten paths (seven opened, three access-denied)
and descriptor report IDs without reading report payloads. A separate audit
made direct `HidD_GetFeature` reads and a later probe repeated two short
feature reports, detailed in the
[firmware readback audit](docs/rk-firmware-readback-audit.md). No input report
was read, and no output report, `HidD_SetFeature` payload, configuration or
firmware write, or bootloader operation was sent. These live observations do
not identify the physical keyboard or prove model selection. Static traces do
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
is the companion web app and Python/WebView2 desktop wrapper. This repository
is the static research archive and source for the separate native Windows
rebuild. The native app is an early offline profile workspace, not a complete
hardware-compatible replacement; see the directory for community projects
that document hardware configuration support.
