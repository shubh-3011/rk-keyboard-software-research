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
- [Official RK Web, Hub, model-selected driver, firmware, and QMK/VIA distribution paths](docs/rk-official-driver-distribution-audit.md)
- [Model profile and `KB.ini` schema audit](docs/rk-profile-schema-audit.md)
- [Static profile-to-family and protocol coverage](docs/rk-profile-family-protocol-coverage.md)
- [Confidence-ranked profile tuple semantics](docs/rk-profile-tuple-semantics.md)
- [RKKB keymap tuple translation audit](docs/rk-keymap-translation-audit.md)
- [Keymap profile-to-UI and serializer path audit](docs/rk-keymap-ui-path-audit.md)
- [Macro file, persistence, and serializer audit](docs/rk-macro-format-and-path-audit.md)
- [Macro editor and physical-input capture gap audit](docs/rk-macro-capture-path-audit.md)
- [Audio-reactive capture and output-path audit](docs/rk-audio-reactive-path-audit.md)
- [Audio UI page-state and capture lifecycle follow-up](docs/rk-audio-ui-control-followup.md)
- [Lighting profile options to runtime records and UI](docs/rk-lighting-profile-record-path-audit.md)
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
- [4.6 G5 vtable, ApplySetting and command paths](docs/rk-v4.6-cdevg5-settings-and-vtable-audit.md)
- [4.6 G5 29-slot method evidence map](docs/rk-v4.6-cdevg5-vtable-map.csv)
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
- [Tray icon Configuration/Exit workflow and command handlers](docs/rk-tray-icon-menu-workflow-audit.md)
- [General settings UI and host-persistence audit](docs/rk-general-settings-ui-persistence-audit.md)
- [Recovered MFC message-map arrays and system-message routes](docs/rk-mfc-message-map-audit.md)
- [CLedDlg key-position mapping message follow-up](docs/rk-led-key-position-message-followup.md)
- [HID enumeration and hot-plug notification audit](docs/rk-device-enumeration-notification-audit.md)
- [Native API import, callsite, and syscall crosswalk](docs/rk-system-api-crosswalk.md)
- [Indirect API call and callback follow-up](docs/rk-native-api-indirect-call-audit.md)
- [Remaining unresolved native API invocation paths](docs/rk-remaining-native-api-path-audit.md)
- [Deep scan of remaining 4.06 API reference gaps](docs/rk-remaining-native-api-gap-deep-scan.md)
- [Remaining API reference scan evidence](docs/rk-remaining-api-reference-scan.csv)
- [Dynamic API resolution paths](docs/rk-dynamic-api-resolution-audit.md)
- [Dynamic API export and cached-pointer consumer follow-up](docs/rk-dynamic-api-consumer-gap-audit.md)
- [Updater UART receive state machine](docs/rk-updater-uart-state-machine.md)
- [Updater low `WM_TIMER` producer follow-up](docs/rk-updater-low-timer-producer-followup.md)
- [One-click updater command `0x0419` static UI-to-worker trace](docs/rk-updater-command-0419-static-path-audit.md)
- [Updater dongle-pairing checkbox state and direct-reference audit](docs/rk-updater-dongle-pairing-option-audit.md)
- [Updater UART file-sink direct-reference and initialization audit](docs/rk-uart-file-sink-reachability-audit.md)
- [Updater UART file-open path crosswalk](docs/rk-uart-file-open-path-crosswalk.md)
- [3632 request/response framing and retry audit](docs/rk-3632-response-semantics-audit.md)
- [Updater and firmware readback audit](docs/rk-firmware-readback-audit.md)
- [Updater UART chunk paths, byte order, and firmware-read gaps](docs/rk-uart-firmware-path-semantics-audit.md)
- [Screen/GIF and frame/page payload audit](docs/rk-screen-gif-payload-audit.md)
- [Screen image conversion and worker path audit](docs/rk-screen-image-conversion-path-audit.md)
- [Lighting, RGB, and color payload audit](docs/rk-rgb-lighting-color-payload-audit.md)
- [Settings serializer and command paths](docs/rk-setting-serializer-audit.md)
- [Settings Apply signaling, worker, and family dispatch](docs/rk-settings-apply-worker-audit.md)
- [4.06 selected-profile Apply dispatch and conditional S98 path](docs/rk-406-active-profile-apply-dispatch-follow-up.md)
- [Reset, periodic system-parameter worker, and stop-event paths](docs/rk-reset-and-system-parameter-path-audit.md)
- [Recovered Apply signal callsites and masks](docs/rk-apply-signal-callers.csv)
- [UI event and device worker path audit](docs/rk-ui-event-worker-path-audit.md)
- [Installer and uninstaller script audit](docs/rk-installer-uninstaller-script-audit.md)
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
is the companion web app and Python/WebView2 desktop wrapper. This repository
is the static research archive and source for the separate native Windows
rebuild. The native app is an early offline profile workspace, not a complete
hardware-compatible replacement; see the directory for community projects
that document hardware configuration support.
