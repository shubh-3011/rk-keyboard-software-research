# Royal Kludge Keyboard Software Research

An independent, open-source starting point for researching Royal Kludge (RK)
keyboard software. This repository brings together versioned evidence,
reproducible catalog tools, detailed software audits, and a source-built
Windows research workbench so contributors can inspect how the examined RK
package is organized and continue the analysis.

The archive includes model profiles, installed-file hashes, localization and
dialog-resource inventories, profile-to-driver maps, native API and
updater-path crosswalks, and a downloadable Windows app. It documents the RK
4.06 package examined here; it is not a universal inventory of every RK
release or keyboard, and the workbench is not a feature-complete replacement
for the vendor utility.

**Get the Windows app:** [latest RK Research Workbench release](https://github.com/shubh-3011/rk-keyboard-software-research/releases/latest)
· **Browse the source:** [`workbench/`](workbench/) · **Audit scope:** [coverage and open work](COVERAGE.md)

This is independent community research, not the official RK software, and it
is not affiliated with RK. No vendor executable, DLL, installer, firmware
image, or copied artwork is included. The separate `workbench/` app is an
original, open-source profile editor and does not implement vendor hardware
writes.

## Two open-source projects

| Project | Best for | Available today |
| --- | --- | --- |
| [Keydeck RK Studio](https://github.com/shubh-3011/keydeck-rk-studio) | A user-facing web app and native Windows profile editor | Local model layouts, profile editing, and JSON import/export. Its hosted web app is at [keydeck-rk-s98.vercel.app](https://keydeck-rk-s98.vercel.app/). |
| This research archive | Studying the installed RK Windows software and building on its documented evidence | Static audits, source scripts, the 188-profile catalog, and the downloadable source-built research workbench. |

Both projects are independent and open source. Neither currently sends
settings, lighting, macro, screen, or firmware writes to a keyboard. The
research workbench is a reference and profile editor, not a fully compatible
hardware clone of the RK utility. See [coverage status](COVERAGE.md) for the
confirmed findings and open questions.

## Coverage

The baseline is one installed **RK Keyboard Software 4.06** package. Its
catalog contains **188 named profiles** and **189 `KB.ini` files**, including
the unregistered profile `01C7`. The package manifest records 810 installed
files by relative path, size, and SHA-256. The machine-readable
[`models.json`](models.json) preserves all decoded named-profile options,
base/Fn mappings, layout metadata, and the unregistered profile. The static
[`profile-to-driver map`](docs/rk-profile-driver-family-map.csv) covers the
installed named catalog, not every physical variant sold under each family.

This is complete coverage of the model entries found in that one software
snapshot, not a claim to cover every keyboard RK has ever released. Regional
catalogs, other utility versions, later models, and models absent from this
package may differ. Current product listings are useful discovery sources,
but a product page does not establish compatibility with the 4.06 profiles or
native protocol. See [coverage status](COVERAGE.md) before treating a mapping
as confirmed.

## Start here

- [Main static reverse-engineering report](docs/reverse-engineering.md)
- [Model profile and `KB.ini` schema audit](docs/rk-profile-schema-audit.md)
- [Confidence-ranked profile tuple semantics](docs/rk-profile-tuple-semantics.md)
- [Profile-to-driver-family map](docs/rk-profile-driver-family-map.csv)
- [Machine-readable 188-profile catalog](models.json)
- [Installed package manifest](docs/rk-installed-package-manifest.csv)
- [Resource and localization audit](docs/rk-resource-localization-audit.md)
- [PE dialog-resource and selected updater control audit](docs/rk-dialog-resource-audit.md)
- [HID enumeration and hot-plug notification audit](docs/rk-device-enumeration-notification-audit.md)
- [Native API import, callsite, and syscall crosswalk](docs/rk-system-api-crosswalk.md)
- [Indirect API call and callback follow-up](docs/rk-native-api-indirect-call-audit.md)
- [Dynamic API resolution paths](docs/rk-dynamic-api-resolution-audit.md)
- [Updater UART receive state machine](docs/rk-updater-uart-state-machine.md)
- [Updater and firmware readback audit](docs/rk-firmware-readback-audit.md)
- [Settings serializer and command paths](docs/rk-setting-serializer-audit.md)
- [UI event and device worker path audit](docs/rk-ui-event-worker-path-audit.md)
- [Installer and uninstaller script audit](docs/rk-installer-uninstaller-script-audit.md)
- [Dated public model list compared with the 4.06 profile catalog](docs/rk-public-model-coverage-gaps.md)
- [Dated storefront model list and profile-name crosswalk](docs/rk-storefront-model-crosswalk.csv)
- [All audit documents and evidence tables](docs/)

## Open-source Windows workbench

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

## Related community work

Looking for open-source RK keyboard software? This repository is a convenient
index for the community projects and a detailed evidence archive for the
installed RK Windows suite. The projects below cover adjacent ground,
including actual device configuration and protocol implementations. Their
model support and hardware behavior are independent of the static 4.06
findings here:

- [Rangoli](https://github.com/rnayabed/rangoli) — cross-platform RK
  configuration software with protocol work based on packet captures.
- [Royal Kludge Configurator](https://github.com/Ripwords/royal-kludge-configurator)
  — a Tauri desktop configurator that builds on protocol work from Rangoli.
- [KludgeKnight](https://github.com/vinc3m1/kludgeknight) — browser-based
  configurator with key-configuration references from the official app.
- [RKCU](https://github.com/oddlyspaced/rkcu) — an RK61-focused USB
  configuration implementation.

For the installed Windows suite's static inventory—profiles, resources,
imports, callsite candidates, update paths, and evidence gaps—start with this
repository's [coverage ledger](COVERAGE.md) and
[main report](docs/reverse-engineering.md). No single package snapshot here
establishes compatibility with every RK model or revision.

The catalog and product names are RK trademarks. Research notes and scripts
are licensed under MIT; see [LICENSE](LICENSE) and
[data provenance](DATA-PROVENANCE.md).

The related [Keydeck RK Studio project](https://github.com/shubh-3011/keydeck-rk-studio)
is the companion web and Windows profile editor. This repository is the
standalone research archive and also publishes a research edition of that
open-source desktop workbench, with its source and build instructions.
