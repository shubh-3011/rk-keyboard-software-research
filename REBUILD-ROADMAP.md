# Native RK clean-room reconstruction: scope and current status

This is the target for the **second project**: an open-source, locally run
Windows reconstruction developed from the evidence in this repository. It is
separate from [Keydeck RK Studio](https://github.com/shubh-3011/keydeck-rk-studio),
the companion web/profile editor.

## Current status: first native milestone built from source

The source in [`rebuild/windows/`](rebuild/windows/) is a new C# WPF Windows
application with its own process and no Python, browser, WebView, or local web
server. It contains the first native shell, local profile/layout browser,
local key-label and macro-note drafts, an RK Drive ordered-slot keymap and
layer/table/effect draft editor with descriptor-checked local JSON import/export,
tray restore/exit, opt-in start-with-Windows, and a separate directory for the
public RK Drive keyboard registry. It checks present Windows PnP records,
matches catalogued product IDs, resolves model photos using profile and region
before shared image aliases, and offers a remembered photo selection when the
catalog remains ambiguous. ANSI S98 profiles also offer a manual photo selector
for six RK-hosted finishes/editions. Product photos are fetched from RK's hosts
on demand without bundling them. USB metadata cannot identify physical finish
or live RGB state. Its self-contained `.exe` is produced
by the documented build script; it is not the old downloadable prototype.

The downloadable `RK-Research-Workbench.exe` release is an earlier
**profile-editor prototype**. It is a PyInstaller bundle containing Python, a
local static HTTP server, HTML/CSS/JavaScript, and pywebview backed by
Microsoft Edge WebView2. That app is described in [`workbench/`](workbench/)
and [`workbench/README.md`](workbench/). It is not the native reconstruction.

The new native app is still an early reconstruction milestone, not a same-
function or pixel-matched RK replacement. Its RK Drive editor uses publicly
declared ordered symbolic slots, layers, OS tables, and per-effect controls
only to save local drafts; the bundle does not provide physical key geometry.
Hardware communication, RK-native settings serialization, TFT/media and
performance workflows, updates, firmware, and full workflow parity remain
unimplemented or unresolved. The research archive and rebuild are distinct
deliverables in this repository; the companion Keydeck web app remains a
separate product.

## Reconstruction target

- A native Windows process with local storage and a standalone `.exe`; no
  hosted site, Python runtime, loopback web server, or embedded browser UI.
- Familiar RK utility workflows and navigation, recreated from analyzed
  behavior: model selection, key mapping/layers, macros, lighting, keyboard
  options, audio-reactive effects, screen/GIF tooling, and update information.
- Continue using the public RK Drive registry as a separate evidence source
  for model labels, USB/receiver IDs, and declared layer/table/light-effect
  fields. Its current snapshot has 177 general connection descriptors across
  96 labels, plus two specialized RK68 HE profiles. Add advanced behavior
  controls such as DKS, snap, SOCD, toggle, or mod-tap only when model-specific
  settings and their runtime paths are separately mapped.
- Keep keyboard and mouse registries separate. A static mouse registry and
  feature-gate audit exist, but their model-specific controls are not yet
  reconstructed in the native application.
- Windows integration such as a notification-area icon, minimize-to-tray, and
  an explicit user-controlled start-on-login option.
- A source-first implementation with build instructions and an auditable
  feature-to-evidence matrix. Every model claim must identify a source profile
  and the confidence of its device-family mapping.
- Original replacement artwork and UI assets. RK's original binaries, source,
  fonts, illustrations, and other copyrighted assets will not be republished
  as open-source material. Matching the workflow does not grant permission to
  redistribute vendor art.

## Feature parity gates

| Area | Current prototype | Requirement before claiming parity |
| --- | --- | --- |
| Windows app shell | Native WPF shell in `rebuild/windows/`; older Python/WebView prototype retained separately | Feature-complete workflows, packaging/release, and evidence-linked parity coverage |
| Tray and autostart | Configuration/Exit tray menu and opt-in per-user startup in the native milestone | Verify behavior on supported Windows configurations and document any remaining differences |
| Model recognition | Present-device PnP metadata matching, profile-prioritized photo matching, selectable photos for ambiguous IDs, and manual S98 appearance photos; no HID communication or firmware-revision detection | Evidence-backed device identification with physical revision and ambiguous IDs shown as unknown |
| Keymap, macro, lighting, screen, audio | Layout viewer, local key-label and macro-note drafts, plus RK Drive layer/table/effect drafts with descriptor-checked JSON import/export; no device controls | Reconstructed control paths, data models, and model-specific availability |
| Hardware configuration | Disabled | Protocol and write paths must be independently mapped; no claim from profile labels alone |
| Firmware updater/readback | Not implemented | Complete static updater analysis and safe documented boundaries; current evidence does not show a reachable complete read-only S98 firmware export |
| Vendor artwork/assets | Not included | Clean-room replacements; no copied vendor art in the public repo |

## Safety and evidence boundary

The ongoing analysis remains static. The RK app/updater will not be launched,
the keyboard HID interface will not be opened, and no keyboard report or
command will be sent. Therefore, hardware behavior and full write-path parity
cannot be certified by active testing in this project. Reports must keep
**proven**, **inferred**, and **unresolved** findings separate. A firmware
readback routine is not considered safe merely because it contains a read
call; current updater evidence includes write-before-verify operations and
conditional UART file sinks with unresolved initialization and reachability.

## Exit criteria for a faithful reconstruction claim

Do not call the reconstruction complete until tray/autostart behavior is
verified and documented, every claimed RK workflow is mapped to evidence,
model support is confidence-labeled, and unsupported or unverified device
operations are visibly blocked. The current native milestone and the older
profile prototype do not satisfy these criteria.
