# Native RK clean-room reconstruction: scope and current status

This is the target for the **second project**: an open-source, locally run
Windows reconstruction developed from the evidence in this repository. It is
separate from [Keydeck RK Studio](https://github.com/shubh-3011/keydeck-rk-studio),
the companion web/profile editor.

## Product scope: general RK support, not a single-keyboard build

The target is one installable replacement for Royal Kludge keyboard owners,
not an S98-specific utility or a build bound to the developer's connected
keyboard. Hardware on this PC is one potential test fixture, not the product
scope or evidence for other models.

- Keep model/revision/connection descriptors separate from reusable protocol
  backends. USB, receiver and Bluetooth variants may differ for one model name.
- Keep installed 4.06, Hub 4.6 and RK Drive source snapshots distinct. A profile
  or protocol label is a declaration, not a hardware-validation result.
- Preserve every candidate for shared VID/PIDs. Neither a chosen photograph
  nor a manual profile selection proves firmware/revision compatibility.
- Add backends and fixtures by protocol family, with per-feature validation
  for concrete device revisions. Do not add model-name conditionals to a common
  codec to make one physical keyboard appear universally supported.
- Show unsupported/unknown devices and the reason a feature is unavailable.
  Never send speculative configuration commands to an unknown interface.
- Require a reproducible build/install path, original redistributable assets,
  contribution fixtures and an explicit tested-device list before broad release.

The app's **All-model compatibility** page and offline JSON export present
catalogue entries without calling them supported devices. The first-run
reference profile has no hardcoded S98 preference. Saved user choices remain
intact. This is a foundation for general support, not a universal-compatibility
claim; no keyboard revision has certified hardware writes in the current app.

## Current status: first native milestone built from source

The source in [`rebuild/windows/`](rebuild/windows/) is a new C# WPF Windows
application with its own process and no Python, browser, WebView, or local web
server. It contains the first native shell, local profile/layout browser,
local key-label drafts, structured macro timelines and legacy notes, an RK
Drive ordered-slot keymap and layer/table/effect draft editor with
descriptor-checked local JSON import/export,
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

Earlier reports were deliberately static. On 2026-10-26 the user authorized
runtime investigation and tool execution to pursue general RK compatibility.
That permission enables scoped vendor-UI/transport observations; it does not
make an unobserved path hardware-validated. Declare the target, capture scope,
device/connection and action for each runtime session, avoid capturing typed
user input, and preserve before/after state where possible. Firmware flashing,
bootloader transitions and factory resets are not part of ordinary compatibility
testing and remain excluded unless separately planned. Reports must keep
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
