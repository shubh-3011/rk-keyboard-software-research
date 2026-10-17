# Native RK clean-room reconstruction: scope and current status

This is the target for the **second project**: an open-source, locally run
Windows reconstruction developed from the evidence in this repository. It is
separate from [Keydeck RK Studio](https://github.com/shubh-3011/keydeck-rk-studio),
the companion web/profile editor.

## Current status: not built yet

The downloadable `RK-Research-Workbench.exe` is an earlier **profile-editor
prototype**, not the reverse-built RK application. It is a PyInstaller bundle
containing Python, a local static HTTP server, HTML/CSS/JavaScript, and a
pywebview window backed by Microsoft Edge WebView2. It does not implement the
RK native application, system-tray behavior, login autostart, or keyboard
configuration writes. The source is in [`workbench/`](workbench/); its exact
limits are in [`workbench/README.md`](workbench/README.md).

The prototype must not be described or advertised as a same-function RK
replacement. The research repo currently contains reverse-engineering
evidence and this prototype; it does **not yet contain the native clean-room
reconstruction described below**.

## Reconstruction target

- A native Windows process with local storage and a standalone `.exe`; no
  hosted site, Python runtime, loopback web server, or embedded browser UI.
- Familiar RK utility workflows and navigation, recreated from analyzed
  behavior: model selection, key mapping/layers, macros, lighting, keyboard
  options, audio-reactive effects, screen/GIF tooling, and update information.
- Incorporate the public RK Drive registry as an evidence source for model
  labels, USB/receiver IDs, and feature families. Its current snapshot has 177
  connection descriptors across 96 labels. Add advanced behavior controls
  such as DKS, snap, SOCD, toggle, or mod-tap only when model-specific settings
  and their runtime paths are separately mapped.
- Keep keyboard and mouse registries separate until the Web Driver's mouse
  model map and supported controls have their own audit.
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
| Windows app shell | Python/PyInstaller + local HTML in WebView2 | Native desktop UI/process and standalone local app behavior |
| Tray and autostart | Not implemented | Tray open/restore/exit; autostart opt-in that can be disabled |
| Model recognition | Optional descriptor-only prompt | Evidence-backed model/revision identification with ambiguous IDs shown as ambiguous |
| Keymap, macro, lighting, screen, audio | Local profile editing only | Reconstructed control paths, data models, and model-specific availability |
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

Do not call the reconstruction complete until the native source and EXE are
available, tray/autostart behavior is documented, each official UI workflow is
mapped to evidence, all model support is confidence-labeled, and unsupported
or unverified device operations are visibly blocked. The existing profile
prototype does not satisfy these criteria.
