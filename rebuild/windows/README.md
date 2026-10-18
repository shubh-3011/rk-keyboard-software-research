# RK Rebuild for Windows

This is the first native desktop reconstruction milestone, separate from both
the Keydeck web product and the older Python research workbench. It is a
source-first WPF application written in C# and published as a self-contained
Windows process. It does not use Python, a local web server, a browser, or
WebView2.

## Included now

- A local profile catalog built from the 265 entries in the separately
  documented RK 4.6-labeled package snapshot.
- A second, distinct RK Drive directory built from the public web app's
  derived registry snapshot (without vendor code): 177 connection descriptors
  across 96 standard labels plus the two separately declared RK68 HE profiles.
  Search includes
  connection type, protocol, VID/PID, and HID usage identifiers. Each record
  shows its declared key layers, OS tables, layout count, and lighting modes.
- On-demand display of product photos directly from `drive.rkgaming.com`.
  Connected-device photos prefer the exact software profile and layout region
  over a shared VID/PID image alias. Where the catalog exposes several possible
  images, the overview lets you select one and remembers that choice. Photos
  are not bundled, so loading them needs internet access.
- Read-only Windows USB/HID Plug and Play registry discovery. Catalogued VID/PID
  pairs can be matched to model profiles. It does not open a HID interface or
  send a device report.
- Profile selection and visual layouts from the catalog.
- Local-only key-label drafts and macro notes stored under
  `%LOCALAPPDATA%\RK-Rebuild\settings.json`.
- An **RK Drive editor** that stages the selected descriptor's declared key
  layer, OS table, lighting effect, and supported effect controls as local
  drafts. For standard descriptors, the editor also shows the bundle's ordered
  symbolic key slots and lets you choose per-slot numeric key codes. The
  extracted data does not include physical key coordinates. Drafts are keyed
  by model and connection row and saved only under
  the current Windows user's local settings. Drafts can be exported to or
  imported from a JSON package that records the catalog bundle hash and full
  selected descriptor identity. Schema 2 adds per-slot drafts and schema 1
  remains importable. Imports reject mismatched descriptors and values outside
  the local catalog declarations; a catalog-version mismatch requires an
  explicit confirmation.
- An optional local package folder setting for viewing profile artwork already
  present on this PC. The Windows app also finds the standard RK installation
  automatically when it is present.
- RK-skinned native UI using the installed package's `main_nr.png`, RK logo,
  control-state images, Open Sans font files, and tray icon. Model pages use
  the matching local `Dev/<profile>` keyboard artwork when available; profiles
  with the same family can use a compatible art profile from the installed
  package when a code differs between software versions.
- A notification-area icon with **Configuration**, **Start with Windows**,
  and **Exit**. Minimizing or closing the window hides it to the tray. Start
  with Windows is an opt-in per-user setting and can be changed in Preferences
  or the tray.

## Not a full RK replacement yet

PnP discovery uses Windows SetupAPI's present-device list and reads device
metadata only. A shared wireless-receiver VID/PID may identify several product
labels, so the app asks you to select the matching photo in that case. The
reported USB identity does not confirm shell finish, keycap color, firmware
revision, or the keyboard's live lighting mode/color.
This build does not communicate with the keyboard. It does not read or write
HID reports, apply key mappings or lighting, capture or transfer macros,
control displays, run updates, or read/write firmware. Its key labels, macro
notes, key layer/table choices, and lighting values are local drafts, not
RK-native serialized settings. Ordered slot mappings are a community draft
format, not recovered RK key-layout geometry or a native mapping payload. The
`.rkdrive.json` files are this app's own
portable draft format, not files accepted by RK Drive or keyboard firmware.
The web bundle also exposes TFT/media,
performance, advanced-key, function-setting, and firmware pages; those
workflows are indexed in the source audit, but they are not implemented here.
The catalog contains software profiles from one package snapshot; it is not a
complete model/revision census. Model and feature parity are not certified.

The source archive documents static control flow and known gaps separately in
[`../../docs/README.md`](../../docs/README.md) and
[`../../REBUILD-ROADMAP.md`](../../REBUILD-ROADMAP.md). Tray behavior is based
on the recovered `Configuration` and `Exit` actions. Start-at-login is a new
community-app preference; the available RK evidence does not establish that
the vendor utility autostarts.

## Build

Requirements: Windows and the .NET 8 SDK. From PowerShell:

```powershell
./build.ps1
```

The output is `dist\RK-Rebuild.exe`; it includes the .NET runtime and model
catalog and does not require a separate .NET installation on its target PC.
The build script writes a SHA-256 sidecar. Settings are local to the current
Windows user.

## Local RK skin and asset handling

When RK Keyboard Software is installed in its standard Windows folder, RK
Rebuild loads the existing `skins/`, `font/`, `appico.ico`, and selected
`Dev/<profile code>/` files directly from that installation. You can also
choose another local package folder in Preferences. The selected directory is
read only. The app does not copy, edit, or delete those files.

The public repository and executable do not contain RK's artwork, fonts,
installer, firmware, or application binary. Each user who wants the original
skin needs a local RK software installation. The desktop shell now uses RK's
own background, logo, icon sprites, button states, font family, and available
model artwork; the exact runtime position of every original feature control
has not been recovered from static resources. See
[`../../docs/rk-ui-reconstruction.md`](../../docs/rk-ui-reconstruction.md) for
the asset map and evidence limits. The bundled RK Drive catalog contains
derived model/connection fields and official image URLs, not image bytes.
