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
  source-free registry snapshot: 177 connection descriptors across 96 standard
  labels, plus the two separately declared RK68 HE profiles. Search includes
  connection type, protocol, VID/PID, and HID usage identifiers. Each record
  shows its declared key layers, OS tables, layout count, and lighting modes.
- On-demand display of product photos directly from `drive.rkgaming.com`.
  The executable does not contain or mirror those images or the vendor's
  JavaScript; the directory and metadata work offline, while a photo needs
  internet access.
- Profile selection and visual layouts from the catalog.
- Local-only key-label drafts and macro notes stored under
  `%LOCALAPPDATA%\RK-Rebuild\settings.json`.
- An optional local package folder setting for viewing profile artwork already
  present on this PC. Vendor assets are read from that folder at runtime and
  are not included in this repository or executable.
- A notification-area icon with **Configuration**, **Start with Windows**,
  and **Exit**. Minimizing or closing the window hides it to the tray. Start
  with Windows is an opt-in per-user setting and can be changed in Preferences
  or the tray.

## Not a full RK replacement yet

This build does not detect or communicate with a keyboard. It does not read or
write HID reports, apply key mappings or lighting, capture or transfer macros,
control displays, run updates, or read/write firmware. Its key labels and
macro notes are local drafts, not RK-native serialized settings. The catalog
contains software profiles from one package snapshot; it is not a complete
model/revision census. Model and feature parity are not certified.

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

## Assets and licensing

The UI artwork is original. No RK application binary, source, font, installer,
firmware image, or copied product image is distributed here. The bundled RK
Drive catalog contains extracted model/connection fields and official image
URLs, not vendor code or image bytes. Product photos are fetched from the RK
host only when a model is selected. If you select a local RK app folder, the
application may read `Dev/<profile code>/keyimg.png`, `kbled.png`, or
`sideled.png` for display on this PC. The selected directory is not modified.
Those files and remote images remain subject to their original rights and are
not part of this project's MIT-licensed source.
