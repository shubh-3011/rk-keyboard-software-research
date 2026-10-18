# RK Research Workbench for Windows (legacy prototype)

> This is the earlier Python/WebView2 profile-editor prototype. It is not the
> native Windows reconstruction. Current native source and build instructions
> are in [`../rebuild/windows/`](../rebuild/windows/).

The RK Research Workbench is a source-backed, local Windows desktop profile
studio packaged with this research repository. It reuses the open-source
Keydeck profile-editor code and the research repository's 188-profile catalog.
The web editor and first Windows build remain in the separate
[Keydeck RK Studio repository](https://github.com/shubh-3011/keydeck-rk-studio).

## What it does

- Browse the model profiles captured from RK Keyboard Software 4.06 and show
  their recorded layouts and capabilities.
- Edit local keymap, lighting, macro, connection preference, and display
  profile data.
- Save profiles on this PC and import or export profile JSON.
- Identify a user-authorized device from its USB/HID descriptor if the
  installed WebView2 runtime exposes WebHID.
- Build as an independent Windows `.exe` that opens an app window and does
  not require the hosted website or a general-purpose browser.

The app does not open a HID interface, read or send HID reports, replay
traffic, change hardware settings, control the display, transfer screen media,
update firmware, or write to the keyboard. The profile controls are local data
editing. This is not the official RK program, is not affiliated with RK, and
is not yet a hardware-functional replacement for it. Those limits follow the
static-only evidence in the parent [research report](../docs/reverse-engineering.md)
and [coverage ledger](../COVERAGE.md).

## Previous prototype release

The previously published `RK-Research-Workbench.exe` is built from this
directory's source. It is the Python/PyInstaller/WebView2 prototype described
above, not the native app. The native rebuild has a separate source folder and
build instructions; do not use this legacy release to evaluate native tray,
startup, or device behavior.

Microsoft Edge WebView2 Runtime is required. Most supported Windows 10/11
systems already have it. User profile data and WebView2 storage stay under
`%LOCALAPPDATA%\RK-Research-Workbench\WebView2`.

## Build from source

Requirements: Windows, Python 3.10 or newer, and Microsoft Edge WebView2
Runtime. From PowerShell in this directory:

```powershell
python -m pip install -r requirements-desktop.txt
./build.ps1
```

The build creates `dist\RK-Research-Workbench.exe`. The app starts a static
server on `127.0.0.1:38459` and opens that local page in a WebView2 window.
The server does not expose device or profile APIs. The app stores editable
profile data in WebView2's local storage; nothing is sent to an online service.

The source is licensed under the parent repository's [MIT License](../LICENSE).
RK names and marks belong to their respective owners.
