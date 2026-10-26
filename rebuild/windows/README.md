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
- On-demand display of product photos directly from RK's public image hosts.
  Connected-device photos prefer the exact software profile and layout region
  over a shared VID/PID image alias. Where the catalog exposes several possible
  images, the overview lets you select one and remembers that choice. Photos
  are not bundled, so loading them needs internet access.
- For the ANSI S98 profile, a six-photo gallery offers official product
  thumbnails (Lavender Purple, Deep Black, Sky Blue, Clay Green, Pink Edition,
  and Winter Limited Edition). No finish is selected by default: the app shows
  a model/layout reference and marks the finish unconfirmed until the user
  chooses one. The selected finish updates the large photo and is saved for
  the device/profile. USB identity does not report physical finish or keycap
  colors; photos are fetched at runtime.
- Read-only Windows USB/HID Plug and Play registry discovery. Catalogued VID/PID
  pairs can be matched to model profiles. It does not open a HID interface or
  send a device report.
- Profile selection and visual layouts from the catalog.
- Local-only key-label drafts, structured macro timelines, and legacy macro notes stored under
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
timelines/notes, key layer/table choices, and lighting values are local drafts, not
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

## Local macro timeline editor

Release 0.3.0 adds the editor below, profile-bound lighting drafts, and pure
offline protocol helpers. Run `./test.ps1` to execute all dependency-free
native model/codec test projects. These tests never open a device or launch
the WPF application.

### Profile-bound lighting draft

The Lighting page now permits saving a declared profile slot and a brightness
**lookup index** from that profile's explicit `LightUI` table. It shows the
raw display value and corresponding `LightHW` value where supplied, without
inventing a percentage or a missing output entry. These drafts are stored
separately, bound to the embedded **Hub 4.6** catalog, and must not be confused
with the installed 4.06 native record format. Missing or malformed explicit
tables disable the editor rather than creating guessed defaults. Existing
key/Drive drafts and macro notes are preserved.

### Offline codec foundation

- `ProtocolFrames.cs`: installed 4.06 3632 request framing and recorded-response
  classification, with no device transport. See the
  [framing scope](../../docs/rk-3632-offline-framing-2026-10-26.md).
- `LightingPacketCodec.cs`: distinct ordinary and firmware-2 patchers over an
  explicit 128-byte seed. Unknown bytes survive, all planned accesses are
  checked before mutation, and collisions/write provenance are returned.
  See the [codec evidence and limits](../../docs/rk-406-command04-offline-codec-2026-10-26.md).

Neither helper is wired to a keyboard, nor do synthetic tests establish model
compatibility. `test.ps1` isolates all four projects' intermediate/output
directories to prevent cross-project cached-executable false positives.

### Macro workflow

Open **Macro manager**, then **New timeline**. The profile-specific library has
a separate `MacroTimelines` property in settings; the existing
`MacroDrafts: { profile: ["note", ...] }` shape is unchanged. Existing notes remain
visible below the editor, are not interpreted as events, and can still be added
or removed independently. No migration or deletion of saved notes is performed.

- Set a name and local cycle metadata, then **Save header locally**.
- Choose `key`, `mouse`, or `delay`; enter a symbolic action such as `A down`,
  `A up`, or `left click`. These are free-text labels, not RK codes.
- All delays are integer **milliseconds (ms)**. On key/mouse rows this means
  a specified wait after the label; a delay-only row has no action. The displayed
  total sums specified waits per pass, not actual execution time.
- **Insert before** or **Insert after / append** inserts the field values around
  the selected row. With no selection, both append. Select a row to load its
  fields, edit, and use **Save selected row**. **Move up/down** and **Remove row**
  act on the selected row. Successful mutations save to local settings.
- Header and row fields are not autosaved: save them explicitly before switching
  profiles, switching pages/timelines, or exporting. Export uses saved model values.
- **Import local JSON** appends a new independent timeline into the current
  profile; it never overwrites an existing draft or note. **Export saved JSON**
  writes an app-owned `.rkmacro.json` package with format
  `rk-rebuild-local-timeline` and schema version 1. It is not compatible with
  `.mck`, `mac.dct`, RK Drive, or the companion app's JSON schema.

Community safety limits (not claims about RK hardware): 100 timelines per profile,
200 rows per timeline, 48-character names, 100-character action labels, delays
0–60000 ms, and cycle counts 1–99. `none`, `count`, `while-held`, and `until-press`
are local metadata only; no mode executes. JSON import rejects files over 1 MiB,
invalid UTF-8, malformed/deep JSON (depth over 16), unknown/duplicate properties,
missing required timeline/row properties, unsupported schema/format, and values
outside these limits. Invalid imports are checked before the profile is changed.
Invalid saved structured timelines are left unchanged and reported instead of
being silently normalized. Existing settings save/error behavior otherwise remains.

Workflow evidence: [`../../docs/rk-macro-format-and-path-audit.md`](../../docs/rk-macro-format-and-path-audit.md)
documents macro/event lists, insertion before/after, delay and cycle UI concepts,
local persistence, and import/export paths. The companion `rk-studio/app.js`
provides community structured key/mouse/delay steps and bounded local cycle
metadata. This implementation independently uses those workflow concepts, not
the unresolved native event fields, numeric mouse event mapping, capacity
heuristic, or family-specific serialization. No RK byte encoding, input hooks,
recording, playback, device writes, firmware, or startup changes were added.
The current controls/layout are a community editor, not a claim of pixel-identical
recovered RK runtime UI or device capability validation.

### Repeatable model checks

Using the existing local SDK (no added packages or test runner):

```powershell
./.dotnet/dotnet.exe run --project ./tests/MacroTimeline.Tests.csproj --configuration Release
./build.ps1
```

The console checks compile the production pure model/codec directly. They cover
round trips, ordering, boundary/null/shape validation, schema/format checks,
bounded UTF-8 file import, and an additive legacy-settings-shape round trip.
They do not exercise WPF interactions, the complete settings store, or hardware.
The test sources are excluded from the WPF application's compilation.

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
