# RK Rebuild for Windows

This is the first native desktop reconstruction milestone, separate from both
the Keydeck web product and the older Python research workbench. It is a
source-first WPF application written in C# and published as a self-contained
Windows process. It does not use Python, a local web server, a browser, or
WebView2.

## Included now

### 0.6 preview: wired query, MSI and offline UI checks

The USB G5 lighting reader has been hardware-validated with the published
EXE on one observed `258A:01AF` revision. It discovers the Feature report ID
from HID metadata and uses an isolated, deadline-bounded helper. This does
not enable wired settings writes or certify other models/revisions.

```powershell
.\RK-Rebuild.exe --read-g5-lighting 258A:01AF new-g5-read.json
.\RK-Rebuild.exe --ui-smoke-test new-offline-ui-report.json
```

Close the vendor utility normally before the active lighting query. The UI
smoke renders nine pages without vendor assets, network, settings persistence
or device access; it does not exercise hardware buttons or prove feature parity.
The independent unsigned per-user MSI is built with
`installer\build-installer.ps1`; see [installer notes](installer/README.md).
See [validation and limits](../../docs/rk406-native-g5-reader-validation-2026-10-27.md).

### Existing capabilities

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

## Experimental lighting-configuration read

**0.5.0 adds one strictly evidence-gated writing operation:** switch between
the observed Off/first-effect wire modes while preserving every other byte.
After a successful query, eligible configurations offer explicit apply buttons
on the Compatibility page. All other configurations stay write-disabled.
See [the operation policy and failure boundary](../../docs/rk406-experimental-lighting-write-2026-10-26.md).

The gate requires the observed endpoint metadata **and** the entire known
configuration fingerprint (excluding only the mode byte). Even the same keyboard
with other lighting settings will be refused. Do not copy fixture bytes onto a
device to force a match. This is not general model support or universal RK
compatibility; it is an incremental, reproducible operation in a general app.

Headless apply requires a matching native read report and explicit confirmation:

```powershell
./dist/RK-Rebuild.exe --apply-observed-wireless-mode <VID:PID> <0|1> ./lighting-read.json ./new-apply-result.json --confirm-experimental-write
```

The output must be new and is reserved before hardware access. The current
block is re-queried on the same handle; a stale baseline causes refusal before
configuration writes. A successful change requires echoed frames and a fresh
complete query matching the patched block. A partial write, timeout or failed
verification may leave hardware state uncertain: there is no automatic retry
or rollback. Re-query before another write. The UI retires a baseline after
every attempted apply, and application exit is blocked during its operation.

**Hardware validation:** the replacement completed Off → first effect → Off
over the 20-byte 2.4 GHz path, including both transaction readbacks and separate
independent queries. Only offset `0x0A` changed; the final 128 bytes matched the
original exactly. The vendor utility was restarted afterward. See the
[retained native check](../../docs/runtime-evidence/native-verified-lighting-mode-roundtrip-2026-10-26.json).
Earlier failed attempts and the recovered 200/15/50 ms timing intervals are
documented in the operation report; this was not universal hardware validation.

Version **0.4.0** adds actual HID endpoint discovery and a narrowly bounded
lighting query. This is no longer entirely a disconnected draft editor,
but that version did not apply settings. Version 0.5.0 adds only the operation
described above, not unrestricted configuration writes.

1. Open **All-model compatibility** and click **Inspect HID endpoint metadata**.
   Discovery obtains VID/PID, device version, usage page/usage, and report sizes
   through zero-access metadata handles. It does not read input reports.
2. An eligible catalogue-matching vendor endpoint (`FF02:0002`, 20-byte
   input/output reports) offers **Experimental lighting query**. This is an
   explicit active query: it sends command `44`, receives a 128-byte lighting
   block, and checks packet order/count/length plus its `5A A5` signature.
3. Close the vendor utility normally first. The app refuses a query while
   `DeviceDriver.exe` is running, refuses ambiguous multiple matching endpoints,
   and applies one absolute timeout. There are no retries or fallback probes.
4. The result can be exported without device paths or serial strings. No
   configuration, macro, keymap, reset, bootloader or firmware command is sent.

Headless alternatives (output paths must be new):

```powershell
./dist/RK-Rebuild.exe --hid-diagnostics ./hid-metadata.json
./dist/RK-Rebuild.exe --read-wireless-lighting <VID:PID> ./lighting-read.json
```

The second command is intentionally opt-in and experimental, not automatic
device detection. It requires exactly one eligible endpoint for the supplied
catalogued identity. The metadata export omits opaque HID paths and does not
retrieve serial strings. Device version numbers are not certified firmware IDs.

### What was hardware-validated

The native reader successfully queried all **128 bytes** from the connected
fixture; its result exactly matched the original block observed through the
vendor utility. The vendor utility was closed normally for this test and
restarted with its original `-s` background argument afterward.

Separately, the vendor's ordinary G5 → 3632-child path was observed during
an effect-off → first-effect → effect-off round trip. The trace retained 62
allowlisted lighting reports. Only block offset `0x0A` changed (`0→1→0`);
the second query returned the first changed block, the final outgoing block
and echoes equalled the initial block, and the independent native query
confirmed final restoration. No keymap/macro input was captured.

This validates a **query operation and one observed path**, not every model
sharing `258A:0150` or every workflow. The runtime root was `CDevG5KB`, but the
actual reports used its 20-byte child rather than the 520-byte G5 feature
transport. Shared VID/PID alone would not have established that distinction.

### Code and reproducibility

- `HidDiscovery.cs`: metadata only, safe-handle disposal and bounded enumeration.
- `WirelessLightingReader.cs`: one query, cancellable bounded reads, strict
  10-frame assembly and no arbitrary-command/configuration-write API.
- `G5FeatureCodec.cs`: separate pure offline 520-byte framing, not a claim of
  validated G5 feature transport. Its header differs from the screen writer.
- `tests/fixtures/rk406-wireless-lighting-roundtrip.json`: derived, reviewed
  lighting-only golden frames; no paths, serials, keymaps or artwork.
- `scripts/extract_rk406_lighting_fixture.py`: regenerates/validates the fixture
  from the saved direct-Frida trace. Such traces are not relabeled REA Evidence.

Retained records:
- [REA active-device/vtable snapshot](../../docs/runtime-evidence/rk406-lighting-device-state-2026-10-26.json),
  Evidence `ev_892d00024fee1046dd72bc16e91277be1f43587518da7930a9539f0912f28318`.
- [Direct-Frida lighting-only round trip](../../docs/runtime-evidence/rk406-wireless-lighting-roundtrip-frida-2026-10-26.json).
- [Independent native lighting read](../../docs/runtime-evidence/native-wireless-lighting-read-2026-10-26.json).

REA's snapshot still reports artifact identity unavailable: the host supplied
the executable path/hash check. The direct-Frida report and native read are
separate authored observation records, not canonical REA Evidence. Vendor
screenshots remain local and are not included or relicensed.

Captured query-response checksum bytes do **not** match the outgoing additive
rule. The native vendor consumer does not check them; this implementation
does not invent a response checksum. The signature/framing checks are not
authentication or proof of complete protocol understanding.

## Not a full RK replacement yet

### General compatibility, not an S98-only build

The product goal is a single application for RK owners across models and
protocol families. **All-model compatibility** lists the embedded Hub 4.6 and
RK Drive keyboard source entries, allows filtering/export, and shows every
candidate for matching present PnP VID/PIDs. Shared IDs are not resolved by
guessing a physical model. Mouse descriptors are excluded. There is no
hardcoded S98 first-run preference; saved profile/photo choices still work.

An entry is currently **catalogued only**: all entries explicitly report that
hardware writes are unavailable. Declared protocol names remain source labels,
not an automatic binding to a transport or firmware family. Separate models,
revisions and connection types will need evidence-backed feature validation.

Version 0.3.1 preserves **444 source entries**, not 444 certified keyboards:
265 Hub profiles, 177 ordinary RK Drive connection descriptors, and two
specialized keyboard profiles. The compatibility test suite checks all real
source records, direct identities, source separation, ambiguous matches,
invalid identities and mouse exclusion (11 tests / 4,513 assertions).

For automation, the following exports the full catalogue without starting the
UI, touching settings/startup or accessing hardware. The output path must be
new; existing files are never overwritten by this CLI command:

```powershell
./dist/RK-Rebuild.exe --compatibility-report ./rk-compatibility.json
```

Unlike the general UI launch, this command does not fetch photos or enumerate
devices. A failed export returns a nonzero process exit code without a modal
dialog.

### Runtime observation boundary

With the user's runtime authorization, REA 6.7.0 attached to the already-running
installed x86 `DeviceDriver.exe` and observed six known lighting-function entry
counters for 1,803 ms. All six counts were zero during that idle window; the
script detached all six interceptors. No control was changed and no argument,
typed input, device report or configuration buffer was captured. This verifies
the observation route, **not** an executed brightness workflow or device support.
The [complete runtime result](../../docs/runtime-evidence/rk406-lighting-counters-2026-10-26.json)
contains Evidence `ev_b72c93e83943aa3b5082cab9a994acab648243b9fc8bfeca1733403d30b93084`.
REA reports artifact identity unavailable and lacks OS/architecture metadata;
the host separately checked the installed path and SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`
before attaching. The script asserts x86 and checks relocated entry witnesses.
The snapshot's `state=running` precedes REA's cleanup; cleanup reports no error.
The reproducible [counter-only script](../../scripts/observe_rk406_lighting_counts.js)
must not be used with other executable hashes.

PnP discovery uses Windows SetupAPI's present-device list and reads device
metadata only. A shared wireless-receiver VID/PID may identify several product
labels, so the app asks you to select the matching photo in that case. The
reported USB identity does not confirm shell finish, keycap color, firmware
revision, or the keyboard's live lighting mode/color.
Outside the explicit experimental lighting operations above, this build does not
read/write HID reports. It does not apply key mappings or general lighting drafts, capture or transfer macros,
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

`./test.ps1` runs the dependency-free native test suites; after building,
`./smoke-test.ps1` executes only the published EXE's headless catalogue export
and error paths. It does not start the WPF UI or touch a device. The
[Windows CI workflow](../../.github/workflows/windows-native.yml) repeats these
checks plus the Python synthetic tests on a clean runner and uploads the EXE
and checksum as a downloadable build artifact. This is an unsigned Windows
x64 preview, not a signed installer or a universal hardware-support release.

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
compatibility. `test.ps1` isolates all projects' intermediate/output
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
