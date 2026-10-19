# RK 4.06 audio-reactive path audit

## Scope and evidence

This is an offline static analysis of the installed `DeviceDriver.exe` from RK
Keyboard Software 4.06 and its installed configuration/localization files. The
driver SHA-256 is
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`
(2,326,528 bytes, x86). The hash matches the package manifest and native API
inventory. Addresses below are x86 virtual addresses in that exact image.

The distinction used here is important: Windows loopback capture is a host
audio-input path; `CDevRKKB::SendMusicData` is a separate keyboard-output path.
The static evidence does not close the data-flow edge between them. No RK app
or updater was run, no audio was captured, and no HID/GATT/serial interface was
opened or used. No command or report was sent.

Evidence labels:

- **Proven statically:** directly supported by package bytes, imported API
  references, disassembly, or decompilation for the hashed binary.
- **Inferred:** interpretation supported by call arguments, object fields, or
  nearby code, but without complete type/control-flow proof.
- **Unresolved:** the available static artifacts do not show the mapping or
  runtime outcome.

## Feature labels and profile configuration

**Proven — localization.** The English `Text/en/text.xml` contains 20
audio-related keys: ten `tc_music*` setting/option keys and ten
`tc_music_mode*` effect-name keys:

| Key | English value |
| --- | --- |
| `tc_music1` | Music |
| `tc_music2` | Gain factor |
| `tc_music3` | The keyboard light changes with the rhythm of the system sound |
| `tc_music4` / `tc_music5` | Monochrome / ColorFull |
| `tc_music6` / `tc_music7` | ON / OFF |
| `tc_music8` | Effect |
| `tc_music9` | Audio device |
| `tc_music10` | Auto gain |
| `tc_music_mode1`–`tc_music_mode10` | Effect1–Effect10 |

The same intended key set is present in each of the seven UI locale XML files;
the existing [resource and localization audit](rk-resource-localization-audit.md)
records the Japanese XML parse defect and its in-memory-only normalization.
These XML keys establish the audio feature's user-facing vocabulary, not a
control ID, event handler, or device command. The UI is substantially generated
dynamically, and no exact `tc_music*` label-to-control-to-writer chain has been
recovered; see the [UI control crosswalk](rk-ui-control-command-crosswalk.md).

**Proven — profile/runtime fields.** `FUN_004513B0` reads these values while
initializing the selected profile:

| Field | Static behavior | Installed profile evidence |
| --- | --- | --- |
| `OPT\MusicMask` | Reads an integer into `0x00611818`, default `0`. | Present in 12/189 profiles; every stored value is `0x08`. |
| `OPT\MusicInter` | Reads an integer into `0x00612B26`, default `10`. | Not stored in the 189-profile snapshot, so the loader default applies when absent. |
| `OPT\MusicRGBIndex` | Parses a comma tuple into `0x00612B4C` onward; warns if the three parsed bytes do not sum to 3. | Present in 29 profiles; all are `1,0,2`. |
| `OPT\ShowMusic` | Read by the profile loader at `0x0045274D` into a local text buffer and passed through a numeric parser that writes adjacent globals beginning at `0x00612B53`; the downstream meaning and gating role remain unresolved. | Present only in profile `014E`, with value `0`. |

These are profile/configuration observations, not proof that any particular
model exposes or runs the feature. `MusicRGBIndex` is a runtime color-channel
ordering input by name and use in the profile initializer; the worker later
uses its three bytes to choose the destination positions for the three bytes
of a packed value (`0x0043BBB8`–`0x0043BC22`). The channel names and exact
effect on music samples remain unknown. `MusicMask` is tested as a bit mask in
an effect-list builder (`0x0042424F`–`0x0042425C`): it skips the candidate
whose bit is set for the current loop index. That is a list-building filter;
it is not evidence that the mask gates WASAPI capture or the keyboard writer.
The [lighting/color audit](rk-rgb-lighting-color-payload-audit.md) documents
`MusicRGBIndex` separately from the normal RGB and game-color paths.

The profile loader also reads `OPT\VerNeedToUpdate` into byte global
`0x00612B20` (`0x0045171F`–`0x00451729`; the installed snapshot has a value
only in profile `01AF`). `Music_Theard` passes this byte as the final argument
at one writer dispatch (`0x0043BAC0`). The value's meaning at that call is
unresolved; it is not established as a music-specific option.

The package also contains global and model-local `ET/*/audiobar.txt` files.
Their comments and text describe audio bars as key-group/layer data. The
installed set contains 74 global ET text files across 18 numbered folders.
This supports an audio-visualization resource family, but does not by itself
prove which profile file is loaded for a particular effect or how its tokens
reach a device packet.

## Host-side audio capture and processing

**Proven statically.** `FUN_0043C780` contains a WASAPI loopback path. Its
`CoCreateInstance` call is at `0x0043C85D`; the code obtains an
`IMMDeviceEnumerator`, registers an endpoint-notification callback, asks for
the default endpoint with `eRender`/`eConsole` arguments, activates an
`IAudioClient`, obtains the mix format, and initializes capture with
`AUDCLNT_STREAMFLAGS_LOOPBACK` (`0x20000`). It then obtains an
`IAudioCaptureClient`, polls packet size, reads captured buffers, releases
them, converts supported sample representations to floating point, and
reduces audio into 24 visualization bands. The capture routine uses a large
`0x60C8`-byte stack frame. A nearby helper at `0x0043C670` accumulates sample
squares, divides by the sample count, and calls a square-root helper; this is
consistent with RMS-style amplitude processing.

The COM lifecycle is threaded:

1. The worker entry at `0x0043D7D0` calls `CoInitialize(0)` at
   `0x0043D7D2`, calls `FUN_0043C780` at `0x0043D7DC`, then calls
   `CoUninitialize()` at `0x0043D7E1`.
2. The start routine at `0x0043D7F0` sets an active flag and creates a thread
   at `0x0043D823`, passing `0x0043D7D0` as its entry point.
3. The stop routine at `0x0043D830` clears the active flag and a related
   object flag. Static references include start/stop calls at
   `0x00424D9B`/`0x00424DB4` and `0x0043C63A`/`0x0043C610`. The caller fields
   and exact UI action that select these branches are not named reliably.

COM interface methods are invoked through vtables, not imported by their
individual method names. In the PE import table, the directly imported COM
support relevant to the worker includes `ole32!CoCreateInstance`,
`ole32!CoInitialize`, `ole32!CoUninitialize`, and `ole32!CoTaskMemFree`.
The capture method does not use a named `waveIn*` import: it obtains audio
through WASAPI COM interfaces. `WINMM.dll` is also imported, but its visible
entries are `PlaySoundW` and multimedia-timer functions. The import crosswalk
records no direct callsite for `PlaySoundW`; the timer callsites are elsewhere
in the image and are not shown to be part of the loopback capture path. An
import alone is not evidence of execution.

**Inferred — in-process buffering.** The neighboring routines at
`0x0043C270`, `0x0043C2C0`, and `0x0043C390` allocate/init a buffer, append
data with wraparound, signal an unnamed event created with all-zero arguments,
and wait for queued data under a critical section. The fields at offsets
`+0x04`, `+0x08`, `+0x0C`, `+0x14`, `+0x18`, and `+0x1C` behave like a backing
buffer, capacity, position/count, event, and lock. This is host-process
buffering; its exact ownership relationship to the WASAPI worker and every
sample-processing stage remain only partly established.

The `Audio device` localization label suggests a selectable endpoint, while
the captured path statically requests the default render/console endpoint.
Whether a UI selection changes that endpoint request, or whether the label
controls another setting, is **unresolved**. This routine captures system
playback loopback; it does not establish microphone capture.

## Local audio configuration and visualization settings

The resource inventory records `audio.dct` as a local 36-byte (`0x24`)
audio-visualization configuration record. The package manifest contains no
`audio.dct` sample, so its byte layout cannot be independently checked against
a saved instance. The available native notes identify `FUN_0043BEE0` as
reading text configuration into an in-memory matrix and `FUN_00438810` as
building an audio-visualization structure. Direct calls into these routines
appear at `0x004396F1`/`0x004398EA` and `0x0043962E` in the UI-side code. The
exact text file path, settings offsets, UI control mapping, and
`audio.dct`-to-visualizer data flow are **unresolved**. No installed `audio.dct`
was found to fill that gap.

The present evidence therefore has three distinct layers:

1. Local profile/configuration fields and pattern text (`MusicMask`,
   `MusicInter`, `MusicRGBIndex`, `audio.dct`, and `ET/*/audiobar.txt`).
2. Host-side WASAPI capture, sample conversion, visualization-band
   processing, and in-process buffering.
3. A keyboard-specific writer described below.

The joins from profile/resource settings into capture, and from captured
samples into the separate device worker, are not fully traced. The dispatch
from that worker to the device-family writer methods is recovered below.

## Device worker and keyboard-output paths

**Proven statically — a separate device worker exists.** The long-running
`Music_Theard` routine begins at `0x00439210`; its exit diagnostic is emitted
at `0x0043BE44`. Each loop first requires global `0x00609AE4 == 0` and a
non-null active-device pointer at `0x0062B380`. It asks the active object's
vtable slot `+0x14` for a successful state. If that test fails, it proceeds
only when the root object's `+0x24C` field is nonzero, its child at `+0x250`
exists, the child's `+0x258` field is zero, and that child's vtable slot
`+0x14` succeeds (`0x00439210`–`0x00439275`). These are observed branch
conditions; the fields' source-level names are unknown.

The worker snapshots global `0x00609AE8` as its current mode. When the root
object's `+0x24C` is zero, it waits 5 ms on each loop unless mode is 9; when
that field is nonzero, it waits the profile byte `OPT\MusicInter` at
`0x00612B26` (default 10; `0x0043927B`–`0x004392A4`). A local copy of the
mode is compared with 3 at `0x0043B9FE`, selecting a distinct record-output
branch. No source-level mapping from those mode values to the ten localized
effect names was recovered.

The worker builds family-independent data and calls the active device's
vtable slot `+0x40` at `0x0043B91B`, `0x0043B94F`, `0x0043B9BD`, and
`0x0043BAC0`. The nearby error strings are “Set music failed”, “Set rgb
music failed”, and “SendMusicData failed”. The calls pass different buffers,
lengths, and fourth-argument values; these are static dispatch sites, not
proof that a particular device class ran them.

In the non-mode-3 record builder, local records have a repeated `0x88`-byte
stride. The worker stores a DWORD value at record `+0`, a DWORD byte count at
`+4`, and appends matching one-byte entries starting at `+8`; the count is
bounded by `0x7E` (126) (`0x0043BAE5`–`0x0043BB64`). The array has room for 64
such records. The output builder uses the three `MusicRGBIndex` bytes to
place the three bytes of the DWORD value into a three-byte output group and
copies the record's count and entries into the output buffer
(`0x0043BB90`–`0x0043BC43`). This establishes the local record layout and
channel permutation, but not the profile/resource schema that populates the
worker's source arrays or the meaning of each record value.

These record fields and the writer argument roles below are static
interpretations of fixed-offset memory accesses, stack setup, and callee use
in the hash-pinned 4.06 image. They are not recovered source declarations,
runtime traces, or validated device-protocol fields. The reported argument
positions and constants describe the observed call sites; names such as
"length" and "mode/flag" summarize how the callee uses those values.

The `VerNeedToUpdate` byte at `0x00612B20` is passed as the final argument at
`0x0043BAC0`; other worker sites pass literals `0x0A` or `0x12`. Do not
interpret that argument as a Boolean RGB selector: `CDevRKKB::SendMusicData`
only distinguishes zero from nonzero, and the nonzero values are not limited
to 1.

**Family dispatch, proven statically.** The direct-profile selector routes
`Fw=0` profiles to `CDevRKKB` and `Fw=1/2` profiles to `CDevG5KB`; see the
[profile-family map](rk-profile-family-protocol-coverage.md). The `+0x40`
worker dispatch therefore resolves differently by dynamic class:

| Dynamic family | Vtable `+0x40` target | Static path reached |
| --- | --- | --- |
| `CDevRKKB` | `FUN_00413340` | The method checks busy field `this+0x238`, prefixes either `[0]` for a zero fourth argument or `[6, 0]` for nonzero, and calls the RKKB 65-byte feature-report writer `FUN_00413220`. The worker's fourth argument may be a mode value such as `0x0A`, `0x12`, or the profile byte described above. |
| `CDevG5KB` | `FUN_00410670` | After its `this+0x238` busy check, the direct-handle branch calls shared writer `FUN_0040F700` with operation `1`, command `8`, the profile report-ID byte at `this+0x2D0`, and caller fields. If no primary handle exists but `this+0x250` contains a child, it forwards all four worker arguments to that child's `+0x40` slot. |
| `CDev3632` child | `FUN_0040E570` | The `CDev3632` `+0x40` method checks `this+0x238` and enters common helper `FUN_0040D7E0`, passing literal `0x88` plus caller-derived fields. The 3632 helper's complete selector/record interpretation is unresolved. |

The 4.06 wireless companion constructor at `0x00415A00`–`0x00415B93`
creates a `0x2C8`-byte child through `FUN_0040D3F0` (which installs vtable
`0x005CA32C`) and stores the child at parent `+0x250`. This is a conditional
nested `CDev3632` route, not the direct `Fw=0/1/2` selector outcome. The
wireless profile/descriptor gates and remaining uncertainties are recorded
in the [profile-family coverage](rk-profile-family-protocol-coverage.md).

**Unresolved — no capture-to-device data edge.** The WASAPI worker computes
24 visualization bands and calls the visualizer/key-group helper, but the
inspected capture path does not call `Music_Theard`, any of the four
`+0x40` sites above, or `CDevRKKB::SendMusicData`. Conversely, the worker's
source arrays and local records have not been tied to the capture ring or the
24-band table. The binary can therefore be shown to contain both a host-side
loopback/visualization path and family-specific device-worker output paths;
the static evidence does not establish that captured system audio supplies
the worker's bytes.

**Proven statically.** The separate `CDevRKKB::SendMusicData` routine is
`FUN_00413340`. It refuses to send when the device object's field at
`this+0x238` is nonzero. Its four stack arguments include a data pointer, an
unused second field, a byte length, and a final mode/flag field. Otherwise:

- For its final argument equal to zero, it prefixes the caller's data with
  byte `0`, then passes `data length + 1` to `FUN_00413220`.
- For a nonzero final argument, it prefixes bytes `[6, 0]`, then passes
  `data length + 2` to `FUN_00413220`.
- The writer `FUN_00413220` frames the bytes into 65-byte HID feature reports
  using report ID `10`, up to 62 payload bytes per report, one-based chunk
  indices, and an inter-report delay. It is an active write path; it was not
  invoked.

The zero/nonzero prefix branch establishes two output forms, but the bytes'
meaning, sample/band encoding, update rate, and relationship to the profile's
`VerNeedToUpdate` byte remain **unresolved**. The worker vtable dispatch and
family targets establish corresponding static G5 and nested 3632 output
routes, although their payload schemas remain incomplete. Do not infer that
the 24 capture bands are copied directly into these packets, or that
`MusicRGBIndex` describes the two-byte RKKB prefix.

This is separate from the settings serializers in the [lighting/color
audit](rk-rgb-lighting-color-payload-audit.md): the G5/3632 command 4 lighting
settings and RGB table/color-group commands have their own packers. No direct
audio worker-to-G5/3632 serializer path was recovered.

## Remaining unknowns

- Which localized controls, if any, start/stop capture, select an endpoint,
  change auto-gain/gain, choose one of ten effects, or set monochrome/RGB.
- The exact path, schema, and field semantics of the 36-byte `audio.dct` file;
  whether it is generated only after the first runtime save.
- The precise path from `audiobar.txt` layer/key maps and profile music fields
  to the 24 computed bands.
- The complete DSP transforms, sample-format edge cases, normalization,
  band-to-key mapping, and timing.
- The origin of the worker's source arrays and whether they ever consume the
  WASAPI ring, 24-band table, `audio.dct`, or `ET/*/audiobar.txt` data.
- The exact meaning of the worker's mode values and each vtable call argument;
  in particular, whether the `VerNeedToUpdate` profile byte is a selector or
  carries another purpose at the mode-3 call.
- The G5 command-8 and CDev3632 `0x88` payload schemas, per-model availability,
  and runtime acceptance; only the static worker-to-vtable dispatch is
  established.

These findings document static code and package data only. They do not show a
successful runtime capture, device connection, or audio-reactive keyboard
effect.

## Related reports

- [Resource and localization audit](rk-resource-localization-audit.md)
- [Native API inventory](rk-native-api-imports.md)
- [System API crosswalk](rk-system-api-crosswalk.md)
- [UI control-command crosswalk](rk-ui-control-command-crosswalk.md)
- [Lighting, RGB, and color payload audit](rk-rgb-lighting-color-payload-audit.md)
- [Settings serializer audit](rk-setting-serializer-audit.md)
