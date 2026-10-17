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
| `OPT\ShowMusic` | The field occurs in the profile corpus, but this audit did not establish its reader or gating semantics. | Present only in profile `014E`, with value `0`. |

These are profile/configuration observations, not proof that any particular
model exposes or runs the feature. `MusicRGBIndex` is a runtime color-channel
ordering input by name and use in the profile initializer; its channel names
and exact effect on music samples remain unknown. The [lighting/color audit](rk-rgb-lighting-color-payload-audit.md)
documents that field separately from the normal RGB and game-color paths.

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

The joins from layer 1 to 2 and from 2 to 3 are not fully traced.

## Separate keyboard-output path

**Proven statically.** The separate `CDevRKKB::SendMusicData` routine is
`FUN_00413340`. It refuses to send when the device object's field at
`this+0x238` is nonzero. Otherwise:

- For its `bRGB` argument equal to zero, it prefixes the caller's data with
  byte `0`, then passes `data length + 1` to `FUN_00413220`.
- For nonzero `bRGB`, it prefixes bytes `[6, 0]`, then passes `data length + 2`
  to `FUN_00413220`.
- The writer `FUN_00413220` frames the bytes into 65-byte HID feature reports
  using report ID `10`, up to 62 payload bytes per report, one-based chunk
  indices, and an inter-report delay. It is an active write path; it was not
  invoked.

The `bRGB` branch and error log establish two output variants, but the bytes'
meaning, band encoding, rate, color packing, and profile field that selects
the flag remain **unresolved**. The `FUN_00413340` name/log associates this
writer with RKKB. No equivalent G5/3632 audio output writer or complete
capture-to-writer call chain was established in this audit. Do not infer that
the 24 capture bands are copied directly into these packets, or that
`MusicRGBIndex` is this prefix's schema.

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
- The caller/consumer of the captured data and how it reaches
  `FUN_00413340`; actual packet fields and which device models use the method.
- Whether any G5/3632-specific audio output exists outside the inspected
  writer path.

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
