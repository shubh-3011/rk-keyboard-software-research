# RK 4.06 audio UI and capture-control follow-up

## Scope and evidence

This is an offline static follow-up for the installed RK Keyboard Software
4.06 `DeviceDriver.exe`, SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`
(2,326,528 bytes, x86). The address references below are image virtual
addresses for that exact file. The native call edges were cross-checked against
an `objdump -d -Mintel` disassembly regenerated from the hash-matched file;
resource and localization evidence comes from the installed 4.06 package
inventory and `docs/rk-localization-delta-v4.06-v4.6.csv`.

No RK software or updater was launched. This pass did not open or use a
keyboard interface, capture host audio, or send a command/report. It only adds
static evidence to the existing [audio-reactive path audit](rk-audio-reactive-path-audit.md).

Evidence labels:

- **Proven statically**: present in the hash-pinned package/resource, disassembly,
  or a direct code/data-flow edge.
- **Inferred**: a likely interpretation of a field or UI path without a proven
  source name, control binding, or runtime observation.
- **Unresolved**: no direct static edge ties the relevant items together.

## Localization keys

**Proven statically.** The installed 4.06 English `Text/en/text.xml` has 20
audio labels. The localization delta records each as unchanged in 4.6; the
English source XML hash is
`85b26e0c7cd8317adeb136d37b6877601b0c3e7f6fb072867f937aa46c73de8c`
(23,402 bytes).

| Key(s) | Installed English value | What the resource establishes |
| --- | --- | --- |
| `tc_music1` | Music | Audio-related UI vocabulary; no control ID by itself. |
| `tc_music2` | Gain factor | Gain label. |
| `tc_music3` | The keyboard light changes with the rhythm of the system sound | Feature description. |
| `tc_music4`, `tc_music5` | Monochrome, ColorFull | Two color-mode labels. |
| `tc_music6`, `tc_music7` | ON, OFF | Enable/disable words. |
| `tc_music8` | Effect | Effect selector label. |
| `tc_music9` | Audio device | Endpoint-selection label. |
| `tc_music10` | Auto gain | Automatic-gain label. |
| `tc_music_mode1`–`tc_music_mode10` | Effect1–Effect10 | Ten effect-choice names in the English resource. |

All seven locale XMLs carry the intended audio key set. The Japanese file is
malformed elsewhere and is only parseable after the separately documented
in-memory normalization; the source bytes were not changed. These keys confirm
the vocabulary and page family, but XML does not encode child HWNDs, numeric
control IDs, event-map rows, or device command IDs. The 4.06 main executable's
parsed dialog resources contain no audio feature dialog with corresponding
static child controls. The broader UI evidence says feature controls are
mostly runtime constructed, but this pass did not prove the exact audio widget
creation path or the labels' individual dynamic-control bindings.

## Recovered page-state and mode update path

**Proven statically.** Several direct call edges connect a page-state routine
to the audio processing globals:

1. `FUN_00425440` (`0x00425440`) obtains the active root object from
   `0x0062B388` and checks its current page/index field at `root+0x213C`.
   Only when that field equals `0x1E` does it copy selected state from the
   passed object into process globals:
   - object `+0x300C` -> `0x00609AE8`;
   - object `+0x2B5C` -> `0x00609AEC`;
   - object `+0x2C38` then `+0x74` -> `0x00609AF8`;
   - values obtained by calling `FUN_0044DB20` on object `+0x35C4` and
     `+0x4148` -> `0x00609AF0` and `0x00609AFC`;
   - object `+0x4D74` -> `0x00609AF4`.
   It also updates adjacent object fields and, when global
   `0x006117CC` equals the root's current index, copies a 132-entry table
   from child `+0x2C74` into the active root.
2. The inspected device worker named `Music_Theard` at `0x00439210` reads
   `0x00609AE4` as its loop/cancellation gate and snapshots `0x00609AE8` as
   its mode. Other `0x00609AEx` globals feed branches and output construction
   in the same worker. Thus the object-to-global update is a real static
   state-flow into the music worker; the semantic names of most fields remain
   unknown.
3. Direct callers of `FUN_00425440` include `0x004221A6`, `0x00422601`,
   `0x004226E2`, `0x00422883`, and `0x00424A97`. At `0x004221A6`, for example,
   the caller first invokes `FUN_00422220` and then updates the audio globals.
   Several callers also update local child/list state or signal a window/event.

**Inferred.** Page/index `0x1E` is the audio/music settings page: its update
helper transfers settings into globals consumed by `Music_Theard`, and the
initializer below starts the WASAPI capture worker only for this index. This
is a strong code-path inference, not a recovered mapping from `tc_music1` to a
particular control or an observed UI click.

**Unresolved.** The symbols and offsets do not identify which of the localized
gain, auto-gain, color-mode, endpoint, or effect controls updates each member.
The audio-related caller routines are not tied to a recovered application-owned
MFC `WM_COMMAND` row. No per-control HWND/ID, slider range, checkbox value,
selected endpoint ID, or mode-to-`tc_music_modeN` mapping is proven. Do not
interpret `0x00609AF0` etc. as named settings based only on their use in this
path.

## Page entry/exit controls WASAPI capture lifecycle

**Proven statically.** `FUN_00424B10` has an explicit branch for its first
argument equal to decimal 30 (`0x1E`, `0x00424B5B`–`0x00424B63`). When that
branch runs, it initializes or resets several page-object fields. Near
`0x00424D62`–`0x00424DA0`, it checks object state at `+0x2F34`; if that state
is not `1`, it calls `FUN_0043D7F0` at `0x00424D9B`. It then writes zero to
`0x00609AE4` (`0x00424DA0`), the same global the music worker checks as its
loop/cancellation gate. In the non-`0x1E` branch, it calls `FUN_0043D830` at
`0x00424DB4` and sets `0x00609AE4` to one (`0x00424DB9`–`0x00424DBC`). Direct
callers of `FUN_00424B10` in the inspected image include `0x004224B3` and
`0x004253C4`; their higher-level UI routing is not fully named.

The callee behavior is direct in the same binary:

- `FUN_0043D7F0` sets object `+0x2BC` to one, resets `+0x94`, sets a related
  child flag at `+0x4AC` when present, then calls imported `CreateThread`
  (`0x0043D823`) with entry `FUN_0043D7D0`.
- `FUN_0043D7D0` calls `CoInitialize(0)`, calls `FUN_0043C780` at
  `0x0043D7DC`, then calls `CoUninitialize`.
- `FUN_0043C780` performs the WASAPI loopback capture previously documented
  in the [audio path audit](rk-audio-reactive-path-audit.md).
- `FUN_0043D830` clears object `+0x2BC` and its related child flag, then
  performs local cleanup/signaling. It is the statically observed stop path.

**Inferred.** The `0x1E` page entry/exit routine owns capture activation and
cancellation for the audio page. The object state at `+0x2F34`, the reason
for its `== 1` guard, and the state represented by `0x00609AE4` are not named
by the source artifacts; their exact user-visible meaning is unknown.

## Default audio endpoint change callback

**Proven statically.** The `0x0043C5C0` callback method compares its third
stack argument against a stored endpoint identifier at object `+0x9C`. It only
continues when its first argument is zero. When the identifier differs, it
refreshes the stored value and checks the capture-object state at `+0x2BC`.
If that state is one, it calls stop `FUN_0043D830` at `0x0043C610`, sleeps for
600 ms through the imported `Sleep` at IAT `0x0059E4C4`, and conditionally
calls start `FUN_0043D7F0` at `0x0043C63A` if the state is still not one. The
capture routine registers an endpoint-notification client. This callback
therefore contains a second static stop/restart route associated with a
changed endpoint identifier.

**Inferred.** Its four-argument stack cleanup (`ret 0x10`), first-argument
flow check, and third-argument endpoint ID are consistent with the
`IMMNotificationClient::OnDefaultDeviceChanged` shape; the `0` flow branch
matches the render-flow value used by capture setup. The exact COM callback
symbol is not present in the current native artifacts. Whether the
user-facing `tc_music9` Audio device selector selects the same endpoint is
also unresolved. The capture setup requests the default render/console
endpoint, so there is no direct proof that a UI-selected endpoint overrides
that default.

## Dynamic controls and the device-output worker remain separate questions

The 4.06 localization identifies audio controls, the `0x1E` page-index branch
copies page state into globals, and that page's initializer starts/stops the
WASAPI capture thread. This is a concrete UI-page-to-capture-lifecycle trace.
It does not establish the exact dynamic control constructors, label-to-control
mapping, or which control event calls each state mutator.

**Correction to the earlier audit wording.** The call sites at `0x0043962E`,
`0x004396F1`, and `0x004398EA` are inside the large `Music_Theard` routine
whose entry is `0x00439210`; they are not UI-side callers. Their callees
`FUN_00438810` and `FUN_0043BEE0` are reached from the music worker. They
therefore do not establish a UI-to-visualizer control path. The page-to-worker
state edge supported here is instead `FUN_00425440` copying selected object
fields into globals that `Music_Theard` reads.

It also does not close the separate `Music_Theard` data-flow gap. Static
analysis proves both the WASAPI capture routine and the device-family
`+0x40` output dispatch exist; it still does not prove that the 24 captured
audio bands feed `Music_Theard`'s source arrays or the RKKB/G5/3632 writer
payloads. No keyboard write was executed. See the existing [WASAPI and
device-output audit](rk-audio-reactive-path-audit.md) for the separate buffer,
DSP, profile, and payload limits.

## Exact remaining work

- Recover the runtime-created audio widget list and exact child HWND/control
  IDs for `tc_music1`–`tc_music10` and `tc_music_mode1`–`tc_music_mode10`.
- Resolve `0x00422220`, `0x00424B10`, and callers of `0x00425440` to their
  callback/event ownership and show which state writes correspond to gain,
  auto-gain, color type, endpoint choice, and effect selection.
- Determine whether the endpoint selector changes the `IMMDevice` chosen by
  `FUN_0043C780` or only a persisted/displayed host setting.
- Trace capture ring/band writes into `Music_Theard`'s source arrays, or prove
  that the data paths are disconnected in the complete 4.06 image.

