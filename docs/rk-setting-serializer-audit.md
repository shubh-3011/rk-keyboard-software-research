# RK settings serializer and command paths

This report traces the installed `DeviceDriver.exe` 4.06 settings orchestrator
from dirty flags to serializer and transport wrappers. It is static analysis
of the PE with SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
The vendor binary is not included in this repository. Addresses are specific
to that hash. No RK application, updater, keyboard HID handle, command, or
report was run.

## Entry and family dispatch

`FUN_00411B90` at `0x00411B90` is the shared apply-settings orchestrator.
The 3632 wrapper `FUN_0040E690` at `0x0040E690` checks a busy field at
object offset `+0x260`, sets it, waits 200 ms, and calls the orchestrator at
`0x0040E781`. The operation reads flags, configuration, selected-profile
state, and the active device object before selecting a transport.

| Transport class | Static writer path | Framing and limit |
| --- | --- | --- |
| G5 | `FUN_0040F700`; report ID from device object `+0x2D0` | 520-byte feature report; up to 512 payload bytes per chunk. |
| 3632 | `FUN_0040D7E0` or `FUN_0040DD60` through the child object at `+0x94` | 20-byte frame with up to 14 data bytes; the primary helper has response/retry handling. The macro helper's internal framing was not independently recovered. |
| RKKB | Separate `FUN_00413220` path, report ID 10, up to 62 payload bytes | Proven from the SendMusicData caller only. This does not establish RKKB keymap, macro, lighting, or settings support. |

The device-family classification and exact profile selection are described in
the [main reverse-engineering report](reverse-engineering.md) and
[profile-to-driver-family map](rk-profile-driver-family-map.csv). A similar
model name alone is not enough to assign a physical revision to one of these
classes.

## Apply flags and serialized features

The following branches were traced inside `FUN_00411B90`. Addresses in this
table refer to the hashed x86 PE and are virtual addresses.

| Apply condition | Data flow and command path | Confidence and unresolved points |
| --- | --- | --- |
| Bit `0x01` | Branch at `0x00411CF0`–`0x00411FCE`. Tag-`0x0B` key data is read from configuration `+0x3E21` and sent via `FUN_00410360` as command `0x12`. Key mappings pass through `FUN_00411260`, which maps four 132-position layers, then `FUN_0040F9C0`. Dirty layers select commands G5 `3` or 3632 `1`. Macro-tag records (tag byte `+3 == 5`) associate matrix entries with macro buffer IDs; the concatenated table/blob buffer uses G5 command `5` or the 3632 `FUN_0040DD60` command-`3` path. | High for the static branch, sizes, and command numbers. Translation semantics, UI flag source, macro event encoding, and 3632 macro framing/ack details remain incomplete. |
| Bit `0x02` | Reads 128 bytes of LED configuration using five response/signature attempts in `FUN_00411B90`. `FUN_0040FAD0` uses G5 command `0x84` (`HidD_SetFeature` followed by `HidD_GetFeature`, with a trailing `5A A5` check) or 3632 command `0x44`. Packer `FUN_00411700` or `FUN_00411900` emits command `4` on both transports. | High for source offsets and control flow. Most payload bytes, UI action mapping, and settings units remain unresolved; this is an active read-modify-write path when executed. |
| Bit `0x20` and selected-profile guard | Packs rows from configuration `+0x2154` through `FUN_004101B0`; G5 command `10`, 3632 command `9`. | High for transport; channel order, RGB index meaning, and guard semantics remain unresolved. |
| Bit `0x04` with selected-profile guard, or bit `0x10` | Dirty groups at configuration `+0x25C4` are remapped from DWORD colors through table `0x6169D1` and serialized as three bytes per key slot. G5 command `6`; 3632 command `2`; group index is the option. The `0x10` branch also gates a reset-like virtual call at vtable offset `+0x38`, using global `0x00612B8C`. | High for the conditional paths and payload shape. Exact color-group labels, channel ordering, the meaning of `0x10`, and reset caller/effect remain unresolved. |

The tag-`0x0B` text path is named `SendWeb` by its log string; that name does
not establish its user-facing purpose or payload grammar. The
[keymap/macro section](reverse-engineering.md#keymap-and-macro-mapping-details)
and [lighting section](reverse-engineering.md#lighting-payload-details)
document the recovered offsets and their remaining semantic limits.

## Screen and reset paths are separate

The screen writers are present in the binary, but the inspected
`FUN_00411B90` body does not call the screen-parameter, GIF-parameter, or
page/frame writer. Their external UI or virtual-dispatch caller chain remains
unresolved.

- `FUN_00410230` writes screen parameters: G5 command `0x0B`; when a nested
  object is present, it invokes vtable offset `+0x48` instead.
- `FUN_00412890` writes GIF parameters with command `0x0D`, option `5`, and a
  five-byte payload containing GIF index, frame count, and delay fields.
- `FUN_00412B10` transfers page/frame data with command `0x0C`, up to 512
  payload bytes per 520-byte G5 report, and optional checksum, ACK, retry,
  cancellation, and progress handling.
- `FUN_004102D0` is the reset helper. Its G5 path uses command `0x11`, option
  `1`, and a one-byte payload; the nested-object path calls vtable `+0x38`.

Command presence is not evidence that a command is safe to replay. These are
write paths; none was executed. The `0x11` reset command above is distinct
from the screen-parameter command `0x0B`.

## Remaining work

- Recover the UI event and virtual caller paths that set each apply flag,
  including which labels/actions reach the serializer.
- Resolve every matrix translation field and the model-vtable macro serializer.
- Recover `FUN_0040DD60` framing, response checks, and retries independently.
- Map all 128 LED bytes and RGB/group color semantics to profile fields and UI
  controls.
- Map screen helpers to their callers and supported device families.
- Compare these paths against separately hashed RK package versions and
  model-specific device IDs. This report does not claim universal model
  coverage or complete runtime behavior.
