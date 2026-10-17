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
| 3632 | `FUN_0040D7E0` or `FUN_0040DD60` through the child object at `+0x94` | 20-byte frame with up to 14 data bytes; the primary helper has response/retry handling. Macro helper `FUN_0040DD60` chunks up to 512 bytes, calls command `3` through the 14-byte transport, and waits 100 ms between successful outer chunks; option `6` and trailing argument `0x0F` semantics remain unresolved. |
| RKKB | `FUN_00413220` emits report ID 10 with up to 62 payload bytes; direct callers include music and the separate `FUN_00413BF0` apply routine | Static evidence also shows key/layer, macro-derived, LED-data, per-key-color, matrix, and conditional Fn write paths. Their exact UI triggers, model availability, and payload meanings remain incomplete. |

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
| Bit `0x01` | Branch at `0x00411CF0`–`0x00411FCE`. Tag-`0x0B` key data is read from configuration `+0x3E21` and sent via `FUN_00410360` as command `0x12`. Key mappings pass through `FUN_00411260`, which maps four 132-position layers, then `FUN_0040F9C0`. Dirty layers select commands G5 `3` or 3632 `1`. Macro-tag records (tag byte `+3 == 5`) associate matrix entries with macro buffer IDs; the concatenated table/blob buffer uses G5 command `5` or the 3632 `FUN_0040DD60` command-`3` path. | High for the static branch, sizes, and command numbers. Translation semantics, UI flag source, macro event encoding, and 3632 macro option/response details remain incomplete. |
| Bit `0x02` | Reads 128 bytes of LED configuration using five response/signature attempts in `FUN_00411B90`. `FUN_0040FAD0` uses G5 command `0x84` (`HidD_SetFeature` followed by `HidD_GetFeature`, with a trailing `5A A5` check) or 3632 command `0x44`. Packer `FUN_00411700` or `FUN_00411900` emits command `4` on both transports. | High for source offsets and control flow. Most payload bytes, UI action mapping, and settings units remain unresolved; this is an active read-modify-write path when executed. |
| Bit `0x20` and selected-profile guard | Packs rows from configuration `+0x2154` through `FUN_004101B0`; G5 command `10`, 3632 command `9`. | High for transport; channel order, RGB index meaning, and guard semantics remain unresolved. |
| Bit `0x04` with selected-profile guard, or bit `0x10` | Dirty groups at configuration `+0x25C4` are remapped from DWORD colors through table `0x6169D1` and serialized as three bytes per key slot. G5 command `6`; 3632 command `2`; group index is the option. The `0x10` branch also gates a reset-like virtual call at vtable offset `+0x38`, using global `0x00612B8C`. | High for the conditional paths and payload shape. Exact color-group labels, channel ordering, the meaning of `0x10`, and reset caller/effect remain unresolved. |

The tag-`0x0B` text path is named `SendWeb` by its log string; that name does
not establish its user-facing purpose or payload grammar. The
[keymap/macro section](reverse-engineering.md#keymap-and-macro-mapping-details)
and [lighting section](reverse-engineering.md#lighting-payload-details)
document the recovered offsets and their remaining semantic limits.

## Separate RKKB apply and write paths

`FUN_00413BF0` is a separate RKKB apply routine; it is not a branch in the
shared `FUN_00411B90` G5/3632 orchestrator. Its flag argument is tested for
bits `0x02`, `0x04`, and `0x01` at `0x00413C81`, `0x00413DC4`, and
`0x00413F50`. These are static call paths; no UI event, profile, or device was
used to trigger them.

| Flag and path | Inner payload and evidence | Confidence and remaining gap |
| --- | --- | --- |
| `0x02`, LED data | Builds inner prefix `02 29`, copies configuration values, and sends `0x3C` bytes through `FUN_00413220` at `0x00413D83`. Nearby log text at `0x005CBC0C` says “Set led data”. | Strong evidence for a labeled LED-data write. Field meanings and units are unknown. |
| `0x04`, per-key color | Builds prefix `03 7E`; walks 16-byte records in the table at `0x006169D1`, packing three output bytes per selected record. Length is `0x81` or `0x17D` according to global `0x006117C4`; writer call at `0x00413F03`. Log text at `0x005CBC54` says “Set key color[index]”. | Strong evidence for a per-key-color write. The selector, RGB ordering, and global's source remain unknown. |
| `0x01`, key/layer translation | Four `0x840` input regions are translated by `FUN_00413B20` into four `0x210` internal layers. The translator processes 132 records of 16 bytes, calls `FUN_00413410`, maps through table `0x006169D0`, and rejects indices greater than `0x83`. | Strong for loop bounds and table use. Record fields and their connection to `KB.ini` tuples are not fully established. |
| Macro-tag handling under `0x01` | Records with byte `+3 == 5` enter a branch that calls `FUN_00413870` at `0x004140A3`. This helper compacts a `WORD`-counted, 8-byte-stride event structure into three-byte rows in a `0x1FF` temporary buffer; it has no HID call of its own. | The helper is a serializer in the RKKB apply pipeline. Event subfield meaning and the exact translated bytes are unresolved. |
| Key write under `0x01` | `FUN_004143F0` prepends `04 00`, copies `0x780` bytes, then calls the writer with length `0x782` at `0x00414440`. Error text at `0x005CBDB0` says “SendKey Failed”. | Strong for prefix, copy size, and helper path. Four translated layers total `0x840` bytes, so the `0x780` transmitted region is not a transparent copy of all 132 positions; the selection/packing step remains open. |
| Matrix write under `0x01` | Constructs prefix `01 F8` and sends `0x1F9` bytes at `0x00414268`; error text at `0x005CBDA8` begins “Matrix:”. | Command and length are proven statically; `F8` fields, data schema, and the relation to the key write remain unresolved. |
| Conditional Fn write under `0x01` | When global `0x006117E4` is nonzero, constructs prefix `10 F8` and sends `0x1F9` bytes at `0x00414326`; error text at `0x005CBDE4` says “Send Fn Failed”. | The write and gate are proven. The gate's source and Fn payload schema remain unknown. |

The writer `FUN_00413220` itself builds 65-byte (`0x41`) feature reports.
It uses report ID `0x0A`, a packet count rounded up by 62, one-based packet
indices, and at most 62 bytes per report beginning at byte 3. It calls
`HidD_SetFeature` and waits 8 ms after successful chunks. This helper has no
ACK/readback or checksum branch. These are one-way write operations and were
not invoked.

All six direct references to `FUN_00413220` in the analyzed image are at
`0x004133CA`, `0x00413D83`, `0x00413F03`, `0x00414268`, `0x00414326`, and
`0x00414440`. `FUN_00413340` is the separate music caller and emits its
own caller-supplied prefix (`00` or `06 00` depending on a flag). This closes
the earlier evidence gap that had attributed the writer only to music; it does
not establish that the UI exposes every branch or that all RKKB profiles use
these paths.

## Screen and reset paths are separate

The screen writers are separate from the shared settings orchestrator
`FUN_00411B90`, but they are exposed in the G5 class dispatch table. The
static method-pointer block near `0x005CBA50` contains screen-parameter,
page-transfer-wrapper, and GIF-parameter methods at successive slots
(`0x005CBA74`, `0x005CBA78`, and `0x005CBA7C`, respectively). The page
transfer wrapper at `FUN_00412F20` has a direct call to `FUN_00412B10` at
`0x00412F4A`; a direct caller for the wrapper and UI-to-virtual-slot bridge
were not recovered. The existence of virtual entries does not establish which
UI action invokes them at runtime.

- `FUN_00410230` takes a data pointer and length. Its G5 path sends command
  `0x0B` through the 520-byte transport, using report ID from object offset
  `+0x2D0`; if no primary handle exists, it invokes nested-object vtable `+0x48`.
  The payload is passed through unchanged, so its screen-parameter schema is
  not known.
- `FUN_00412890` writes command `0x0D` with option 0 and a five-byte payload.
  Byte 0 combines caller flags in bits 6–7 with the low six bits of GIF index;
  bytes 1–2 hold frame count little-endian; bytes 3–4 hold delay little-endian.
  A secondary handle repeats the command using report ID 9. The response path
  tests an internal response byte for nonzero. Delay units, allowed values,
  flag meanings, and response semantics remain unknown.
- `FUN_00412F20` selects a secondary screen handle at `this+8` when present,
  otherwise the primary handle at `this+4`, then delegates frame data and
  callbacks to `FUN_00412B10`. `FUN_00412B10` transfers up to 512 bytes per
  520-byte report using command `0x0C`. Its frame has report ID at byte 0,
  command at byte 1, zero at byte 2, caller frame value at byte 3, rolling
  packet counter at byte 4, one-byte checksum at byte 5, little-endian payload
  length at bytes 6–7, and payload at bytes 8–519.
- The optional checksum is enabled by global flag `0x611844`. It is a single
  byte equal to `0xFF - (sum(payload) mod 256)`, computed through alternating
  even/odd accumulators; it is not a polynomial CRC and does not emit two
  checksum bytes. A response is accepted only when internal byte 3 is
  nonzero, byte 4 matches the packet counter, and, in checksum mode, byte 5
  matches the outgoing checksum. Feature-write attempts are bounded to four
  per packet with 100 ms delays; invalid page ACKs rewind the data offset and
  counter, while the outer invalid-ACK retry has no visible retry bound.
  Cancellation uses device vtable `+0x5C`; progress reports frame, total
  length, and bytes sent. These are transfer mechanics, not a safe backup
  protocol.
- `FUN_004102D0` is the reset helper. Its G5 path uses command `0x11`, option
  `1`, and a one-byte payload; the nested-object path calls vtable `+0x38`.

Command presence is not evidence that a command is safe to replay. These are
write paths; none was executed. The `0x11` reset command above is distinct
from the screen-parameter command `0x0B`.

## Remaining work

- Recover the UI event and virtual caller paths that set each apply flag,
  including which labels/actions reach the serializer.
- Resolve every RKKB matrix/key/Fn/LED field and trace the `0x780` key payload
  selection/packing from the four translated 132-position layers.
- Recover the UI event and virtual caller paths for `FUN_00413BF0`, including
  model/profile gates and the source of global `0x006117E4`.
- Resolve the G5/3632 model-vtable macro serializer and the exact RKKB macro
  event fields.
- Resolve the meaning of `FUN_0040DD60` option `6` and trailing `0x0F`, then
  connect its 512-byte macro chunks to their source buffer and profile state.
- Map all 128 LED bytes and RGB/group color semantics to profile fields and UI
  controls.
- Recover the runtime caller of the G5 screen vtable slots and the UI-to-device
  bridge; the static worker near `0x00466450` converts frames and invokes
  virtual slots `+0x4C`/`+0x50`, but the concrete target relationship remains
  unresolved.
- Determine whether other software versions implement screen/GIF/page paths
  for RKKB or 3632; the inspected 4.06 model map has 15 screen profiles, all
  statically routed to G5, which is not universal product evidence.
- Compare these paths against separately hashed RK package versions and
  model-specific device IDs. This report does not claim universal model
  coverage or complete runtime behavior.
