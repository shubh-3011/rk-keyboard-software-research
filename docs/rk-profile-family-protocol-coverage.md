# RK 4.06 profile-to-family and protocol coverage

This report separates what the installed profile catalog says from what the
4.06 native binary statically routes, and from what is actually known about a
physical keyboard. It covers the installed package snapshot only. The analysis
used the profile data, extracted catalog, and existing static PE findings; it
did not run RK software, open a keyboard interface, transmit a report, or
change a device.

## Coverage summary

| Evidence layer | Count | What it establishes |
| --- | ---: | --- |
| Installed `Dev/*/KB.ini` profiles | 189 | Configuration and associated profile data exist in this package snapshot. |
| Named `DevName` catalog entries | 188 | The software has a registered model row for each listed profile code. |
| Registered rows with a statically selected initial class | 188 | 125 rows route to `CDevRKKB`; 63 route to `CDevG5KB`, subject to the binary's HID descriptor checks. |
| Unregistered profile directory | 1 | `01C7` has configuration/layout data but no named catalog row or row-specific handler assignment in the recovered direct-profile map. |
| Wireless-ID profile rows | 7 | These rows are inputs to a conditional wireless/companion scan; none is proof of a successful `CDev3632` match. |
| Profiles with screen options | 15 | These G5-routed profiles contain display-related configuration; this is not device validation. |

The row-level inventory is in
[`rk-profile-driver-family-map.csv`](rk-profile-driver-family-map.csv), and
the complete extracted profile/configuration model is in
[`models.json`](../models.json). The installer snapshot and binary identity
are summarized in the [main reverse-engineering report](reverse-engineering.md).

## Registered profile routes

The recovered direct-profile selection function checks the profile VID/PID
and HID usage/report-capability criteria, then branches on the profile's
`Fw` value. All 188 named catalog rows are direct PID profiles using the
configured default VID `258A`; each row's PID is its four-character profile
code.

| Profile data | Count | Initial class selected by the inspected branch | Serializer evidence in the binary |
| --- | ---: | --- | --- |
| `Fw` omitted, loaded as zero, or explicitly zero | 125 | `CDevRKKB` | 65-byte feature-report writer `FUN_00413220`; the separate RKKB apply routine contains key/layer, macro-derived, LED, key-color, matrix, and conditional Fn write paths. |
| `Fw=1` | 53 | `CDevG5KB` | 520-byte feature-report access path `FUN_0040F700`; shared settings orchestrator includes keymap, macro, lighting, RGB, and color-group paths. |
| `Fw=2` | 10 | `CDevG5KB` | Same initial class as `Fw=1`; this audit does not establish that every `Fw=2` firmware revision accepts every G5 command or payload. |

For the zero group, 124 rows omit `Fw` and rely on the loader's zero default;
`015B` explicitly sets `Fw=0`. The ten `Fw=2` profiles are `01DE`, `01D0`,
`01CB`, `0215`, `0222`, `020C`, `0210`, `0225`, `01F4`, and `0207`.

This is evidence of the software's **initial static class-selection rule**,
not proof of the connected device's firmware, of a successful runtime match,
or of complete feature support for every profile. The selector also checks
HID descriptor fields. No descriptor or command was captured from a physical
keyboard in this audit. Details of the serializers and descriptor conditions
are in [`rk-setting-serializer-audit.md`](rk-setting-serializer-audit.md) and
the [main report](reverse-engineering.md).

## Profiles with configuration but no recovered registered route

`01C7` is the one extra installed `KB.ini` directory beyond the 188 named
rows. It contains a `KEY` layout and `[OPT]` entries including `Fw=0`,
`KbImgUse=0x0094`, `MacroBufferNum=4`, and LED options. Its code is absent from
the configured `DevName` list, so it does not have a recovered direct PID row
in the family map. Its data is evidence that the package carries a profile;
it is not evidence that ordinary device detection can select it. Hidden or
indirect use of this directory was not ruled out.

Accordingly, this report classifies `01C7` as **configuration-only in the
recovered model map**, rather than calling it a supported or unsupported
physical keyboard.

## Conditional 3632/wireless path

The binary has a separate `CDev3632` implementation and 20-byte transport.
The recovered wireless classifier can bypass the ordinary direct-profile ID
loop for recognized receiver IDs and enter a follow-on scan. A later candidate
constructor requires descriptor checks plus profile-table values including
nonzero `Fw`, wireless VID/PID, and a six-byte comparison. A focused static
trace closes the signature dataflow: `FUN_00447210` calls `FUN_00447110`,
which reads `[OPT] Psd`, parses up to six hexadecimal bytes, and stores them
at row offsets `+0x04..+0x09`. `FUN_00415D20` obtains a six-byte result through
`FUN_0040E210` and passes it to `FUN_00415900` for comparison against eligible
rows. The meaning of `Psd`, actual runtime row selection, physical-device
identity, and completion of the conditional transition remain unresolved.

Seven registered rows have nonempty wireless VID/PID fields, all with
nonzero `Fw`:

| Profile code | Catalog name | Configured wireless ID | Static status |
| --- | --- | --- | --- |
| `020F` | RK A70 Keyboard | `258A:0150` | Candidate for special scan. |
| `0211` | RK M100 Keyboard | `258A:01BB` | Candidate for special scan. |
| `0228` | RK M70 DE Keyboard | `3554:FA09` | Candidate; this pair is also hardcoded in the wireless classifier. |
| `0227` | RK M70 FR Keyboard | `3554:FA09` | Candidate; shares the M70 receiver pair. |
| `020C` | R98Pro Keyboard | `258A:01BB` | Candidate; `Fw=2`; shares the configured receiver pair with other rows. |
| `0210` | R98Pro Keyboard | `258A:01BB` | Candidate; `Fw=2`; shares the configured receiver pair with other rows. |
| `0207` | X87 Keyboard | `258A:0233` | Candidate; this pair is classified through the profile wireless-ID data. |

These are **seven configuration candidates**, not seven validated 3632
devices. They represent four distinct configured receiver pairs; shared pairs
mean a receiver ID alone does not distinguish every profile. The current
catalog has no direct profile code equal to the listed `258A` wireless PIDs,
but that does not resolve the special-scan bypass or identify the board behind
a receiver. See the [device-enumeration audit](rk-device-enumeration-notification-audit.md)
and the [native model-selection findings](reverse-engineering.md).

## Feature-specific profile evidence

### Screen and GIF configuration

Fifteen registered profiles have nonzero `ShowScreen` and `RGBScreen=1`:

`01A2` RK M87; `01D6` RK M87 ISO Return; `01F5` RK M87; `0187` RK N80;
`01B8` RK N99; `0193` RK S85; `01FA` RK S85 ISO Return; `0174` RK S98RGB;
`0224` RK-S98 DE; `022B` RK-S98 ES; `022F` RK-S98; `0230` RK-S98 RU;
`0223` RK-S98 TH; `01BF` RK-S98RGB ISO Return; `01AF` RK-S98RGB-New.

All 15 have `Fw=1` and `DataUnitSize=512`; profile `MaxScreenFrame` values
vary. The N99 row alone has `ShowScreen=2`, which is the value that gates a
separate secondary-screen/PSD branch in the inspected binary. The other 14
use `ShowScreen=1`. The driver has G5 screen-parameter, GIF-parameter, and
page-transfer methods, but static vtable presence and profile options do not
prove that a specific UI control reaches those methods or that a named
physical model implements the same display protocol. The [screen transfer
trace](reverse-engineering.md#screen-and-gif-data-paths) documents the
observed writes and remaining gaps.

### `Psd` and profile collisions

There are 63 nonzero-`Fw` rows with six-byte `Psd` strings and 58 unique
normalized strings. Three values are shared:

| `Psd` bytes | Profiles sharing the value |
| --- | --- |
| `0A 00 00 00 00 06` | `01DE` RK F75 Wired; `01D0` RK F75 three-mode. |
| `03 00 00 00 00 6E` | `014A` RK-R65RGB; `0172` RK-R65RGB Wired Keyboard. |
| `0A 00 00 00 00 22` | `0215` R98Pro DE; `0222` R98Pro FR; `020C` R98Pro; `0225` R98Pro. |

These collisions mean a matching six-byte value would not uniquely identify
every profile. The recovered wireless path statically loads these catalog
`Psd` values into comparison rows and compares them with the result of a
device-helper query. A separate screen-device routine obtains a six-byte
keyboard response through G5 slot `+0x34`, sends a report to a candidate
screen handle, and compares that response with the earlier keyboard bytes;
it is not shown comparing against the profile `Psd` value. Both paths contain
active device transactions, not passive identification. The wireless query
uses a 20-byte `WriteFile` request followed by a 20-byte `ReadFile` response;
the screen path has a separate report transaction. Neither path proves a
runtime match or establishes a universal model-identification query. Neither
transaction was executed.

## Claims this evidence supports

- **Supported claim:** this installed 4.06 package contains 188 registered
  profile rows. Its static direct-profile selector routes those rows to
  `CDevRKKB` or `CDevG5KB` based on `Fw`, conditional on additional HID
  descriptor checks.
- **Supported claim:** the binary contains distinct serializer/transport
  implementations for RKKB and G5, plus a separate 3632 transport and
  conditional wireless/companion matching logic.
- **Supported claim:** 15 registered profile configurations advertise screen
  fields and correspond to G5-routed rows; seven rows have wireless IDs that
  are inputs to a possible conditional 3632 scan.
- **Not established:** that any one physical model/revision was tested or is
  compatible, that every feature shown in a profile is reachable or accepted
  by the corresponding hardware, that the seven wireless candidates construct
  a working 3632 instance, or that 4.06 covers every RK keyboard.
- **Not established:** that other software versions, regional packages,
  QMK/VIA models, Hall Effect variants, or later devices use the same profile
  or protocol map. The dated storefront comparison is only a discovery
  crosswalk; see [`rk-public-model-coverage-gaps.md`](rk-public-model-coverage-gaps.md).

For a machine-readable boundary and open-work checklist, see
[`COVERAGE.md`](../COVERAGE.md). The package's row-level names, options,
mapping records, and assets are catalog evidence; they should not be promoted
to hardware-compatibility claims without separately sourced device and
firmware evidence.
