# Live RK HID descriptor cross-check against the 4.6 selector

## Scope and evidence boundary

This note compares one live, read-only HID descriptor observation from this
PC with the static profile selector in the extracted 4.6-labeled
`DeviceDriver.exe`. It does not identify a physical keyboard revision or
prove that RK software selected a model. No input report was read, no output
report or feature request was sent, and no RK application or updater was run
for this cross-check.

The live observation was collected on 2026-10-19 with the repository's
[read-only HID metadata probe](../scripts/probe_rk_hid_metadata.ps1). The
present USB composite device reports VID/PID `258A:0150`, revision `0206`,
and exposes ten enumerated HID collections. Seven accepted a `GENERIC_READ`
handle; three returned Win32 access denied. The accessible collection
`MI_01/COL_01` reports:

| Field | Live value |
| --- | ---: |
| Usage page | `0xFF02` |
| Usage | `0x0002` |
| Input report byte length | `20` (`0x14`) |
| Output report byte length | `20` (`0x14`) |

The 4.6 static target is the extracted `DeviceDriver.exe`, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`, image
base `0x00400000`. Its selector and profile rows are analyzed in the
[4.6 selector audit](rk-v4.6-profile-selector-audit.md); its selected
`CDev3632` vtable is analyzed in the
[Fw=3 vtable audit](rk-v4.6-fw3-cdev3632-vtable-audit.md).

## Field-by-field match

The 4.6 per-interface helper calls `HidP_GetCaps` at `0x004174EB` with a
`HIDP_CAPS` buffer. After selecting a metadata row, it copies the relevant
words into that row at `0x00417542`–`0x0041758C`. Stack offsets resolve the
stored values as follows:

Microsoft documents that `HidP_GetCaps` returns a `HIDP_CAPS` structure and
defines its member order, including the input and output report lengths
([structure](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/hidpi/ns-hidpi-_hidp_caps),
[function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/hidpi/nf-hidpi-hidp_getcaps)).

| Stored row field | `HIDP_CAPS` member | Selector use |
| --- | --- | --- |
| `row+0x20C` | `InputReportByteLength` | Compared as `0x14` at `0x00416395` |
| `row+0x210` | `OutputReportByteLength` | Compared as `0x14` at `0x0041639A` |
| `row+0x218` | `UsagePage` | Compared as `0xFF02` at `0x00416382` |
| `row+0x21C` | `Usage` | Compared as `2` at `0x0041638A` |

The selector iterates these capability rows at stride `0x22C`; its base
`0x0063C048` is the first row's `UsagePage` field. In the `Fw==3` branch, the
selector checks usage page `0xFF02`, usage `2`, input length `0x14`, and output
length `0x14` (`0x0041637D`–`0x0041639D`). The live `MI_01/COL_01` values
therefore satisfy the **descriptor portion** of that branch's test.

The extracted 4.6 catalog also reuses wireless VID/PID `258A:0150` in six
profile rows: `020F` RK A70, `025A` RK S104, `02D1` RK S104, `02DA` RK S104
FR, `02DB` RK S104 ES, and `02F6` RK S104. All six have `Fw=1` in
`models-4.6.json`, which enters the selector's general nonzero branch. These
are profile-declared receiver candidates; the shared receiver ID does not
prove that the attached keyboard is any one of them. In the installed 4.06
catalog, the only profile row with wireless ID `258A:0150` is `020F` RK A70.
The version difference is further reason not to treat the receiver ID as a
stable keyboard-model identifier. None of the eight S98-labeled rows in the
4.06 catalog or twelve S98-labeled rows in the 4.6 catalog declares a
`VID_Wireless`/`PID_Wireless` pair. That is a limit of these package profile
records; it does not establish that S98 hardware lacks a wireless receiver.

## Installed 4.06 selector and receiver cross-check

The installed 4.06 selector at `0x004155C0` first compares the candidate
profile VID/PID with enumerated HID attributes. Its descriptor alternatives
then use `HIDP_CAPS` fields. For zero `Fw`, one vendor alternative is page
`0xFF00`, usage `1`, and feature-report length `0x41`; the consumer alternative
is page `0x000C`, usage `1`, input-report length `3`, with PID `0x49` excluded.
For nonzero `Fw`, the vendor alternative is page `0xFF00`/usage `1` or page
`0xFF02`/usage `1` or `2`, with feature-report length `0x208`; the consumer
alternative is page `0x000C`, usage `1`, input-report length `3`. The live
`MI_01/COL_03` tuple is exactly `000C:0001` with a three-byte input report, so
it satisfies the consumer descriptor alternative for either profile family.
This is still only a capability match; it does not override the VID/PID
profile comparison.

Neither `models.json` (installed 4.06) nor `models-4.6.json` contains a direct
profile code `0150`. In 4.06, however, `FUN_004474D0` classifies `258A:0150`
as a special wireless/receiver ID, and profile `020F` (RK A70) declares that
same pair as `PID_Wireless`. The special path skips the ordinary direct
profile-ID loop and gates a later wireless scan. Its downstream six-byte
comparison is not tied to loaded `Psd` data, so this identifies a receiver
candidate route in the software, not the keyboard attached to the receiver.

## What this does and does not establish

**Proven comparison:** the currently exposed `258A:0150` interface has the
same four HID capability values checked by the 4.6 `Fw=3` predicate. This is a
useful family-signature match between a live descriptor and a static software
branch. The package catalog's six `258A:0150` wireless-ID profiles further
show that the receiver VID/PID is shared among A70 and S104 entries. The
installed 4.06 build also has a special wireless classification for this pair,
but its later six-byte profile match remains unresolved.

**Not proven:** that the 4.6 selector chose `CDev3632` for this device, that
the installed 4.06 binary uses the same branch, or that the connected
keyboard is an M20. The 4.6 catalog's sole direct `Fw=3` profile is M20
`258A:0208`, while this USB interface reports PID `0150`. The selector also
checks profile/device identity fields, and a separate wireless/receiver
selection path is not closed by this descriptor match. The installed 4.06
build's special path and `020F` A70 receiver declaration are only catalog/code
evidence; they do not identify this connected keyboard. The 4.6 registry has
multiple profiles associated with receiver identifiers, so `258A:0150` alone
does not identify the keyboard behind the interface. The BLE nodes labeled
`RK-S98RGB` remain in separate PnP containers from this USB device.

This result does not establish firmware data, a readback command, or a way to
copy firmware. For the current firmware-readback evidence and limits, see the
[readback audit](rk-firmware-readback-audit.md).

## Expanded live collection and report-descriptor inventory

A later read-only pass on the same date reopened the present `258A:0150`
collections using `GENERIC_READ` and parsed Windows' preparsed HID data with
`HidP_GetCaps`, `HidP_GetButtonCaps`, and `HidP_GetValueCaps`. It did not call
`ReadFile`, `WriteFile`, `HidD_GetFeature`, or `HidD_SetFeature`. Seven of ten
collection paths opened; `MI_00`, `MI_01/COL_05`, and `MI_01/COL_09` returned
Win32 access denied (`5`). The table reports descriptor metadata only; report
payloads and current keyboard settings were not read.

| Collection | Usage page / usage | Input / output / feature bytes | Descriptor report fields |
| --- | --- | ---: | --- |
| `MI_00` | unavailable | unavailable | open denied (`5`) |
| `MI_01/COL_01` | `FF02:0002` | `20 / 20 / 0` | Input and output report ID `13`; each exposes 19 button fields |
| `MI_01/COL_02` | `0001:0080` | `2 / 0 / 0` | Input report ID `01`; button usages `0081–0083` |
| `MI_01/COL_03` | `000C:0001` | `3 / 0 / 0` | Input report ID `02`; consumer usage range `0000–02FF` |
| `MI_01/COL_04` | `FF02:0001` | `4 / 0 / 0` | Input report ID `03`; three 8-bit values at usage `FF02:002F` |
| `MI_01/COL_05` | unavailable | unavailable | open denied (`5`) |
| `MI_01/COL_06` | `FF00:0001` | `0 / 0 / 6` | Feature report ID `05`; descriptor has usage range `0000–0004` |
| `MI_01/COL_07` | `FF00:0001` | `0 / 0 / 1032` | Feature report ID `06`; descriptor has usage range `0001–0002` |
| `MI_01/COL_08` | `FF01:0001` | `0 / 0 / 8` | Feature report ID `0A`; descriptor has usage range `0001–0002` |
| `MI_01/COL_09` | unavailable | unavailable | open denied (`5`) |

The HID product string returned non-printable text under the probe's basic
Unicode rendering, so it is not used as a model label. The manufacturer string
reported `SINOWEALTH`; the device still identifies only as the shared USB
`258A:0150` VID/PID and revision `0206`. These additional descriptor fields
show which report IDs and sizes the USB HID descriptor declares. They do not
show the values currently stored in the keyboard, the commands the RK driver
sends, or which profile the RK application would select. The three feature
layouts are descriptor declarations, not evidence of a complete firmware
readback path.

## Live HID follow-up after updated authorization

On 2026-10-19, the descriptor and metadata probes were run again against the
present USB composite device. Windows reports VID/PID `258A:0150`, revision
`0206`, and generic USB/HID child names. The USB parent and the ten `MI_00` /
`MI_01/COL_nn` interface paths share one PnP container; the three disconnected
BLE roots named `RK-S98RGB` remain in other containers, so the current USB
identity still cannot identify the keyboard model. The manufacturer string
is `SINOWEALTH`; the product string is rendered as `慇業杮䬠` by the existing
probe, and the serial-number query returns Win32 error `87`. Neither string
provides a usable model name.

`probe_rk_hid_capabilities.ps1` again opened seven of ten interface paths with
shared `GENERIC_READ` handles. `MI_00`, `MI_01/COL_05`, and `MI_01/COL_09`
returned access denied (`5`). The parsed report IDs, lengths, and usages
matched the earlier inventory above. The metadata and capability probes did
not call `ReadFile`, `WriteFile`, `HidD_GetFeature`, or `HidD_SetFeature`.

The feature-read probe was then run with `-RepeatCount 1` and again with
`-RepeatCount 3`. Across these two runs, each of the two supported requests
below succeeded four times and returned an identical report on every call:

| Collection | Requested report | Calls | Returned bytes | SHA-256 |
| --- | --- | ---: | --- | --- |
| `MI_01/COL_06` | ID `05`, 6 bytes | 4/4 success | `06 A0 02 86 28 CB` | `0942459c22f269a1c5126070bbede7a6fb01bcdd2bf47f54e11e95346c1b2763` |
| `MI_01/COL_08` | ID `0A`, 8 bytes | 4/4 success | `06 A0 02 86 28 CB 24 67` | `cda6d71acf4f56682512674c8846aa7786ab6d8b81181537f529f0f831182168` |

These calls use `HidD_GetFeature` on descriptor-declared feature IDs and
lengths. The probe contains no `HidD_SetFeature`, output-report, input-report,
or device-control call. No write report was issued in this follow-up. The
repeat results strengthen the observation that the two short responses are
stable under this request, but do not identify their fields or prove they
represent current settings. In both results the first returned byte is `06`,
not the requested report ID; that mismatch and the shared six-byte prefix
remain unresolved. No model identity or firmware readback is established.
