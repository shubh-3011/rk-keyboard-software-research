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
stable keyboard-model identifier.

## What this does and does not establish

**Proven comparison:** the currently exposed `258A:0150` interface has the
same four HID capability values checked by the 4.6 `Fw=3` predicate. This is a
useful family-signature match between a live descriptor and a static software
branch. The package catalog's six `258A:0150` wireless-ID profiles further
show that the receiver VID/PID is shared among A70 and S104 entries.

**Not proven:** that the 4.6 selector chose `CDev3632` for this device, that
the installed 4.06 binary uses the same branch, or that the connected
keyboard is an M20. The 4.6 catalog's sole direct `Fw=3` profile is M20
`258A:0208`, while this USB interface reports PID `0150`. The selector also
checks profile/device identity fields, and a separate wireless/receiver
selection path is not closed by this descriptor match. The 4.6 registry has
multiple profiles associated with receiver identifiers, so `258A:0150` alone
does not identify the keyboard behind the interface. The BLE nodes labeled
`RK-S98RGB` remain in separate PnP containers from this USB device.

This result does not establish firmware data, a readback command, or a way to
copy firmware. For the current firmware-readback evidence and limits, see the
[readback audit](rk-firmware-readback-audit.md).
