# RK 4.6 HID record construction and interface eligibility

## Scope and identity

This is a static follow-up to the [4.6 HID enumeration/rescan audit](rk-v4.6-hid-interface-enumeration-rescan-audit.md). It traces the per-interface helper, its global record row, and the two immediate methods that select/open a row by VID/PID and HID capabilities. The subsequent [caller-to-profile bridge audit](rk-v4.6-hid-profile-caller-bridge-audit.md) resolves how the selected profile row supplies those arguments and chooses the driver-family method.

Target: `DeviceDriver.exe`, PE32, image base `0x00400000`, 2,418,176 bytes, SHA-256:

`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`

The digest was rechecked against `.research/rk4_6_official_extract_20261015/app/DeviceDriver.exe`. Addresses below are virtual addresses confirmed from the exact file with GNU `objdump -d -Mintel`. The binary was not executed. No device, HID interface, updater, or bootloader was accessed.

## Enumeration and free-row selection

`0x004497C0` clears `0xADC0` bytes at `0x0063BE30` and calls the enumerator at `0x00417330`. The row stride is `0x22C`; the cleared region therefore holds 80 rows and ends at `0x00646BF0`.

At `0x00417330`, SetupAPI enumerates HID device interfaces and calls the per-interface helper `0x004173F0`. The helper obtains the interface detail buffer and uses its UTF-16 path at `detailBuffer + 4` for `CreateFileW` (`0x004174A1` or `0x004174B2`). The earlier rescan audit documents the SetupAPI arguments and `CreateFileW` flags.

The routine at `0x00417300` is not a VID/PID search. It scans row starts from `0x0063BE30` to (excluding) `0x00646BF0`, stepping by `0x22C`, and tests the first `WORD` of each row against zero. It returns the first row with a zero first word, or zero when all rows are occupied. The first word is also the beginning of the stored UTF-16 interface path. Thus this is an empty-row search keyed by whether the path is empty.

## Per-interface metadata flow and row layout

After opening the path, `0x004173F0` calls `HidD_GetPreparsedData` through thunk `0x00590A1A` (`0x004174CD`), `HidD_GetAttributes` through `0x00590A20` (`0x004174DC`), and `HidP_GetCaps` through `0x00590A26` (`0x004174EB`). It branches on the `HidP_GetCaps` status. It does not branch on the return value from `HidD_GetAttributes` before proceeding to `HidP_GetCaps`.

On the successful-capabilities path, `0x004175C0` reads HIDP_CAPS count fields and queries button/value-cap structures through thunks `0x00590A32` and `0x00590A38` when their counts are nonzero. It returns zero if those queries do not produce a recognized result; otherwise it returns a small code from the returned capability structure. The exact meaning of that code is unresolved here; it is stored as a capability classification field, not identified as a model ID.

If `0x00417300` returns a row, `0x00417534` calls `0x00575B4E` to put the interface path into the row's first field. The formatter's format string at `0x005D0524` is UTF-16 `%s`, and the call supplies a `0x104`-character destination capacity and `0x103`-character limit. The helper then writes the following DWORD fields while the HIDP_CAPS and HIDD_ATTRIBUTES buffers are still in the stack frame:

| Record-row offset | Source buffer field | Meaning |
| --- | --- | --- |
| `+0x208` | return from `0x004175C0` | capability classification code; exact semantics unresolved |
| `+0x20C` | HIDP_CAPS `+0x04` | `InputReportByteLength` |
| `+0x210` | HIDP_CAPS `+0x06` | `OutputReportByteLength` |
| `+0x214` | HIDP_CAPS `+0x08` | `FeatureReportByteLength` |
| `+0x218` | HIDP_CAPS `+0x02` | `UsagePage` |
| `+0x21C` | HIDP_CAPS `+0x00` | `Usage` |
| `+0x220` | HIDD_ATTRIBUTES `+0x04` | `VendorID` |
| `+0x224` | HIDD_ATTRIBUTES `+0x06` | `ProductID` |

These copies are at `0x00417542–0x0041758C`. The offsets are obtained from the local buffer addresses passed to `HidP_GetCaps` and `HidD_GetAttributes`, including the five still-pushed formatter arguments. The attribute `VersionNumber` at HIDD_ATTRIBUTES `+0x08` is not copied by this helper. The attributes buffer is passed at the helper's local `[ESP+0x1C]`; the later two DWORD copies at `0x00417579` and `0x00417584` read its `+4` and `+6` words.

After writing the row, this helper closes the opened handle and frees the interface-detail buffer. The `HidP_GetCaps` failure branch calls `HidD_FreePreparsedData`; no corresponding free is visible on this helper's successful-capabilities branch, so successful preparsed-data lifetime remains unresolved in this trace.

## Immediate VID/PID and capability gates

The immediate consumers are methods at `0x0040DD80` and `0x00413DD0`. Both scan the same 80-row table, starting at `0x0063C054` (row base `+0x224`) and stepping `0x22C`. Their first stack argument points to two expected 16-bit IDs: VID at argument `+0`, PID at argument `+2`. Each ID is zero-extended before comparison with the row's DWORD-stored values.

At `0x0040DD80`, a row is eligible for `CreateFileW` only after all of these comparisons pass:

| Compared value | Required value | Record row offset |
| --- | --- | --- |
| expected VID | equal | `+0x220` |
| expected PID | equal | `+0x224` |
| `UsagePage` | `0xFF02` | `+0x218` |
| `Usage` | `0x0002` | `+0x21C` |
| `InputReportByteLength` | `0x0014` | `+0x20C` |
| `OutputReportByteLength` | `0x0014` | `+0x210` |

The matching row's path at row offset `+0` is passed to `CreateFileW` at `0x0040DDE8–0x0040DDEF`. This is direct evidence that the IDs copied from HIDD_ATTRIBUTES and the selected HIDP_CAPS fields feed a later interface-eligibility gate.

At `0x00413DD0`, the same expected VID/PID comparisons are followed by a different capability filter. One branch opens the row path when `UsagePage` (`+0x218`) is `0xFF00`, `Usage` (`+0x21C`) is `1`, and `FeatureReportByteLength` (`+0x214`) is `0x41`. The alternative branch recognizes `UsagePage == 0x000C`, `Usage == 1`, and `InputReportByteLength == 3`; this branch sets an internal flag at `+0x230` after the scan rather than opening that row at the observed comparison site. The intended product meaning of either branch is not established by these instructions alone.

After a row is opened, these methods copy its path into an object field and perform another `HidD_GetAttributes` query through helper `0x00417720`. That helper returns the 16-bit value at local attributes-buffer offset `+0x08` (the standard `VersionNumber` position) to its caller. This is a later metadata read, not an additional VID/PID comparison in the two gates above.

## Proven, inferred, and unresolved edges

**Proven statically:** the free-row scan uses the first WORD, not VID/PID; the path and metadata are written into a fixed 80-row record table; HIDD_ATTRIBUTES offsets `+4/+6` are stored as VID/PID; the HIDP_CAPS report lengths and Usage/UsagePage are stored at the offsets above; and both immediate consumers compare caller-supplied VID/PID against those row values before applying interface-shape checks.

**Inferred:** `0x004175C0`'s return is a capability-derived classification because it is built from button/value-cap query results and is stored at row `+0x208`. The row is a discovery/transport record, not itself proven to be a selected keyboard profile object.

**Resolved in the linked follow-up:** the surrounding profile routine passes the selected profile row to these methods; its VID/PID fields are the expected pair, and its `Fw` branch selects the driver-family route. This audit by itself does not inspect that caller or profile table. **Still unresolved:** whether any physical keyboard/revision reports the configured IDs and descriptors, passes a gate, or is accepted by the software. No product-name comparison appears in these gate methods.

**Static caveat:** no write to the local HIDD_ATTRIBUTES `Size` field is visible before the calls at `0x004174DC` or `0x00417732`; the helper `0x00417720` likewise passes a stack buffer without a visible `Size` initialization. The stored ID offsets match the standard HIDD_ATTRIBUTES layout, but runtime success and the contents returned by the API were not tested. This does not establish that enumeration fails.

## Reproduction boundary

The checks were static disassembly of the hash-pinned local binary with GNU `objdump -d -Mintel`. No program execution, live capture, HID access, device write, or keyboard test was performed. The result describes this exact 4.6 binary only.
