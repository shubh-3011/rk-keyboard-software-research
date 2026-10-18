# V4.6 `CDevG5KB` vtable and settings-path audit

## Evidence boundary

This report traces the G5-derived class installed by the V4.6 profile selector,
the semaphore worker's `ApplySetting` dispatch, and the feature routes visible
in that method. The only executable input is the 2,418,176-byte x86 PE
`.research/rk4_6_official_extract_20261015/app/DeviceDriver.exe`, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
Addresses are virtual addresses in that exact file.

The binary was read and disassembled statically. RK software was not launched,
no HID/device interface was opened, and no report, command or configuration
was sent. “Proven” below means the instruction/data flow is present in this
PE; it does not mean that a connected model accepts the request or that the
path was executed on a PC.

The profile selector constructor `0x0040F490` installs vtable address point
`0x005D3D0C` at `0x0040F4C3`; its RTTI type descriptor names `CDevG5KB`, derived
from `CHidDev` (see the [RTTI route audit](rk-v4.6-profile-family-rtti-audit.md)).
The 29 four-byte executable pointers occupy `0x005D3D0C` through
`0x005D3D7F`. At `0x005D3D80`, the next bytes begin the UTF-16 diagnostic
`CDevRKKB::WriteDevice`, providing an independently checked table boundary.
The row-by-row pointer and method-evidence ledger is
[`rk-v4.6-cdevg5-vtable-map.csv`](rk-v4.6-cdevg5-vtable-map.csv); the
hash-pinned verifier is
[`audit_rk46_cdevg5_vtable.py`](../scripts/audit_rk46_cdevg5_vtable.py).

## Apply worker to G5 virtual method

The worker at `0x00401290` logs `Start Thread` (`0x005CFC0C`) and waits on two
objects through `WaitForMultipleObjects` at `0x004012CC`. It retrieves the
active device object from global `0x00647320`, checks connection state, logs
the selected device and apply arguments, then calls the object's vtable entry
at offset `+0x44` (`0x004013D5`–`0x004013E7`). That slot resolves to
`CDevG5KB::ApplySetting`, `0x004127B0`, in the verified table. The routine's
embedded diagnostic at `0x005D33A0` records `hWnd`, `nFlag`, firmware value,
data, delegate, and Bluetooth state. The V4.6 **Apply** and **Restore** main-
window controls are now statically connected to a conditional queue signal
with value `1`; see the [UI-to-worker trace](rk-v4.6-ui-setting-signal-audit.md).
The runtime active class, request reachability, and arguments supplied by a
connected model remain unvalidated.

## Stored-path / handle availability slot

The G5 vtable's `+0x20` entry targets `0x0040FED0`. This method first checks
the primary handle at object `+0x04`; when it is null and a child object is
present at `+0x254`, it delegates to that child's vtable `+0x20`. Otherwise,
it checks whether the UTF-16 field beginning at `+0x22` is empty. For a
nonempty field, it passes that field address to `CreateFileW` with access mask
`0x12019F`, share mode `3`, `OPEN_EXISTING`, and `FILE_FLAG_OVERLAPPED`, then
closes a successful temporary handle and returns success/failure. For an empty
field, it calls `HidD_GetAttributes` with the handle stored at object `+0x04`
and returns a Boolean result. The matching RKKB `+0x20` method
(`0x0040DEB0`) has the same stored-field open/close and HID-attribute
fallback shape, without the G5 child-object delegation.

This supports an inferred description as a stored-path/handle availability
probe and corrects the earlier “synchronization / child-worker status” label.
It does not identify the string at `+0x22`, prove that it is a keyboard
device path, recover a visible caller, or establish runtime execution. The
analysis did not call `CreateFileW` or `HidD_GetAttributes`, open a device, or
send a report. The slot evidence remains in the
[vtable map](rk-v4.6-cdevg5-vtable-map.csv).

## Apply flags and settings routes

The `nFlag` argument controls these paths inside `0x004127B0`:

| Flag/path | Confirmed static route | Status and open meaning |
| --- | --- | --- |
| `0x01` | Calls the `SendWeb:`-labelled key/action builder at `0x00411BA0` (`0x004129C6`), then sends its buffer through `0x00410C90` as operation `1`, command `0x12` (`0x00412939`). It also walks 132 key positions and sends per-layer blocks through `0x00410290`, operation `1`, command `3`, with a layer/option value. The macro-tag path serializes records through `0x00412060` and calls the generic writer with operation `1`, command `5` at `0x00412DAC`. | The branch, loop bounds, helper calls, and command values are proven. The `SendWeb` strings at `0x005D3450` and `0x005D1EB8` are diagnostic labels, not proof of a user-facing feature name. Key/action and macro field meanings, layer UI origin, and firmware interpretation remain unresolved. |
| `0x02` | Reads a 128-byte LED/profile block using virtual `+0x3C` (`0x00412EB7`), checks trailing bytes `5A A5` (`0x00412EE0`–`0x00412EEA`), transforms the buffer via `0x00412110` or `0x00412470`, then calls `0x00410340` to send operation `1`, command `4`, length `0x80`. Error text includes `SetLED failed` at `0x005D1E04`. | Proven as an active read-modify-write path. LED fields, units, profile labels and the initiating control are unresolved. |
| `0x20` | Packs RGB-index data from the object/configuration region around `+0x2154`, with firmware-dependent record construction, then calls `0x00410AE0`. That helper selects G5 operation `1`, command `10`; a nested `CDev3632` branch uses selector `9`. G5 failure text is `SetLedRgbTab error` at `0x005D36D4`. | G5 transport route and separate nested-family branch are proven. RGB channel order, table index meaning, selected-profile guard semantics and model availability are unresolved. |
| `0x04` with a selected-profile guard, or `0x10` | Reads color-group state, maps group/key entries into RGB triples, and writes command `6`, operation `1` through the generic G5 writer. A nested `CDev3632` route calls selector `2` through `0x0040DF10`. Per-group diagnostics begin at `0x005D3720`. | Group iteration, transport branches and packed RGB structure are proven. Group names, channel interpretation, and the meaning of the two flag conditions remain unresolved. |
| `0x10` plus global gate `0x0062B8B1` | Calls the G5 `+0x38` virtual method at `0x00412DF6`; that target `0x00410C00` sends operation `1`, command `0x11`, one zero byte. The diagnostic is `ResetDevice failed` at `0x005D1ED8`. | The gated write is proven; its device effect and whether any UI reset prompt reaches it are unresolved. |

The inspected `ApplySetting` body does not show a direct `0x08` branch. That
observation is scoped to this body and does not establish that no other G5
method or caller can handle a value containing that bit.

The vtable also exposes separate G5 methods for command-`0x0B` screen
parameters (`+0x50`), the command-`0x0C` page/GIF transfer wrapper (`+0x54`),
and five-byte command-`0x0D` GIF parameters (`+0x58`). Their frame conversion,
page transfer, UI path and protocol limits are documented in the
[V4.6 screen/GIF trace](rk-v4.6-screen-gif-ui-transport-audit.md). The G5
table additionally contains power, password and real-data query methods; the
command-`0x11` reset write; command-`0x08` writer; input/macro conversion
helpers; and cancel-event state. Their exact slot, target and evidence are
listed in the CSV. A follow-up traces the `+0x34` password-query method as a
command-`0x82` feature write followed by conditional response-read/copy code.
Correct stack accounting shows that `HidD_GetFeature` uses the same saved
`[this+0x04]` handle as `HidD_SetFeature`; the byte at `+0x2DC` is copied
separately into the report. Runtime response, caller and returned-data meaning
remain unresolved. See the
[password-query read-path audit](rk-v4.6-cdevg5-password-query-audit.md).

The `+0x70` method at `0x00411030` is a busy-guarded wrapper around
`0x00410890`. The helper builds command-`0x88` feature reports of `0x208`
bytes and, when its conditional path succeeds, copies response bytes beginning
at offset 8 into the caller buffer in chunks capped at `0x200`, bounded by
the caller's requested length. `HidD_SetFeature` at `0x00410992` and
`HidD_GetFeature` at `0x004109F1` use the same saved `[this+0x04]` handle. The
byte at `[this+0x2DC]` is stored separately and copied into the report. The
response-copy code is conditional on API success and matching command. A scan
of 77 decoded `call *+0x70` sites found no caller attributable to this G5
slot. The command's meaning, caller-supplied length, firmware address/range,
full-image behavior and persistence remain unresolved; the method has no file
sink, and no device response was observed. Details and the incompatible
callback candidate are in the
[V4.6 firmware readback audit](rk-firmware-readback-audit.md) and the
[focused caller-attribution audit](rk-v4.6-cdevg5-realdata-caller-audit.md).

## Limits and remaining work

- The method table and apply branches are specific to this V4.6 PE. The 4.06
  slot numbers are different and were not copied as V4.6 evidence.
- Profile-to-`CDevG5KB` routing covers the 131 direct profile rows in the
  package snapshot. It does not establish support for every RK model,
  receiver, firmware, hardware revision, or wireless state.
- The two `tc_apply`/`tc_restore` control paths into the queue are mapped, but
  the active runtime receiver and profile-field semantics remain unresolved.
  Static calls into a serializer do not demonstrate that every branch is
  reachable from the visible UI or accepted by a keyboard.
- Packet schemas, many values and selectors, all error/retry responses,
  model-specific feature availability, and physical acceptance remain
  incomplete. Several reads and writes are active operations and were only
  inspected, never invoked.
- This closes a class-vtable and settings-route gap; it is not a claim that
  the full RK application, every system call, or all G5 feature semantics have
  been exhaustively reverse engineered.
