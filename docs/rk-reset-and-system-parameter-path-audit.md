# RK reset and periodic system-parameter path audit

## Scope and evidence

This report joins the static reset/factory-reset evidence with the periodic
system-parameter worker and the internal `0x6401` stop event. It uses the
installed RK Keyboard Software 4.06 snapshot. `DeviceDriver.exe` has SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`, PE32
x86, image base `0x00400000`; addresses below are virtual addresses for this
binary only. `Text/en/text.xml` has SHA-256
`85B26E0C7CD8317ADEB136D37B6877601B0C3E7F6FB072867F937AA46C73DE8C`.

Evidence marked **proven statically** is present in file bytes, the recovered
message map, or the decompiled control flow. **Inferred** labels an
interpretation based on that structure. **Unresolved** marks a missing
control-flow or runtime connection. The application and updater were not run;
no HID/GATT/serial interface was opened, no command or report was sent, and
the keyboard firmware was not accessed.

## Reset helper and vtable slots

`FUN_004102D0` is a reset-device method by its caller-visible vtable position,
its `ResetDevice failed` diagnostic, and its command path. A scan of the
hash-pinned PE's code bytes found no direct relative `CALL` instruction
targeting `0x004102D0`. Its sole literal function-pointer reference is at
`0x005CBA64`, which is slot `+0x38` in the RTTI-backed `CDevG5KB` vtable whose
address point is `0x005CBA2C` (COL `0x005E3C10`; TypeDescriptor `0x006037A8`).
Thus the helper is reached by virtual dispatch, not a recovered direct caller.

| Class / table | Slot `+0x38` target | Static behavior | Status |
| --- | ---: | --- | --- |
| `CDevG5KB`, vtable `0x005CBA2C` | `FUN_004102D0` (`0x004102D0`) | If the primary handle at object `+0x04` is present, calls the G5 writer `FUN_0040F700` with command `0x11`, option `1`, and a one-byte zero-initialized payload; logs `ResetDevice failed` on failure. If the primary handle is absent but a nested object at `+0x250` exists, dispatches that nested object's slot `+0x38`. | **Proven statically.** No invocation was made. |
| `CDev3632`, vtable `0x005CA32C` | `FUN_0040DED0` (`0x0040DED0`) | Calls the 3632 transport helper `FUN_0040DA80` with literal arguments `6, 0, 0`; the error path also uses the `ResetDevice failed` diagnostic. The helper's request-field interpretation is not independently resolved here. | Target and call literals **proven statically**; command/option semantics beyond the method's reset label are **unresolved**. |
| `CDevRKKB`, vtable `0x005CBE0C` | `FUN_0040D040` (`0x0040D040`) | Returns zero without a transport call. | **Proven statically.** |

The shared G5/3632 settings orchestrator `FUN_00411B90` contains a second
reset-like route. At `0x00411C9B`–`0x00411CC3`, it checks operation-flag bit
`0x10` and byte global `0x00612B8C`; when both are nonzero, it logs
`Reset using cmd` and calls the current object's vtable slot `+0x38`. The
profile loader reads `OPT\CmdReset` (default `0`) and stores its low byte in
`0x00612B8C`. On a successful virtual result, or when the earlier shared
status value is nonzero, the code clears the operation mask and continues to
the common completion path. This establishes a configuration-gated virtual
reset branch, not a connection to either localized confirmation dialog.

The class-specific targets above show what the slot would resolve to for
those vtables. The concrete `this` object and runtime model at this branch
were not observed. `CDevRKKB` applies through its separate `FUN_00413BF0`
vtable route; this audit does not establish that the shared orchestrator's
reset branch runs for RKKB.

The same profile loader reads `OPT\ResetItem` into a temporary string and
passes nonempty text to `FUN_0044DC70`. The profile-backed option table has
`CmdReset=1` in 18 installed profiles; no installed `KB.ini` has a
`ResetItem` entry. The `FUN_00411700` and `FUN_00411900` LED packers consume
up to three two-byte entries from the parsed `0x00612B84` data when their
operation flags include `0x10`, writing the configured byte pairs into a
local LED-configuration buffer. This is a profile-dependent LED-data path;
the option name alone does not prove it is the factory-reset data or that it
is the same operation as the virtual reset above. The parser grammar and
intended user-facing meaning remain unresolved.

## Localized prompts and resource edges

The installed English localization contains these distinct keys:

| XML key | English value | Evidence and limitation |
| --- | --- | --- |
| `tc_msg2` | `Reset Keyboard` | String is present in the locale XML. |
| `tc_msg3` | `Resetting the keyboard will clear all keyboard data. Do you want to continue?` | Confirmation wording is present; no originating control or handler was identified. |
| `tc_msg4` | `Reset keyboard data` | String is present in the locale XML. |
| `tc_msg5` | `Restore factory settings` | String is present in the locale XML. |
| `tc_msg6` | `Restoring factory settings will erase all data. Do you want to continue?` | Confirmation wording is present; no originating control or handler was identified. |

The locale-table builder registers `tc_*` lookups, and the resource/localization
audit classifies `tc_msg*` as the status/device/layer/tap/reset prompt family.
That proves the strings are available to the application, but **not** which
window displays them, whether `tc_msg2`/`tc_msg4` are buttons or dialog titles,
what confirmation result is tested, or which reset method follows a positive
response. `DeviceDriver.exe` static dialog resources contain only generic
templates and standard `New` / `OK` / `Cancel` controls; no embedded reset
caption or resource control-to-reset-handler path was recovered. The feature
UI appears to construct controls dynamically, so the absence of a static
resource control does not prove a prompt is never shown.

`CmdReset` is a profile `OPT` option consumed by the static reset-like
orchestrator gate. It must not be conflated with a localized prompt merely
because the names overlap. Likewise, internal app command `0x6401` has no
matching static resource control or localized label and is not evidenced as a
reset button.

## Periodic worker start, timeout work, and stop event

The device setup path at `0x00456F90` checks the loaded
`OPT\SendSysParam` value (`0x00611820`). If positive, it creates an unnamed
event with null security attributes, auto-reset behavior, and an initially
unsignaled state, stores its handle in device-object field `+0x25C`, then
starts thread entry `0x004566C0` with that device node. The thread logs its
start and waits on that handle for the `SendSysParam` timeout. A wait timeout
is interpreted by Win32 in milliseconds; it is not the total cycle duration.

On a timeout, the worker reads `OPT\SysParamMask` (default `7`) and
`OPT\SendOnlyDataChanged`, builds a 14-byte candidate buffer from host-side
state, and dispatches the object's vtable slot `+0x48`. It then returns to
the wait loop. The exact byte meanings and whether the buffer is passed to
the family implementation are unresolved. If the profile selected at
runtime is one of the eight S98 profile entries in the prior worker audit,
its stored timeout/mask values are `1000`/`5` and `SendOnlyDataChanged=1`;
this does not prove which profile was active for the connected keyboard.

The recovered family slot targets are:

| Class | Slot `+0x48` | Timeout operation |
| --- | ---: | --- |
| `CDevRKKB` | `0x0040D060` | Stub returns false; no HID operation is identified in this slot. |
| `CDevG5KB` | `0x00410720` | Reads 128 bytes via `FUN_0040FAD0`/G5 command `0x84`, waits, then writes that buffer via `FUN_0040FA50`/G5 command `4`. |
| `CDev3632` | `0x0040E5D0` | Reads 128 bytes via command `0x44`, then writes that buffer via command `4`. |

The latter two are active read-modify-write routes if executed. These are
static paths only; this audit did not open the keyboard or exercise the
worker.

The close/save path is the message-map entry for `COemDrvDlg` command
`0x6401`: message-map record at `0x005D4C38` routes to handler `0x00446820`.
That handler first sends `WM_CLOSE` (`0x0010`) to top-level windows named
`OemDrvMacroTopWindow` and `OemDrvMsgTopWindow`. Under profile-state guard
`0x00611794`, it writes host-local `pro.dct` and `curid.dct` state. It then
matches the active ID against records at `0x006102A0`, locates the live
device node, and calls `SetEvent` on its nonzero field `+0x25C`. This is the
event created by the periodic worker's setup path. The worker's
`WAIT_OBJECT_0` branch calls `CoUninitialize`, logs `SysParam_Thread exit`,
and returns; therefore the direct event effect is worker shutdown, not a
reset or an Apply command.

The worker's operation may already be in progress when the event is set.
Static analysis does not prove whether an in-flight family call finishes
before the worker observes the event on its next wait. The internal source
of command `0x6401`, its visible UI action, and actual scheduling remain
unresolved.

## Evidence boundaries and related audits

- **Proven statically:** helper/vtable addresses and targets; G5 reset helper
  command arguments; the `CmdReset` loader and gate; the `Reset using cmd`
  branch; the English prompt strings; `0x6401` message-map target; guarded
  `.dct` writes; worker event creation/storage, timeout loop, family slot
  targets, and signaled-stop branch.
- **Inferred:** `CreateEventW(NULL, FALSE, FALSE, NULL)` is an unnamed
  auto-reset event; the vtable slots are family reset/timed-work methods
  based on their target code and class tables.
- **Unresolved:** prompt-to-control-to-confirmation-to-reset dispatch;
  meaning/grammar of `ResetItem`; model and object instance at the shared
  reset virtual call; complete 3632 request argument semantics; worker buffer
  schema; active profile/runtime cadence; and in-flight shutdown ordering.
- **Not established:** any safe reset replay, firmware readback, or hardware
  state change.

For supporting detail, see the [general settings and persistence audit](rk-general-settings-ui-persistence-audit.md), [settings Apply worker audit](rk-settings-apply-worker-audit.md), [UI event and system-parameter worker audit](rk-ui-event-worker-path-audit.md), [serializer audit](rk-setting-serializer-audit.md), [localization audit](rk-resource-localization-audit.md), and [dialog-resource audit](rk-dialog-resource-audit.md).
