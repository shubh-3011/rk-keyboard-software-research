# V4.6 Apply/Restore UI-to-worker signal trace

## Scope and evidence boundary

This trace follows two main-window child controls in the V4.6 `DeviceDriver.exe`
through the window handler, queue signal, and worker dispatch. The executable is
the 2,418,176-byte x86 PE with SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
Addresses below are virtual addresses in that exact image.

Analysis is static: the RK application was not launched, no HID/device
interface was opened, and no report, command, or configuration was sent. The
trace establishes code and data relationships in the file, not runtime
reachability for a connected keyboard or successful device acceptance.

## Control identity

The main-window constructor binds two embedded control objects to descriptor
globals:

| Main-window field | Descriptor global | String key and visible English text | Registration argument |
| --- | --- | --- | --- |
| `this+0x1C54` | `0x00647444` | UTF-16 `tc_restore` at `0x005DC1E8`; installed English `Text/en/text.xml` maps it to **Restore**. | `0x0B` at `0x004445F3` |
| `this+0x1DD8` | `0x00647450` | UTF-16 `tc_apply` at `0x005DC220`; installed English `Text/en/text.xml` maps it to **Apply**. | `0x11` at `0x00444746` |

The first object/descriptor pair is joined by constructor instructions at
`0x0040A833`–`0x0040A842`; the second pair is joined at
`0x0040A88A`–`0x0040A897`. The registration/setup code passes the same globals
to `0x00405B20`, alongside the respective numeric arguments and localized
string descriptors (`0x004445EE`–`0x004445FB` and
`0x00444741`–`0x0044474E`). The numeric arguments are recorded as supplied;
their separate framework meaning is not inferred here.

The string keys are independently visible in the PE's UTF-16 read-only data
and in the installed English localization XML. Other locales can supply
different text; the stable identifiers are `tc_restore` and `tc_apply`.

## Window-handler and queue path

In the main-window handler, the incoming command handle is compared with the
child handle stored at `this+0x20` for each embedded control:

1. `0x0040AC7D` loads `this+0x1C54`, reads its `+0x20` handle, and branches to
   common block `0x0040B2AD` on a match. This is the `tc_restore` control.
2. `0x0040AC92` performs the same comparison for `this+0x1DD8` and branches
   to `0x0040B2AD` on a match. This is the `tc_apply` control.
3. The common block calls `0x0040B840`. If the `ApplyNow` integer stored in
   global `0x0062A234` is nonzero, it
   pushes the constant `1` and calls queue helper `0x00401100`
   (`0x0040B2AD`–`0x0040B2C4`). Both controls therefore converge on the same
   conditional request value; the queued value does not retain which label
   was clicked.

The pre-queue helper `0x0040B840` sends `SendMessageW` to the window stored at
`this+0x1F8`, with message `0x110A`, `wParam=9`, and `lParam=0`. It uses the
returned value to search a linked collection at `this+0x2FC`, checks current
index/range fields around `this+0x1458`–`0x1460`, and updates or clears a
16-byte-stride runtime record through the pointer loaded from global
`0x00647324`, at record offset `+0x458`.
The profile-record field's semantic name and the meaning of message `0x110A`
remain unresolved. This is a static state-update path; no message was sent
during this analysis.

Startup/configuration code at `0x004566B3` loads the gate through
`GetPrivateProfileIntW` from section `OPT`, key `ApplyNow`, with default `0`;
the return is stored to `0x0062A234` at `0x004566C9`. The import is
`KERNEL32!GetPrivateProfileIntW` at IAT `0x005A63E0`. The specific INI pathname
and wider user-facing meaning of the option remain unresolved.

Queue helper `0x00401100` masks the request, places it on the queue, and
releases the associated semaphore. The worker at `0x00401290` waits on that
semaphore, retrieves the active device object, and dispatches the value through
its vtable `+0x44`. For a `CDevG5KB` object, the verified target is
`CDevG5KB::ApplySetting` at `0x004127B0`; the worker and G5 flag routes are
covered in the [class/settings audit](rk-v4.6-cdevg5-settings-and-vtable-audit.md).
The virtual call is family-dependent: this trace does not prove that every
connected descriptor selects G5 or that every profile's request reaches the
same implementation.

## Findings and remaining limits

- The visible **Restore** and **Apply** controls are both statically connected
  to a gated queue signal with value `1` after the same `0x0040B840` state
  update.
- The queue consumer dispatches virtually to the active device family's
  `+0x44` method. The G5 implementation is mapped; other family routes must
  be interpreted from their own vtables.
- The return semantics of message `0x110A`, the profile field at record `+0x458`,
  the wider UI semantics of `[OPT] ApplyNow`, runtime control reachability, and actual hardware
  effects remain unresolved.
- This closes the specific V4.6 Apply/Restore UI-to-queue gap. It does not
  complete reverse engineering of every control, API, syscall, family,
  protocol field, model, or firmware behavior.

The byte-level evidence is checked by
[`audit_rk46_ui_setting_signal.py`](../scripts/audit_rk46_ui_setting_signal.py).
