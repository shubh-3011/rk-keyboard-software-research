# V4.6 profile signal 2 to G5 command-4 follow-up

## Evidence and scope

This static follow-up traces the `CKeyDlg` private-message route that queues
value `2`, through the shared settings worker, into the G5 `ApplySetting`
branch and its command-4 writer. The exact input is the 2,418,176-byte x86
`DeviceDriver.exe` from the V4.6-labeled package, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
Addresses below are VAs for that PE.

Only PE bytes and static disassembly were examined. The vendor application and
updater were not launched. No HID/device interface was opened, no report was
sent, and no device response or effect was observed. A static route in this
report is not evidence that a particular connected keyboard accepts it.

## Message handler to queued value

The `CKeyDlg` MFC message-map entry at `0x005D4CA0` maps private message
`0x477` to handler `0x0041CF20`. Its relevant branch requires the second
message argument to equal `2` and the first argument to have a nonzero
`0xFF00` mask (`0x0041CFEA`–`0x0041CFFF`). It copies global `KnobDef`
(`0x0062A278`) into object byte `this+0x5EBF`, copies the 16-byte profile row
selected by `KnobIndex` (`0x0062A274`), and checks `[OPT] ApplyNow`'s loaded
value at `0x0062A234`. If that gate is nonzero, it pushes `2` and calls queue
helper `0x00401100` (`0x0041D034`–`0x0041D048`); it then calls profile mutator
`0x0041EC50`.

The helper clears bit `0x8000`, enqueues the resulting DWORD through
`0x0043E6C0`, and releases semaphore `0x006356C4` (`0x00401100`–
`0x00401127`). The queued value `2` is unchanged by this mask.

This is a proven handler-to-queue route, conditional on message arguments and
`ApplyNow`. It is not yet a proven visible knob-control-to-handler route. The
existing static audit identifies two `PostMessageW(0x477)` sites, at
`0x00435A23` and `0x00436686`, but does not identify their objects as the
localized knob controls or show that either sender supplies the required
second argument `2`. The four knob labels and profile fields are evidence of
software data, not a confirmed sender identity.

## Queue to family implementation

Worker `0x00401290` drains the queue using `0x0043E780`; the dequeued DWORD is
held at `0x004012F4`–`0x004012F8`. After active-device and state checks, the
worker loads the selected object's vtable slot `+0x44` and calls it at
`0x004013D5`–`0x004013E7`. The worker pushes the dequeued value as the fourth
stack argument (`0x004013DA`); the G5 method's `nFlag` tests read that fourth
argument (including the bit-`0x02` test at `0x00412E31` after its local frame
setup). Thus this queue value reaches G5 as `nFlag=2` when the active object's
slot resolves to `CDevG5KB::ApplySetting`. The target class depends on the
active object; the worker does not establish the physical device's model.

All eight profiles carrying `KnobIndex`/`KnobDef` in the extracted catalog
(`02FE`, `0300`, `02EB`, `02EC`, `02ED`, `02F2`, `02F4`, `02F6`) have `Fw=1`
and route through the selector's general nonzero factory to the verified
`CDevG5KB` vtable. Its `+0x44` slot is `0x004127B0`. This joins the listed
knob-profile records to the G5 class in the package's static configuration;
it does not prove that those profiles are selected or that a physical board
matches them.

## G5 flag-2 serializer path

`CDevG5KB::ApplySetting` at `0x004127B0` logs an `nFlag` field and tests its
flag bits. For value `2`, its flag-`0x02` branch is taken at
`0x00412E31`–`0x00412E38` (subject to the method's surrounding object, state,
and read-success checks). That branch:

1. Requests a `0x80`-byte block through the object's virtual slot `+0x3C`
   (`0x00412EA2`–`0x00412EB7`).
2. Checks the block's final bytes for `5A A5` (`0x00412EE0`–`0x00412EF2`).
3. Selects a transformer based on object field `+0x250` (`0x00412F2D`–
   `0x00412F5F`), then passes the resulting `0x80` bytes to
   `0x00410340` (`0x00412F89`–`0x00412F93`).
4. `0x00410340` calls `0x0040FFD0` with operation `1`, command `4`, and length
   `0x80` (`0x00410366`–`0x00410375`). The shared frame builder creates a
   `0x208`-byte feature report and calls thunk `0x00590A08` at
   `0x0041014F`; the thunk resolves to `HID.DLL!HidD_SetFeature` in the
   hash-pinned API crosswalk.

The diagnostic at `0x005D1E04` says `SetLED failed`, so the code labels this as
an LED-related route. The exact fields, units, profile meaning, firmware
interpretation, and visible initiating control remain unresolved. The writer
path is static only; it does not prove a report was sent or accepted.

## Conclusion and open edges

**Proven statically:** when `CKeyDlg` handler `0x0041CF20` receives the
specified `0x477` arguments and `ApplyNow` is nonzero, it queues `2`; the
worker can pass that value to the active object's `+0x44` method; the listed
knob-profile rows select `CDevG5KB`; and G5 flag `2` contains a conditional
read/transform/operation-1 command-4 (`0x80`-byte data) path ending in a
`HidD_SetFeature` call.

**Unresolved:** the exact visible knob control and its sender, whether a
specific profile/device is active, runtime worker reachability, the meaning of
the `0x80`-byte layout and command-4 payload, device acceptance, and physical
effect. In particular, this report does not claim the knob labels are controls
that initiate the identified `0x477` message.

## Existing evidence

- [Knob localization, profile and message-map audit](rk-v4.6-ui-knob-localization-path-audit.md)
- [Profile selector and family routing audit](rk-v4.6-profile-family-rtti-audit.md)
- [G5 vtable and settings-path audit](rk-v4.6-cdevg5-settings-and-vtable-audit.md)
- [Queue and Apply/Restore worker audit](rk-v4.6-ui-setting-signal-audit.md)
- [HID API call-site crosswalk](rk-v4.6-native-api-call-sites-reconciled.csv)
