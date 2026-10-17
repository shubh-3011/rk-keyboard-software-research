# Settings Apply signaling and device-family dispatch

## Scope and binary identity

This audit traces one UI Apply event to a semaphore-backed worker, the
worker's indirect device-family call, and the recovered vtable targets in the
installed `DeviceDriver.exe` 4.06 image. The available static evidence does
not resolve the concrete receiver and data arguments at that indirect call.
SHA-256:
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
The binary was inspected statically. No RK executable was launched, no HID
interface was opened, and no keyboard report was sent.

## Semaphore initialization and wake-up

The initialization block at `0x004010E0` creates two synchronization objects:

| Handle global | API and arguments | Role in worker |
| --- | --- | --- |
| `0x00619728` | `CreateEventW(NULL, FALSE, FALSE, NULL)` at `0x00401110` | Second handle in the worker's wait array; a signaled result `1` takes the worker exit path. |
| `0x00619724` | `CreateSemaphoreW(NULL, 0, 100, NULL)` at `0x0040111F` | First wait handle; signaling sites release one count and update shared operation state. |
| `0x00619738` | `CreateEventW(NULL, FALSE, FALSE, NULL)` at `0x0040114F` | Completion event signaled after the worker's post-apply state check; also signaled during shutdown. |

The block initializes thread context at `0x00619720` and starts worker entry
`0x00401170` through helper `0x0056DC08` at `0x00401162`. The shutdown helper
`0x00401020` signals both events, sleeps 10 ms, and closes both events and
the semaphore. The worker waits
with `WaitForMultipleObjects(2, handles, FALSE, INFINITE)` at `0x004011AB`.
Its handle array is built from globals `0x00619724` and `0x00619728`.

`FUN_00401080` receives a mask in `EAX`. It clears bit `0x8000`, stores the
resulting value at shared field `0x0061972C`, and calls
`ReleaseSemaphore(0x00619724, 1, NULL)` at `0x00401094`. All 15 direct helper
callers and two additional direct mask-`4` releases are listed with their
observed masks, gates, and nearby code in
[`rk-apply-signal-callers.csv`](rk-apply-signal-callers.csv). The mask values
and some UI-adjacent operations are mapped, but visible control labels and
final hardware effects remain incomplete. The mechanism is a counting
semaphore plus shared state, not a recovered FIFO of independent operation
records: each signal has no separate payload object, and concurrent signals
share the single mask field.

## Worker dispatch

For a semaphore wake, `FUN_00401170` loads the root object through global
`0x0062B380`, checks its state through vtable slot `+0x28`, and calls the
root object's `+0x3C` method at `0x004012A0`. The call receives the shared mask
from `0x0061972C` plus thread/device context values. The concrete vtable and
argument values at this callsite are unresolved. Log strings referenced by
this path include “Start Thread”, “Start Apply: pDev or pHidDev=NULL”,
“Start Apply: hDevice=0x%x, vid=%04x, pid=%04x, nFlag=0x%x, pHidDev=%x”,
“Update settings failed!”, “Apply Over”, and “thread exit”. After the virtual
method returns, the worker checks device state again; when that check passes,
it signals the event stored at shared-state offset `+0x18` (global
`0x00619738`). Its apply return value is checked separately for the error
path. This is a statically recovered worker, not evidence that it ran for a
particular keyboard.

RTTI-backed vtables resolve the `+0x3C` target for all three recovered device
classes:

| Class | Vtable address point | COL VA | RTTI TypeDescriptor VA | Slot `+0x3C` target |
| --- | ---: | ---: | ---: | --- |
| `CDevRKKB` | `0x005CBE0C` | `0x005E3C5C` | `0x006037C0` | `FUN_00413BF0` — RKKB apply/writer path |
| `CDevG5KB` | `0x005CBA2C` | `0x005E3C10` | `0x006037A8` | `FUN_00411B90` — G5 settings orchestrator |
| `CDev3632` | `0x005CA32C` | `0x005E3B7C` | `0x00603778` | `FUN_0040E690` — busy-check/delay wrapper that enters `FUN_00411B90` |

These class-specific slot targets are statically identified. The worker's
receiver type at `0x004012A0` is not; therefore this table does not prove that
every UI signal dispatches to any particular family. When the worker's
receiver uses the `CDevRKKB` vtable, slot `+0x3C` enters `FUN_00413BF0` and
its key/layer, LED-data, per-key-color, matrix, and conditional Fn branches
described in the [settings serializer audit](rk-setting-serializer-audit.md).
The `CDevG5KB` slot enters `FUN_00411B90`; the `CDev3632` slot enters
`FUN_0040E690`, whose busy-check/delay wrapper then calls `FUN_00411B90`.
Profile construction in `FUN_004156E0` scans 0x12-byte records beginning at
`0x006102A0` and checks each against HID descriptor data through
`FUN_004155C0`. For a matched record, the word at entry offset `+0x0A`
selects `CDevRKKB` when zero and `CDevG5KB` when nonzero; the field's semantic
name is unresolved. This profile-based selection does not identify which
object the worker held during any runtime event. A separate factory path at
`FUN_00415900` can attach a `CDev3632` child at parent offset `+0x250`. The
worker dispatches on the root object's vtable; the nested-object evidence does
not show that the worker directly calls the child's `+0x3C` method. The
`CHidDev` base vtable at `0x005CA2C4` is a different table; its
`+0x3C` entry is a false-returning stub at `0x0040D080`. It must not be
mistaken for the RTTI-backed `CDev3632` vtable at `0x005CA32C`, whose
`+0x3C` entry is the `0x0040E690` wrapper.

## UI Apply edge and limits

One generated `tc_apply` control is stored at `this+0x1DD8`. Its handler checks
that child HWND, reaches `0x0040AE1D`, calls `0x0040B3B0` to update an
in-memory record under `0x0062B384+0x458+index*0x10`, then calls
`FUN_00401080` with mask `1` when global `0x00611794` is set. The semaphore
worker passes this shared mask to its object's `+0x3C` method. This establishes
the UI-handler-to-worker signal edge and the worker's indirect dispatch site,
but not the concrete receiver or final writer for this particular event. If
the receiver is `CDevRKKB`, mask `1` reaches its key/layer branch in
`FUN_00413BF0`; if it is `CDevG5KB`, the same bit reaches the corresponding
keymap branch in `FUN_00411B90`.

`CKeyFunPickDlg` has a separate localized Apply button at `this+0x204`, with
handler `0x0041F810`; that handler updates its local selection/dirty fields.
No direct call from that picker handler to `FUN_00401080` or a device writer
was found. The two controls must not be collapsed into one action solely
because both use the `tc_apply` label.

The broader 15 helper-callsite set and two direct mask-`4` releases still need
a per-control mask map. No direct call instruction to `FUN_00413BF0` exists;
its only code pointer is the `CDevRKKB` vtable slot. The worker's concrete
receiver and profile were not observed at runtime. This audit therefore
proves the UI signal edge, the polymorphic worker call, and class-specific
vtable targets separately, but not which model or operation ran on the
connected S98 or what every serialized byte means. Address values apply only
to the hash-pinned 4.06 image.
