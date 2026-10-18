# RK 4.6 `CDevRKKB` vtable and ApplySetting audit

## Scope and safety

This report statically examines the `CDevRKKB` implementation in the
2,418,176-byte x86 `DeviceDriver.exe` extracted from the 4.6-labeled package.
The executable SHA-256 is
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
Addresses below are virtual addresses for that exact PE.

The executable was only read as PE bytes and disassembly. RK software and the
updater were not run; no HID interface was opened, no report or command was
sent, and no firmware or boot mode was touched. “Proven” means the code or
data path is present in this binary. It does not mean that a device accepts a
request or that a path was executed on the PC.

The hash-pinned [verifier](../scripts/audit_rk46_cdevrkbb_vtable.py) confirms
the profile-selected `CDevRKKB` vtable, constructor write, RTTI name, 26
function pointers, and selected `ApplySetting` frame markers. The row-level
[vtable ledger](rk-v4.6-cdevrkbb-vtable-map.csv) keeps uncertain virtual
method names and caller/device limits explicit.

## Class route and shared apply worker

The 4.6 profile selector's Fw-zero route initializes the `CHidDev` base and
then writes vtable address `0x005D410C` at constructor instruction
`0x00413D46`. The table's Complete Object Locator resolves to RTTI type
`CDevRKKB : CHidDev`. In the 265-row selector inventory, 133 profile rows
route to this class; this is profile-table evidence, not a confirmed mapping
from every physical board or receiver to that class. See the
[RTTI-backed family map](rk-v4.6-profile-family-rtti-audit.md).

The worker entry at `0x00401290` waits on two objects, reads the active device
object through global `0x00647320`, and—after its connection/state checks—loads
that object's vtable entry `+0x44` at `0x004013D5` and calls it at
`0x004013E7`. In the `CDevRKKB` table, `+0x44` is `0x00414930`, the large
`ApplySetting` routine described below. This proves the shared worker's
virtual dispatch route for an active object using this table. Which UI action
sets the worker event, how its arguments are assembled for each model, and
whether the route executes for a connected keyboard remain unresolved.

### Deferred-settings signal path and callsites

The helper at `0x00401100` clears bit `0x8000` from its 32-bit argument, passes
the resulting DWORD to the queue object at global `0x006356D8` through
`0x0043E6C0`, then calls the `ReleaseSemaphore` IAT at `0x005A64A4` with
semaphore handle global `0x006356C4`, release count 1, and a null previous
count pointer. `0x0043E6C0` checks the queue buffer and input pointer, enters a
critical section associated with queue offset `+0x1C`, appends a DWORD to the
bounded ring buffer, updates its indices/count, signals its event handle at
`+0x18` when present, and invokes its callback at `+0x14`. These are static
instructions; queue execution was not observed at runtime.

The hash-pinned [caller ledger](rk-v4.6-apply-signal-callers.csv) contains
exactly 24 direct `call 0x00401100` instructions in GNU objdump's x86
linear-sweep listing. Arguments at those sites are `1`, `2`, `4`, `6`,
`0x22`, or caller-derived `EBX`, `EBP`, and `ESI`. The ledger records their
nearest observed state writes and branch gates without assigning unsupported
feature names. In particular, the callsites do not prove that their receiver
object is a `CDevRKKB` instance. The 24-site set and helper bytes are checked
by [`audit_rk46_apply_signal_callers.py`](../scripts/audit_rk46_apply_signal_callers.py).

Global `0x0062A234`, which many callers test before signaling, is assigned at
`0x004566C9` from the return value of the preceding indirect call at
`0x004566B3`, which also receives nearby resource/string addresses. Its type
and precise meaning are unresolved; this null/equality gate is not evidence
that a keyboard is connected. The active device pointer used by the worker is
the separate global `0x00647320`.

There is also an inline producer: code at `0x0045DF36` pushes the constant 2
through `0x0043E6C0`, and `0x0045DF45` releases the same `0x006356C4`
semaphore. It then follows a route through the separate active-device global
`0x00647320`. This producer does not call `0x00401100` and is not counted
among its 24 callers. The other direct `ReleaseSemaphore` sites at
`0x0040893F`, `0x0040C31A`, and `0x0040C6D6` load a handle from global
`0x0063BE0C`; they are a different semaphore path and are not attributed to
this settings worker.

Because the helper strips `0x8000` before enqueueing, the worker's
`0x8000`-bit branch is not set by these helper calls. The producer of that
worker-control value remains unresolved. No callsite has been associated with
a particular visible UI control or confirmed physical keyboard revision.

## `CDevRKKB` virtual table

The 26 executable entries begin at `0x005D410C`; the next data at
`0x005D4174` begins the UTF-16 string `stream_unit.txt`, which bounds the
table in this image. Most slots target short zero/one-return routines. Their
machine behavior is proven, while the corresponding inherited interface
names remain unresolved. The full slot, target, evidence, and scope limit are
in the CSV.

| Slot | Target | Recovered role | Status |
| --- | ---: | --- | --- |
| `+0x00` | `0x00413D50` | Deleting destructor; closes/reset state and conditionally deallocates | Proven |
| `+0x04` | `0x00413DD0` | Descriptor-driven HID discovery/open | Proven code path; never invoked |
| `+0x14` / `+0x18` | `0x00413D90` / `0x00413DA0` | Primary handle getter / close-reset | Proven |
| `+0x20` | `0x0040DEB0` | Stored-path/handle availability probe | Purpose inferred |
| `+0x24` | `0x00413D00` | VID/PID equality check against object fields `+0x24C/+0x24E` | Proven |
| `+0x44` | `0x00414930` | `ApplySetting` | Proven static route |
| `+0x48` | `0x00414080` | Busy-guarded short-frame writer through the RKKB writer | Purpose inferred |
| `+0x5C` / `+0x60` / `+0x64` | `0x0040D750` / `0x0040D780` / `0x0040D7A0` | Set cancel flag and signal / clear and signal / query flag | Proven code behavior |

The unlisted slots are return stubs/adapters; their exact inherited method
names were not recovered. Slot `+0x20` has an open-capable file-path branch,
so its presence must not be mistaken for a passive state query. No slot was
invoked during this analysis.

## RKKB report writer

`0x00413F60` is the shared `CDevRKKB::WriteDevice` helper, identified by the
diagnostic at `0x005D3D80`. It splits the supplied buffer into chunks of at
most `0x3E` (62) bytes, adds a per-chunk sequence/index and report marker, and
calls thunk `0x00590A08` with a `0x41` (65-byte) report buffer. The 4.6 native
API audit resolves that thunk to `HidD_SetFeature` IAT `0x005A61E0`; the
writer's callsite is `0x00414036`. It delays 8 ms between successful chunks
and logs the package index on failure. This is a static write route, not a
validated packet format and not evidence of device acceptance.

## `ApplySetting` branches

The routine at `0x00414930` sets a busy field at object `+0x238`, reads an
apply-mask byte, and contains the following observed branches. Output paths
use `0x00413F60`; the UI/profile provenance of the mask and complete payload
schemas are unresolved. The listing below does not prove there are no other
routes elsewhere in the class.

### Key/action record translator

The `mask & 0x01` route calls `0x00414860` four times. Each call walks 132
16-byte source records, invokes translator `0x00414150`, and writes a
132-DWORD (`0x210`-byte) translated layer. Its source pointer advances by
`0x840` bytes between layer calls; the four translated outputs occupy one
`0x840`-byte region. This is direct evidence of a per-layer, per-record
conversion step, not enough to name each record's user-facing function.

`0x00414150` dispatches on the record's byte at `+3`. The static cases include:

| Record type / fields | Proven conversion behavior | Still unresolved |
| --- | --- | --- |
| `1`, low 24 bits at `+0` in `0x11..0x15` | Returns packed constants `0x0000F003`, `0x0000F103`, `0x0000F203`, `0x0000F403`, or `0x0000F303`. | User-facing action names and firmware interpretation. |
| `2`, bytes `+8/+9`, DWORD `+0x0C` | `+8=0,+9=0xFA` returns `0x00B00000`; `+9` in `1..5` returns the DWORD at `+0x0C`; other values use lookup tables or pack flag/code bytes. | The tables' names, flag meanings, and complete source-code vocabulary. |
| `3` or `4` | Maps a bounded low-24-bit range through jump/byte tables to packed DWORDs. | The semantic names of the ranges and target actions. |
| `5`, DWORD at `+8` | Calls lookup helper `0x00460310`; an unresolved ID returns `-1` and logs the macro ID. A found entry is converted using entry fields and global gate `0x0062B832`. | Macro record identity, the meaning of entry fields, and the global gate. |
| `6` or `7` | Maps a bounded range through a second table to packed DWORDs. | User-facing names and exact target actions. |
| `8` | Accepts only low-24-bit value `0xA2`, returning zero; other values return `-1`. | Meaning of the sentinel. |
| `9` | A zero low-24-bit value reuses the type-2 path; nonzero values call `0x00457EC0` with the DWORD at `+0x0C`. | Callee contract and action meaning. |

This conversion evidence strengthens the layer/key-action path, but does not
decode all table contents or connect individual records to a visible UI
control.

| Mask condition | Static route | Limits |
| --- | --- | --- |
| `mask & 0x14` | Zeroes a `0x800`-byte staging buffer, writes the prefix `03 7E`, walks 132 records at `0x00630875` with 16-byte stride, and packs per-record values. It submits a length selected as `0x81` or `0x17D`. The `0x10` bit forces the branch when the compared global/object values match; otherwise the route depends on the comparison. | A diagnostic labels this `KEYINFO_2_Matrix`. Record fields, offsets, meaning of the two length variants, and the UI trigger are unresolved. Do not equate this diagnostic with a fully recovered keymap schema. |
| `mask & 0x02` | Builds a frame beginning `02 29`, incorporates selected profile/state bytes, and calls the writer with length `0x3C`. | Nearby diagnostics mention key color and LED save/data errors. The complete field map, hardware meaning, and initiating control are unresolved. |
| `mask & 0x01` | Runs four record conversions into a `0x840`-byte translated-layer region as detailed above. It builds a separate `0x780`-byte macro staging region; helper `0x00415140` adds prefix `04 00` and submits `0x782` bytes. The same branch also constructs buffers with `01 F8` and, under a separate global gate, `10 F8` markers, submitting `0x1F9` bytes through the writer. | Diagnostics say `Macro`, `Matrix`, and `Matrix (FN)`. The exact record schemas, relation of the macro staging buffer to visible macro rows, marker meanings, per-profile availability, and UI event route remain unresolved. |

These lengths are arguments passed to the software's writer; they do not imply
that the keyboard accepts the payload or that the transfer completed. The
`02 29`, `03 7E`, `04 00`, `01 F8`, and `10 F8` prefixes are observed
construction markers only.

## Slot `+0x48` short-frame method

The method at `0x00414080` returns early when object `+0x238` is busy.
Otherwise it constructs one of two short buffers; one branch writes prefix
`06 00`, while the other begins with a caller-derived byte. It passes the
buffer to `0x00413F60`. Its four arguments, full payload grammar, callers,
visible label, and device-side meaning are not established. “System parameter
writer” remains a plausible name, not a recovered semantic identity.

## Remaining gaps and readback boundary

- No complete `CDevRKKB` UI-control-to-mask map or per-model feature-gate map
  has been recovered. The signal caller ledger narrows the static producer
  set but does not bridge any caller to a unique UI control.
- Matrix, key/layer, macro, LED and short-frame payload fields remain partly
  opaque. The static writer does not supply firmware interpretation.
- The full `+0x48` call graph and the role of the zero/one-return inherited
  slots remain open.
- This static write-path audit does not demonstrate firmware readback or
  non-destructive firmware copying. The existing
  [firmware readback audit](rk-firmware-readback-audit.md) remains the source
  for that question; no device operation was attempted here.
- This closes a 4.6 `CDevRKKB` class/vtable/settings-path gap. It does not
  complete the RK software suite, the updater, all API call paths, or every
  model/revision protocol.
