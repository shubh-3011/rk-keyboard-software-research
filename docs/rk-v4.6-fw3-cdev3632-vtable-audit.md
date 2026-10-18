# RK 4.6 Fw=3 constructor and `CDev3632` vtable audit

## Scope and safety

This is an offline static audit of the V4.6-labeled package's `DeviceDriver.exe`
only, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9` (2,418,176
bytes; image base `0x00400000`). The exact input is
`.research/rk4_6_official_extract_20261015/app/DeviceDriver.exe`. Analysis used
GNU `objdump` and the existing hash-pinned API-call-site CSV. Neither RK app nor
updater was launched. No HID, serial, Bluetooth, or other device interface was
opened; no report or command was sent.

**Evidence labels:** PE bytes, table values, direct calls, and profile fields
are proven statically for these exact inputs. The names and meaning of protocol
commands are only inferred where stated. Runtime reachability and physical
keyboard acceptance remain unresolved.

## Selector-to-constructor linkage

The 4.6 selector audit records the exact-`Fw=3` branch at `0x004165CD` calling
constructor `0x0040DAD0` for a `0x2D4`-byte object after its HID-capability
predicate. The one configured profile with `Fw=3` in this package is code
`0208`, label `M20`, USB IDs `258A:0208` ([selector audit](rk-v4.6-profile-selector-audit.md)).
This is a static profile-to-factory association. It does not establish that a
physical M20 has the accepted descriptors, or that any runtime operation
succeeds.

## RTTI and class identity

At `0x0040DB03`, the constructor writes vtable address `0x005D2464` to the
object's first word. The preceding vtable word at `0x005D2460` points to RTTI
Complete Object Locator `0x005ECE44`. Its x86 fields decode as signature 0,
object offset 0, constructor-displacement offset 0, TypeDescriptor pointer
`0x0061A0BC`, and ClassHierarchyDescriptor pointer `0x005ECE58`.

The TypeDescriptor at `0x0061A0BC` has the MSVC decorated name
`.?AVCDev3632@@` (name bytes start at `0x0061A0C4`). The hierarchy descriptor
at `0x005ECE58` declares two class entries; the second base descriptor points
to TypeDescriptor `0x0061A0D4`, whose decorated name is
`.?AVCHidDev@@` (name bytes at `0x0061A0DC`). Therefore this vtable is statically
identified as `CDev3632`, derived from `CHidDev`.

This is stronger than inferring a family from `Fw=3`: the class name is present
in RTTI referenced by the actual vtable installed by the dedicated constructor.
It still does not prove device compatibility or executed calls.

## Vtable entries

The pointer array at `0x005D2464` has 27 executable entries before the following
UTF-16 string data begins at `0x005D24D0`. Slots are zero-based. “Unresolved”
means the target is recovered but its behavioral contract is not established by
this pass.

| Slot | Target | Static behavior / evidence |
| ---: | ---: | --- |
| 0 | `0x0040DBC0` | Deleting-destructor wrapper; calls `0x0040DBE0`, then conditionally frees the object. |
| 1 | `0x0040DD80` | Matches VID/PID and HID capability fields against the 4.6 capability table; for the `FF02` / usage 2 / two `0x14` fields, calls `CreateFileW` on the selected device path and stores the returned handle. This is the dedicated open/match method. |
| 2 | `0x0040D710` | Returns zero. |
| 3 | `0x0040DC60` | Creates three event objects and starts thread procedure `0x0040D7D0` with `CreateThread`. |
| 4 | `0x0040DCE0` | Closes and clears the three event handles; signals one event and waits 20 ms before closing it. |
| 5 | `0x00413D90` | Returns object field `[this+4]`, populated with the opened device handle. |
| 6 | `0x0040DD50` | Closes `[this+4]`; clears that handle and adjacent connection fields. |
| 7 | `0x0040D720` | Returns zero. |
| 8 | `0x0040DEB0` | Attempts `CreateFileW` on the object's path field and closes a successful temporary handle; if that path field is empty, calls an unresolved helper with `[this+4]`. Return meaning is not named. |
| 9 | `0x0043E950` | Returns zero; same target as slot 26. |
| 10 | `0x0040D710` | Returns zero; same target as slot 2. |
| 11 | `0x0040E6E0` | If field `[this+0x25C]` is clear, issues command selector `0x07` through `0x0040E200`; on success stores a Boolean derived from one response byte at `[this+0x264]`. |
| 12 | `0x0040E600` | Calls `0x0040E200` with selector `0x4A` and a two-byte local response buffer; optional output pointers receive the two bytes. |
| 13 | `0x0040E6B0` | Calls `0x0040E9C0` with selector `0x05` and caller-supplied buffers/length values; converts its result to a Boolean. |
| 14 | `0x0040E680` | Calls `0x0040E200` with selector `0x06`; returns success/failure. |
| 15 | `0x0040E5D0` | Calls `0x0040E200` with selector `0x44` and caller-provided arguments. Slot 19 invokes this slot indirectly. |
| 16 | `0x0044B310` | Returns one; higher-level behavior unresolved. |
| 17 | `0x0040EE30` | Under a busy flag, allocates and constructs a temporary `0x2F0`-byte `CDevG5KB` object (`0x0040F490`), stores a back-reference, invokes its vtable slot `+0x44`, then destroys it. Exact operation intent unresolved. |
| 18 | `0x0040ED20` | When `[this+0x238]` is clear, calls `0x0040DF10` with selector `0x88`; parameters include caller data/length. |
| 19 | `0x0040ED70` | Sleeps 30 ms; calls this object's vtable slot `+0x3C` (slot 15, selector `0x44`) requesting `0x80` bytes; then passes the resulting 128-byte buffer to `0x0040DF10` with selector `0x04`. This is a statically visible read-then-write path; its setting meaning is unresolved. |
| 20 | `0x0040E640` | Calls `0x0040DF10` with selector `0x0B`, a `0x0F`-byte length, caller data, and an output argument; return is success/failure. |
| 21 | `0x0040D740` | Returns zero; caller cleanup arguments are discarded. |
| 22 | `0x0040D740` | Same target as slot 21. |
| 23 | `0x0040D750` | Sets `[this+0x28C]` and signals event `[this+0x290]` if `[this+0x288]` is nonzero. |
| 24 | `0x0040D780` | Clears `[this+0x28C]` and resets event `[this+0x290]` if present. |
| 25 | `0x0040D7A0` | Returns `[this+0x28C]`. |
| 26 | `0x0043E950` | Returns zero; same target as slot 9. |

The slot descriptions above are instruction-level summaries, not recovered
source-level method names. The targets at slots 9, 16, and 17 are not mapped to
an end-user feature in this pass.

## Direct transport and report evidence

The constructor `0x0040DAD0` first calls base initializer `0x0040D640`, installs
the `CDev3632` vtable, and initializes its event/handle fields. Vtable slot 3
(`0x0040DC60`) creates the worker thread with start address `0x0040D7D0`. The
4.6 API-call-site crosswalk
maps the relevant IAT addresses to `CreateThread` (`0x005A6468`), `CreateFileW`
(`0x005A6474`), `ReadFile` (`0x005A6470`), `WriteFile` (`0x005A646C`),
`WaitForSingleObject` (`0x005A6464`), `CancelIo` (`0x005A6454`), and
`GetOverlappedResult` (`0x005A6450`). Those names are also directly visible in
the API import/call-site inventory.

The worker at `0x0040D7D0` reads `0x14` (20) bytes from the opened handle using
`ReadFile`, with an overlapped event, then calls parser `0x0040D990` on the
buffer. It loops on the wait/read path and updates the object/event state.
Separately, helper `0x0040E200` builds a fixed 20-byte buffer whose leading
framing byte is `0x13`, copies caller selector/payload data, computes a
byte-sum checksum over the frame fields, and calls `0x0040E8A0`. Related helper
`0x0040DF10` validates a maximum length of `0x1FF`, splits payloads into chunks
of at most `0x0E` bytes, frames each chunk, and also calls `0x0040E8A0`. That
writer issues `WriteFile` for 20 bytes, waits on an overlapped event for up to
`0x1F4` ms, and contains an initial attempt plus a retry loop capped at three
retries. This directly establishes a 20-byte request/response transport path
and a writer; it does not establish what any physical keyboard does with a
frame.

For the methods above, literal selector values `0x05`, `0x06`, `0x07`, `0x44`,
and `0x4A` are proven call arguments to the 20-byte transport helper. Values
`0x88`, `0x0B`, and `0x04` are proven call arguments to helper `0x0040DF10`.
The exact protocol names, report type/direction assigned to each selector, and
the semantic meaning of these operations are unresolved here. The separate
4.06 report documents analogous 3632-family code, but its addresses and
behavioral conclusions are not silently treated as 4.6 proof.

## M20 relationship and limits

**Proven:** the V4.6 configuration has one `Fw=3` profile (`0208`, label M20),
and the exact `Fw=3` constructor installs a vtable whose RTTI says `CDev3632`.
That is a strong static link between this package's M20 profile selector and
the `CDev3632` implementation class.

**Inferred:** the compiled class is intended for the profile path selected by
`Fw=3` and uses its own 20-byte transport plus additional HID report-selector
operations.

**Unresolved:** whether a particular M20 revision reports the required HID
capabilities; whether the path is reached on an attached keyboard; whether the
selector values map to named settings; the precise semantics of the temporary
G5 object path; and whether any operation succeeds on real hardware. No I/O was
performed to answer these questions.
