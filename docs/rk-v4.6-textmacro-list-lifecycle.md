# RK 4.6 text-macro mapping-list lifecycle

## Scope and result

This static-only follow-up resolves the list rooted at `0x00619DCC` that the
text-macro reclamation helper walks. It is the head field (`+0x10`) of a
list-like object at `0x00619DBC`. The examined executable is the hash-pinned
4.6-labeled `DeviceDriver.exe` (SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`,
2,418,176 bytes).

The list implementation is recoverable: it allocates 12-byte doubly linked
nodes, appends/removes/clears them, invokes an optional callback, and can free
payloads according to an owner flag. A virtual method in the RTTI-identified
`COemDrvDlg` vtable assigns the list's payload-freeing mode and a no-op callback
when its preceding initialization call returns zero. Two code paths append to
this global list; other paths clear or remove its nodes. This narrows the
cleanup helper's input to mapping-base payloads held by a concrete global
collection, but does not identify every payload's runtime type or prove that
the collection covers all active models or profiles.

The cleanup caller review also narrows persistence. No direct call to the
`textmacro.dct` writer is present on the three cleanup call branches. One
caller writes a separate `pro.dct` before cleanup; another can persist
profile state to `pro.dct` after cleanup. In the picker handler, the direct
`textmacro.dct` save path and cleanup path are mutually exclusive at the local
state gate. The shared virtual tail resolves to a dialog-close path with no
direct file-writer call. Its normal modal result now traces through the
parent's result check: `1` continues to a follow-up at `0x0041EC50`, while
other results branch to cleanup. The TLS helper's null/failure path raises a
C++ exception beyond the immediate picker frames. Higher-level exception
recovery and the later follow-up handler remain open, so this does not rule
out every later persistence route.

## Evidence

### Object and initialization

The file image at `0x00619DBC` contains a vtable pointer `0x005DBF8C`, mode
`0x11` at `+0x04`, and zero values at `+0x08` through `+0x14`. The fields used
by the list helpers are:

| Offset | Static meaning established by helper use |
| --- | --- |
| `+0x04` | Payload ownership mode; removal/clear frees non-null payloads when this equals `0x10`. |
| `+0x08` | Node count. |
| `+0x0C` | Optional callback invoked with the node payload. |
| `+0x10` | Head pointer (`0x00619DCC`). |
| `+0x14` | Tail pointer (`0x00619DD0`). |

`0x00448930` appears in slot 84 of the RTTI-identified `COemDrvDlg` vtable
(`0x005DDC6C`; the preceding complete-object locator resolves to
`.?AVCOemDrvDlg@@`). In this method, a call to `0x00448880` is followed by a
zero test; on the zero-return branch, `0x00448B0D` sets `EDI=0x10`,
`0x00448B15` writes callback `0x00427D80` to `0x00619DC8`, and `0x00448B1F`
writes the mode to `0x00619DC0`. `0x00427D80` is a one-byte `RET`. The method
does not directly initialize the count, head, or tail in this assignment
block; the executable's initial data bytes for those fields are zero. The
method's symbolic name, invocation at runtime, and `0x00448880`'s full role
remain unresolved. The same block writes matching callback/mode values at
`0x00619DB0` and `0x00619DA8`; the adjacent list-like object at `0x00619DA4`
has the same static layout, but its role is outside this follow-up.

The generic constructor at `0x00440AC0` independently shows the common object
shape: vtable `0x005DBF8C`, zeroed count/callback/head/tail, and mode `0x11`.
This establishes helper conventions; it does not prove this constructor ran
for the static global.

### Node and mutation semantics

The helper at `0x00440B80` allocates `0x0C` bytes per node. Node `+0` stores
the payload, `+4` the forward link, and `+8` the backward link. It sets both
head and tail for the first node, otherwise links the prior tail and updates
the tail, then increments the owner count.

`0x00440C50` removes a specified node, repairs neighboring links and owner
head/tail as needed, optionally calls the owner callback, conditionally frees
the payload when owner `+0x04 == 0x10`, frees the node, and decrements the
count. `0x00440CC0` applies the same callback/payload/node release behavior
while clearing the list. `0x00440B00` is the teardown variant: it also restores
the generic vtable pointer. The callback installed for this global returns
immediately; the mode value enables payload freeing in these helpers.

The exact owner-passing callsites recovered in this slice are:

| Operation | Owner setup | Helper call | Scope |
| --- | --- | --- | --- |
| Append | `0x0044910C` loads `0x00619DBC` into ESI | `0x00449111` → `0x00440B80` | One list-building path. |
| Append | `0x00460BA0` loads `0x00619DBC` into ESI | `0x00460BA5` → `0x00440B80` | One copy/insert path. |
| Remove | `0x00460BE5` loads `0x00619DBC` into EDI | `0x00460BEA` → `0x00440C50` | Removes a matching node. |
| Clear | `0x00448788` loads `0x00619DBC` into EDI | `0x0044878D` → `0x00440CC0` | Owner cleanup path. |
| Clear | `0x0044904F` loads `0x00619DBC` into EDI | `0x00449054` → `0x00440CC0` | Rebuild path. |
| Clear | `0x00460D08` loads `0x00619DBC` into EDI | `0x00460D0F` → `0x00440CC0` | File-load/repopulation path. |
| Teardown | Thunk `0x005A53B0` loads `0x00619DBC` into ECX | tail-jumps to `0x00440B00` | Static destructor thunk. |

The orphan-record helper at `0x00401AD0` reads each node payload as a mapping
base and examines cells at fixed offsets. That proves the payload use in that
helper, not the complete source-level type or semantic coverage of the list.
The other list paths manipulate `0x5F14`-sized records, consistent with
mapping/profile objects, but this interpretation remains inferred.

A literal scan of executable sections finds nine encoded references to the
head field `0x00619DCC`; all nine decode as loads. It finds no direct absolute
store to that field. List insertions/removals update the head indirectly
through the generic helper and the owner pointer. The census does not rule out
computed aliases or other dynamically derived references.

### Cleanup callers and text-macro persistence

The three direct cleanup callers remain guarded as described in the [record
reclamation report](rk-v4.6-textmacro-record-reclamation.md). This follow-up
compares their local branches with the existing [text-macro file path
audit](rk-v4.6-textmacro-path-audit.md):

| Cleanup call | Local static path result | Boundary |
| --- | --- | --- |
| `0x0040381B` | `0x00460DA0` (`pro.dct` writer) is called before the cleanup gate. After cleanup, the examined slice has no direct `0x0041F540` text-macro writer or `0x00459F50` save/load wrapper call. | Other indirect dispatch is not excluded. |
| `0x0041D0A4` | The handler can call `0x0041EC50` after cleanup. On eligible selection/update paths, that handler writes a 16-byte row into the active mapping object, calls helper `0x00418890`, and calls the existing `pro.dct` writer at `0x00460DA0`. | This is profile-file persistence, not `textmacro.dct`; selection guards and runtime behavior remain unobserved. |
| `0x00421640` | The cleanup gate requires picker state not equal to `5`. The direct `textmacro.dct` writer call at `0x004215DE` belongs to the state-5 save branch, which skips cleanup. Both paths converge on the virtual call at `0x00421650`. After modal result `1`, the parent reaches `0x0041EC50`, whose eligible update branches can modify the active mapping row and save `pro.dct`. | Local macro save and cleanup branches are mutually exclusive. The normal selection path can persist profile state, but the bounded follow-up contains no direct `textmacro.dct` writer call. The null/failure TLS path raises a C++ exception beyond the immediate picker frames; higher-level handling remains open. |

The `textmacro.dct` writer at `0x0041F540` has two direct callers in the
examined executable: `0x004215DE` and `0x0045A057`. This static direct-call
census does not prove a complete interprocedural call graph. The current
evidence therefore shows no direct write of the reclaimed buffer on the
cleanup branches or within the resolved dialog-close target. The normal
parent result route is mapped through `0x0041EC50`: on eligible branches it
copies a 16-byte selected record into the active mapping row, calls update
helper `0x00418890`, and reaches the `pro.dct` writer at `0x00460DA0`. No
direct `textmacro.dct` writer call appears in that bounded follow-up. Later
vtable methods, higher-level exception recovery, and callers outside the
bounded paths may still lead to other persistence.

### Picker construction and modal return

The parent constructs the picker at `0x0041D135` using constructor
`0x0041F600`, which passes resource ID `106` to the base dialog constructor
and installs the `CKeyFunPickDlg` vtable (`0x005D530C`). It calls modal
wrapper `0x004811E6` at `0x0041D157`. That wrapper reaches
`USER32!CreateDialogIndirectParamW`, optionally runs the message loop through
`0x0047C55D`/`USER32!PeekMessageW`, and returns the dialog's stored field
`+0x44`. A byte scan finds 31 direct call candidates to the shared wrapper;
the picker parent is one of them. This is a static callsite census, not proof
that each caller executes.

After the virtual close path calls `USER32!EndDialog`, the parent compares
the wrapper result with `1` at `0x0041D15C`. Other results branch to parent
cleanup at `0x0041D2B2`; result `1` continues through selection checks and
calls `0x0041EC50` at `0x0041D267`. The semantics and subsequent call graph of
that handler are partly resolved below: its guarded update branches can copy a
selected record into the active mapping row and persist the profile through
`0x00460DA0` (`pro.dct`). The exact runtime-selected branch and its visible
UI meaning remain unobserved.

After the row copy, helper `0x00418890` bounds the row index to `0x84` entries
(132), stores the supplied dirty-state value in a per-row slot with `0x24`
byte stride, and calls `USER32!InvalidateRect` for the HWND stored at object
`+0x20`, passing a null rectangle and `TRUE` for erase. If global flag
`0x0062A234` is set, the same follow-up also calls notifier `0x00401100(1)`.
That helper clears bit `0x8000` in its argument and calls
`KERNEL32!ReleaseSemaphore` with the handle at `0x006356C4`, release count 1,
and null previous-count pointer. The worker consumer is now traced to a shared
queue loop; the queue values' application meanings and the global flags remain
unresolved. The indirect call later in the notifier is not resolved here.

### Shared queue worker and semaphore

The initializer at `0x00401160` creates an event handle at global
`0x006356C8` and a semaphore at `0x006356C4`, then passes handle block
`0x006356C0` and worker entry `0x00401290` to a CRT thread wrapper. The wrapper
reaches `KERNEL32!CreateThread`. The worker copies handle-block fields `+4`
and `+8` into a two-element array, then calls
`KERNEL32!WaitForMultipleObjects(2, handles, FALSE, INFINITE)`. Result index
`0` enters queue processing; result index `1` returns from the worker.

After a semaphore wake, the worker loads queue pointer `0x006356D8` and calls
dequeue helper `0x0043E780`. The producer `0x00401100` clears bit `0x8000`
from its input, enqueues the resulting value through `0x0043E6C0`, then
releases the same semaphore. A second bounded producer at `0x0045DF24` queues
value `2` and releases that semaphore. This proves a static queue/wakeup path
and one worker's wait/dispatch loop; the meaning of each queue value, the
worker's full virtual-dispatch semantics, all producers, and runtime
scheduling remain unresolved. One later host-window branch is identifiable:
the worker loads a window-name pointer from the shared UI object, calls
`USER32!FindWindowW(NULL, name)`, and, after virtual callback and global-flag
gates, may post `USER32!PostMessageW(hwnd, WM_CLOSE, 0, 0)` to the returned
window. The target window's identity and the callback results' meaning remain
unresolved; this is a host UI path, not evidence of a keyboard command. The
executable was not run.

### Picker virtual tail

The call at `0x00421650` loads slot `+0x158` through the `CKeyFunPickDlg`
vtable (`0x005D530C`); that slot points to `0x00480C2C`. This method calls
`0x0047C312` with value `1`; a nonzero result reaches `0x00480C02` with modal
result `1`. For this class, the helper's slot `+0xFC` target is `0x00405770`,
a `ret 4`. The close helper can call slot `+0x8C` (`0x0047C6A1`), which stores
the result and conditionally calls `USER32!PostMessageW`; it then calls
`USER32!EndDialog` through IAT slot `0x005A65C0`. No direct text-macro writer
or save/load wrapper call occurs in these resolved methods.

The normal exception-frame epilogue restores the saved frame and returns.
This closes the immediate virtual target and its normal parent modal-result
route, not every deferred or exceptional route.

### Picker first-use thread-local object

The guard at `0x0048A529` passes callback `0x00477AA0` and state object
`0x0061C398` to helper `0x0048CA84`. On the normal path, the helper initializes
the shared TLS context when absent, allocates a TLS index for the state object,
looks up the current thread's entry, and calls the callback only when no
per-thread object exists. It then registers the callback result in that
thread's TLS record. The callback requests a zero-initialized `0x164`-byte
object through `LocalAlloc`, sets vtable `0x005AA724`, and clears fields
`+0x34`, `+0x4C`, `+0x50`, and `+0x54`.

The traced helper slice uses TLS APIs, critical sections, and local/global
allocation to manage the context and per-thread tables. No file, registry,
network, or HID API call appears in this bounded normal-path helper/callback
trace. If the guard receives a null result, it branches to shared stub
`0x00477A84`, which constructs an exception object and reaches
`KERNEL32!RaiseException`; RTTI for the throw-object template names
`CInvalidArgException`. The helper and callback frames have cleanup/unwind
paths but no local catch blocks. In the picker validation method
`0x0047C312`, the accessor call happens before its protected state begins, so
that method's local catch does not cover this exception. It propagates beyond
the immediate picker methods; higher-level catch/UI recovery is not traced.
This concerns a shared helper with 28 direct callsites, not a picker-exclusive
mechanism. It does not classify later methods reached through the new object's
vtable or prove that an exception occurs at runtime.

## Evidence and reproduction

The [instruction ledger](rk-v4.6-textmacro-list-lifecycle.csv) records exact
bytes for the picker normal modal route, its conditional mapping-row/profile
save follow-up, row-state/invalidation helper, guarded semaphore notifier,
shared queue worker, and shared throw stub, plus the two initial object
images, both dialog RTTI tables, all nine absolute head-field loads, the
RTTI/vtable linkage, and the two relative calls to the text-macro writer. The
verifier also checks the throw-object RTTI and relevant IAT imports. The
[verifier](../scripts/audit_rk46_textmacro_list_lifecycle.py)
pins the executable size and SHA-256 before checking the bytes and censuses.

```powershell
python scripts/audit_rk46_textmacro_list_lifecycle.py --binary ..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe --out docs/rk-v4.6-textmacro-list-lifecycle.csv
```

All work was static. The binary was not executed, the RK application was not
launched, and no keyboard, HID, updater, or firmware interface was opened.

## Remaining questions

- What semantic object type each list payload represents and whether all
  active mapping/profile objects are represented.
- Whether the initializer's zero-return branch executes in an actual process
  and what `0x00448880` initializes.
- Whether higher-level exception recovery or the `0x0041EC50` parent handler
  reach a `textmacro.dct` writer beyond the bounded traces, and whether
  cleared records later appear in a `textmacro.dct` write.
- Which exact user actions select each cleanup branch and what runtime objects
  are active.
