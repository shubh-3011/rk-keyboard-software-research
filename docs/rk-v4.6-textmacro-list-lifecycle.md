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
direct file-writer call. The first-use MFC helper's normal TLS setup and
per-thread object creation are now mapped; its exceptional path and parent
modal-result handling remain open, so this does not rule out every later
persistence route.

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
| `0x0041D0A4` | The handler can call `0x0041EC50` after cleanup; depending on profile-state branches, it can reach `0x00460DA0` or `0x0041F1A9`, both host `pro.dct` persistence paths. | This is profile-file persistence, not `textmacro.dct`; runtime guards and indirect paths remain unobserved. |
| `0x00421640` | The cleanup gate requires picker state not equal to `5`. The direct `textmacro.dct` writer call at `0x004215DE` belongs to the state-5 save branch, which skips cleanup. Both paths converge on the virtual call at `0x00421650`. | Local save and cleanup branches are mutually exclusive. The shared slot resolves to a dialog-close path, with MFC guard and parent modal-result paths still open. |

The `textmacro.dct` writer at `0x0041F540` has two direct callers in the
examined executable: `0x004215DE` and `0x0045A057`. This static direct-call
census does not prove a complete interprocedural call graph. The current
evidence therefore shows no direct write of the reclaimed buffer on the
cleanup branches or within the resolved dialog-close target. It cannot exclude
persistence reached through the first-use helper's unresolved lazy callback,
exception handling, parent modal-result processing, or a caller outside the
bounded paths.

### Picker virtual tail

The call at `0x00421650` loads slot `+0x158` through the `CKeyFunPickDlg`
vtable (`0x005D530C`); that slot points to `0x00480C2C`. This method calls
`0x0047C312` with value `1`; a nonzero result reaches `0x00480C02` with modal
result `1`. For this class, the helper's slot `+0xFC` target is `0x00405770`,
a `ret 4`. The close helper can call slot `+0x8C` (`0x0047C6A1`), which stores
the result and conditionally calls `USER32!PostMessageW`; it then calls
`USER32!EndDialog` through IAT slot `0x005A65C0`. No direct text-macro writer
or save/load wrapper call occurs in these resolved methods.

The normal exception-frame epilogue restores the saved frame and returns, but
the exceptional continuation is not semantically mapped. Parent handling
after `EndDialog` is also outside this local method trace. Thus this closes the
immediate virtual target, not every deferred or exceptional route.

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
trace. That observation does not classify later methods reached through the
new object's vtable, the MFC/SEH exceptional continuations, other callsites of
the helper, or the parent dialog's modal-result handling. It therefore closes
the lazy callback's basic initialization mechanics, not the full picker
behavior or every possible persistence route.

## Evidence and reproduction

The [instruction ledger](rk-v4.6-textmacro-list-lifecycle.csv) records exact
bytes for 114 instructions, the two initial object images, both dialog RTTI
tables, all nine absolute head-field loads, the RTTI/vtable linkage, and the
two relative calls to the text-macro writer. The
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
- Whether the exceptional continuation or parent modal-result handling can
  reach a persistence writer, and whether cleared records later appear in a
  `textmacro.dct` write.
- Which exact user actions select each cleanup branch and what runtime objects
  are active.
