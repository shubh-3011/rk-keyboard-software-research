# RK 4.6 temporary-handle cache lifecycle

## Scope and result

This 2026-10-22 static follow-up maps two cleanup paths for the temporary files
previously traced in the
[native API audit](rk-v4.6-native-api-call-path-audit.md). The registry at
`0x0061DD54` is RTTI-identified `CMenuHash`, and its handle values are closed
by a single-key release routine or a separate bulk loop reached from an
application message-loop termination path. The registered global destructor
clears storage without the handle-closing loop.

The exact 2,418,176-byte input is the separately extracted RK 4.6
`DeviceDriver.exe`, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
It was read and disassembled; no target executable, Windows API, or device
operation was invoked. Addresses are preferred-image virtual addresses.

The [47-instruction ledger](rk-v4.6-temp-registry-lifecycle.csv),
[selected failure-path ledger](rk-v4.6-temp-registry-failure-path.csv), and
[verifier](../scripts/audit_rk46_temp_registry_lifecycle.py) reproduce the
selected bytes, imported targets, RTTI, vtable, MFC, and branch relationships.
They do not prove runtime execution, success, or complete graph coverage.

## Cache identity and ownership

`CMenuHash` has vptr `0x005B2FEC`, COL `0x005E7ABC`, and TypeDescriptor
`0x00608F8C` (`.?AVCMenuHash@@`). Its embedded map at object `+4` has vptr
`0x005B2FDC`, COL `0x005E7A70`, and descriptor `0x00608F58`. The raw type
name is `.?AV?$CMap@PAUHMENU__@@AAPAU1@PAXAAPAX@@`: a menu-handle-keyed map
with pointer-sized values. The factory's value is a raw file handle, as
shown by its `CreateFileW` producer and subsequent `CloseHandle` consumers.

Initializer `0x005A497B` selects global `0x0061DD54` and calls constructor
`0x004DC09B`. It registers callback `0x005A57E9` through helper `0x00576041`.
The callback tail-jumps to `0x004DC0B8`, which resets the object/map vptrs
and tail-jumps to storage cleanup `0x004F7C07`.

Storage cleanup walks bucket/node links, frees the bucket allocation through
`0x00477060`, and releases pool-chain blocks through `0x004B2846`. These
reviewed storage routines do not call `CloseHandle` on values. Handle cleanup
must therefore be distinguished from merely destroying the map.

## Single-key release and a concrete UI caller

Routine `0x004DC28B` selects the embedded map, looks up the supplied key using
`0x004A1617`, and receives the mapped handle in `[ebp-4]`. When found, it
passes that handle to `CloseHandle` at `0x004DC2AF`, then calls map removal
`0x004DC115` at `0x004DC2BB`. The close result is not tested before removal.
No matching entry returns zero; a found entry returns one after removal.

The map-removal helper unlinks the node at `0x004DC16B` and passes it to
`0x004DCDA6`, which updates the count/free list. This is separate from the
explicit close of its value.

The MFC row at `0x005C3580` maps `WM_COMMAND` (`0x0111`), ID `0x40F0`, to
`0x0055181F` in `CMFCToolBarsMenuPropertyPage`. In this handler's examined
branch, `EDI` is checked with `IsMenu`, passed as the key to the global
cache's single-key release at `0x00551A41`, then passed to `DestroyMenu` at
`0x00551A47`. This ties the cache cleanup to host toolbar/menu customization.
The visible command label and actual event delivery remain unobserved.

## Bulk release through the application loop's exit branch

Routine `0x004DC0CC` checks the map count, then iterates using
`0x004DBF94`. The iterator reads node `+4` and copies it to the third output
argument, `[ebp-8]` in the caller. That value is passed to `CloseHandle` at
`0x004DC0FD`. The loop repeats while its position token remains nonzero,
then clears map storage through `0x004F7C07`. Close results are not checked.

There is a concrete static application path into this loop:

```text
COemDrvApp object 0x00647908; vptr 0x005DCFBC
  virtual +0x54 -> 0x00486EA8 -> loop 0x00489643
  loop virtual +0x5C -> 0x00489B3A -> 0x0048994B
  GetMessageW at 0x0048995F returns zero on the selected path
  loop branch 0x004896A4 -> virtual +0x68 at 0x004896CF
  app +0x68 -> 0x00448530 -> 0x004878BF -> 0x00490589
  ECX = global CMenuHash 0x0061DD54
  0x00490598 -> bulk release 0x004DC0CC
```

Initializer `0x005A3E71` installs this app vptr at the global object. RTTI
COL `0x005ED640` links to descriptor `0x0061A3F0`, naming `COemDrvApp`.
The zero-return message branch reaches the cleanup virtual without invoking
the intervening nonzero-result dispatch branch. This closes the static
normal-cleanup gap for this application path. It does not prove that the
installed app actually follows it, that every exit route does so, or that
each close succeeds.

## Replacement failure: retained closed-handle value candidate

Factory `0x004DC2CC` first looks up the existing menu key. Lookup copies the
node's value into a local and does not remove it. If found, the factory calls
`CloseHandle` on the old value at `0x004DC30C`, before attempting the new
temporary file through `CreateFileW` at `0x004DC380`.

If the new call returns `INVALID_HANDLE_VALUE`, branch `0x004DC38E` goes to
`0x004DC485`, destroys two temporary strings, sets the return value to zero,
and exits. It bypasses the map-value address acquisition at `0x004DC40A`
and new-handle store at `0x004DC415`. No key erase/reset is visible on this
selected local failure path. The prior close result is also unchecked.

**Conditional inference:** if the old close succeeds, the new open fails,
and no other actor changes the map, its entry retains the numeric value of
the closed handle. A subsequent release/replacement could then attempt to
close that stored value again. Handle reuse, an actual failing open, and
downstream consequences were not observed. This is a static lifecycle
candidate, not a confirmed runtime fault.

The 72-instruction witness selects a nonzero second-object `+0xB10` field,
a found cache entry, and a failed replacement open. The first helper
`0x0049C242` only returns that field; it does not validate the pointer or type.
Calls are atomic fall-through edges in that
intraprocedural witness: their complete side effects, exceptions, and
concurrency are not simulated. The witness must not be treated as a complete
symbolic execution or proof that all helper calls preserve global state.

## Reproduction and remaining limits

```powershell
python scripts/audit_rk46_temp_registry_lifecycle.py --binary .research/rk46-extract-full/app/DeviceDriver.exe --out docs/rk-v4.6-temp-registry-lifecycle.csv --witness-out docs/rk-v4.6-temp-registry-failure-path.csv
```

Proven static facts are the imported close/create/message/menu APIs, selected
caller/virtual-map bridges, byte-guarded close/remove/iterate operations, and
the local failure branch that bypasses cache replacement. The complete
serialized byte stream, all callers/exit routes, actual handle lifetimes,
API outcomes, and any concurrent mutation remain unresolved. This cache
stores host menu customization state; the traced paths provide no keyboard
firmware-readback or full firmware-copy method.
