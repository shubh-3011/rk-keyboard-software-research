# RK 4.06 `VirtualFree` reservation lifecycle

## Scope and exact input

This static follow-up traces the installed 4.06 `DeviceDriver.exe` import
`KERNEL32!VirtualFree` from its IAT load through both calls, and joins those
calls to the adjacent reservation and commit code. The installed file and the
analysis snapshot were both read and had size 2,326,528 bytes and SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
The binary was not run. No HID interface, keyboard report, serial port,
updater, or bootloader was accessed.

## Why this row was selected

The existing [4.06 import-gap revalidation](rk-406-native-api-gap-revalidation-follow-up.md)
already records `VirtualFree` as one register-indirect import row, and the
[general indirect-call inventory](rk-native-api-indirect-call-audit.md)
lists its two `call ESI` instructions. Neither report recovers the API
arguments, allocation provenance, or the condition for releasing the larger
reservation. The reports named `VirtualFree` elsewhere concern other package
files or the 4.6 build, so they do not answer this 4.06 path.

## Recovered static path

The import is at IAT VA `0x0059E268`. Helper entry `0x0057939E` loads that
slot into `ESI` at `0x005795CF`, then calls through `ESI` at `0x005795E7` and
conditionally at `0x00579642`. Its three statically recovered direct callers
are `0x0056E799`, `0x00570C99`, and `0x00570CE6`; their higher-level purposes
are not attributed here.

The calls participate in a reserve/commit/decommit lifecycle:

1. **Reserve:** the descriptor-growth path at `0x005796B4` allocates a
   `0x41C4`-byte metadata block through `HeapAlloc`. It then calls
   `VirtualAlloc` at `0x0057972B` with `(lpAddress=NULL, dwSize=0x100000,
   flAllocationType=0x2000, flProtect=0x04)`. The returned base is stored in
   descriptor field `+0x0C`; descriptor field `+0x08` is initialized to
   `0xFFFFFFFF`.
2. **Commit a segment:** helper `0x00579764`, called directly from `0x00579C25`,
   computes `reservationBase + (segmentIndex << 15)` and calls `VirtualAlloc`
   at `0x005797B8` with `dwSize=0x8000`, `MEM_COMMIT=0x1000`, and
   `PAGE_READWRITE=0x04`. On the success path it clears the selected bit in
   descriptor field `+0x08` at `0x00579862`.
3. **Decommit a segment:** in helper `0x0057939E`, the first `VirtualFree`
   receives `lpAddress = reservationBase + (segmentIndex << 15)`,
   `dwSize=0x8000`, and `dwFreeType=0x4000` (`MEM_DECOMMIT`). The helper then
   sets that segment's descriptor bit at `0x005795FB`.
4. **Release the reservation:** the helper compares descriptor field `+0x08`
   with `0xFFFFFFFF` at `0x00579636`. If it is not all ones, the branch skips
   the second call. If all bits are set, it calls `VirtualFree` at
   `0x00579642` with `(lpAddress=descriptor[+0x0C], dwSize=0,
   dwFreeType=0x8000/MEM_RELEASE)`. It then calls `HeapFree` for the associated
   metadata pointer at descriptor field `+0x10`.

The 1 MiB reservation and 32 KiB stride imply 32 segment slots. The bitmap is
initialized to all ones, a bit is cleared on segment commit, and set again on
segment decommit. Therefore, an all-ones bitmap is consistent with every
segment having been decommitted before the full reservation release. Windows
documents `MEM_DECOMMIT` as returning committed pages to the reserved state;
for `MEM_RELEASE`, `dwSize` must be zero and `lpAddress` must be the original
reservation base ([`VirtualFree`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree)).
`VirtualAlloc` documents the separate reserve and commit states
([`VirtualAlloc`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)).

## Evidence and confidence

- **Proven statically:** exact binary identity; import-table IAT VAs for
  `VirtualFree`, `VirtualAlloc`, and the related heap APIs; instruction bytes;
  the two register-indirect transfer sites; the call arguments encoded by the
  surrounding pushes; the direct helper calls; the reservation-base store;
  and the bitmap branch/update sequence. The row-level ledger records 44
  address-bound byte facts in
  [`rk-406-virtualfree-reservation-lifecycle-evidence-2026-10-25.csv`](rk-406-virtualfree-reservation-lifecycle-evidence-2026-10-25.csv).
- **Inferred:** this code implements a host-side virtual-memory arena or
  allocator with 32 KiB segments and a 1 MiB reservation. The interpretation
  follows the matching reserve/commit/decommit/release arguments and bitmap
  flow; no symbol names identify the allocator.
- **Unresolved:** whether the helper or any branch ran on this PC; the owning
  application component and user-visible feature; all callers beyond the
  three decoded direct calls; whether each `VirtualFree`/`VirtualAlloc` call
  succeeds; and the broader allocator's complete control-flow and concurrency
  behavior. Both `VirtualFree` return values are overwritten before a result
  check in the shown code. This path says nothing about firmware readback or
  device behavior.

## Reproduction

Run the verifier from the repository root:

```powershell
python scripts/audit_rk406_virtualfree_lifecycle.py --binary ..\_rk_analysis\inputs\DeviceDriver.exe
```

The script verifies the SHA-256 and size, checks the PE import addresses,
compares all 44 ledger byte sequences, checks the relative call destinations,
and regenerates the evidence CSV. It reads the binary as data only; it does not
launch it or access a device.
