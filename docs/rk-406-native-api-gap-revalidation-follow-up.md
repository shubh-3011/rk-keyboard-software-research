# RK 4.06 DeviceDriver import-gap revalidation

## Scope and pinned input

This static-only follow-up rechecks the 32 `DeviceDriver.exe` rows in
[`rk-native-api-callsite-gaps.csv`](rk-native-api-callsite-gaps.csv). The input
is the installed RK 4.06 image at
`C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe`, also present
as `_rk_analysis/inputs/DeviceDriver.exe`:

| Size | SHA-256 | Architecture |
|---:|---|---|
| 2,326,528 bytes | `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6` | x86 PE |

The installed executable and analysis copy match the documented hash. The
application and updater were not launched. No HID interface, report, serial
port, firmware writer, or bootloader was accessed.

## Existing coverage checked first

The earlier [indirect-import audit](rk-native-api-indirect-call-audit.md)
already mapped all 32 rows: 30 through register-indirect API calls and two
through IAT tail-jump wrappers. Its summary listed 77 register-indirect call
instructions. The [device-enumeration and notification audit](rk-device-enumeration-notification-audit.md)
provides the deeper SetupAPI and hot-plug call paths. This follow-up therefore
does not repeat their higher-level feature analysis; it revalidates the IAT
references and transfer instructions and records omissions found in the prior
callsite list.

## Revalidation method

The hash-pinned `.text` section was disassembled offline and checked against the
IAT RVAs in the gap ledger. Absolute little-endian references to all 32 IAT
slot VAs were also searched across the whole PE. Each byte-hit count agrees
with the ledger. For register-indirect calls, a call was attributed to an
import when its register value is statically loaded from that import's IAT
slot. The `SetupDiGetDeviceInterfaceDetailW` path was checked across its
conditional branch in disassembly because a single linear register scan misses
the second call on the other branch.

The machine-readable [32-row revalidation table](rk-406-native-api-gap-revalidation.csv)
records the IAT VA, reference locations, transfer instructions or wrapper
callers, and disposition for each row. It includes the previously documented
sites plus the three newly confirmed call instructions.

## Findings

All 32 rows have a statically identifiable transfer path in this image. The
30 register-indirect rows contain **80** distinct `call reg` instructions,
not 77. The two remaining rows, `PostQuitMessage` and `OleFlushClipboard`,
use the previously documented IAT tail-jump wrappers; their paths are not
register-indirect calls.

Three call instructions were omitted from the earlier per-API address list:

| API | Newly confirmed call instruction | Static evidence |
|---|---:|---|
| `KERNEL32!ConvertDefaultLocale` | `0x0047F92E` | `ESI` was loaded from IAT VA `0x0059E32C` at `0x0047F8A8`; the value remains live at this indirect call on the nonzero branch. |
| `KERNEL32!ConvertDefaultLocale` | `0x0047F937` | Same reaching IAT load at `0x0047F8A8`; the call follows the first newly confirmed call without an `ESI` write. |
| `GDI32!RemoveFontResourceW` | `0x00454B0D` | `ESI` was loaded from IAT VA `0x0059E178` at `0x00454A78`; this is the fourth call through `ESI` before the function returns. |

For `ConvertDefaultLocale`, the audited call instructions are now
`0x0047F8D8`, `0x0047F8E6`, `0x0047F92E`, `0x0047F937`, `0x0047F9A0`, and
`0x0047F9A9`. The nearby call at `0x0047F950` was excluded: its control-flow
predecessor can bypass the `ConvertDefaultLocale` IAT load, and `ESI` then
still holds a different import loaded at `0x0047F860`.

For `RemoveFontResourceW`, the four call instructions are
`0x00454A86`, `0x00454AB3`, `0x00454AE0`, and `0x00454B0D`.

The exact-IAT-VA byte scan found no additional absolute references beyond the
locations in the gap ledger. The code references load the import pointer into
a register before one or more indirect calls; this explains why raw IAT
reference counts are smaller than call-instruction counts. The two wrapper
rows are already covered in the earlier audit: `PostQuitMessage` has a
conditional object callback followed by an IAT tail-jump, while
`OleFlushClipboard` has a conditionally reached IAT tail-jump.

## Evidence classification and limits

- **Proven statically:** all 32 imports have at least one static transfer path
  in the hash-pinned image; 80 register-indirect call instructions and two
  IAT tail-jump wrappers are identified across those rows. The three omitted
  call instructions are now included in the evidence table.
- **Inferred:** the recovered instruction sequences can reach the named APIs
  when their conditional branches and callers execute.
- **Unresolved:** runtime execution, branch reachability, API return values,
  and application-level effects. This audit does not establish that any API
  ran during a particular session or exhaust dynamically constructed pointers,
  external callers, or different software versions.

No findings prove an import is used at runtime merely because its static call
path exists. Conversely, the absence of additional absolute IAT-slot
references in this image does not prove absence of computed references.
