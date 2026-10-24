# R99 CH375 read/write IOCTL call-path follow-up — 2026-10-25

## Scope and pinned input

This bounded static follow-up examines the R99 package's app-shipped
`CH375DLL.DLL`, extending the direct-IAT candidate inventory in the
[R99 native API boundary audit](rk-r99-native-api-boundary-audit-2026-10-19.md).
The extracted DLL is the R99 package's `app/CH375DLL.DLL`, size 23,584 bytes,
SHA-256
`a7d5acb61f0d4b0ccbc5b045c1cdf01146cfdaacff23f3931459f17ecd85f571`.
It is x86, image base `0x00400000`; `.text` starts at VA `0x00401000` and
file offset `0x400`. No application, installer, updater, driver, HID
interface, or keyboard was run or contacted.

## Newly resolved imported-call edges

The existing [R99 import-call ledger](rk-r99-native-api-callsite-candidates.csv)
contains 30 direct `call [IAT]` candidates for
`KERNEL32!DeviceIoControl` in this DLL. A separate instruction-level check
finds two more calls in the exported `CH375WriteRead` function:

| Call VA | Import-pointer load | Transfer | Edge |
|---|---|---|---|
| `0x00401B35` | `0x00401B19: mov esi, dword ptr [0x00401014]` | `call esi` | `KERNEL32!DeviceIoControl` |
| `0x00401B6C` | same load at `0x00401B19` | `call esi` | `KERNEL32!DeviceIoControl` |

`0x00401014` is the DLL's `DeviceIoControl` IAT slot in the hash-pinned import
table. Between the load and the first call, and between the two calls, the
function does not overwrite `ESI`. This closes these two specific register-
indirect edges omitted by the direct-IAT ledger. They are in the same
`CH375WriteRead` export, not separate callers. The ledger's 30 remains the
direct-call count; the bounded total established here is at least 32 call
instructions to this import in this DLL.

## Request and response shape in three data exports

The named export RVAs and instructions below are from the same image. The
buffer is passed as both input and output, consistent with the METHOD_BUFFERED
IOCTL declared by `0x00223CDC`; this describes only the caller-side contract.

| Export | Function VA and call VA(s) | Static request construction | Static response handling |
|---|---|---|---|
| `CH375ReadData` | `0x004017E4`; call `0x00401882` | At `0x00401840`, store operation dword `6` at buffer `+0`; at `0x00401856`, store the requested byte count at `+4`. Payload begins at `+8`. The DLL raises the requested payload length to at least `0x40` and caps it at `0x400000`. For lengths above `0x400`, it requests a `0x400008`-byte temporary allocation; if that fails, it uses a `0x400`-byte local buffer and sets capacity to `0x400`. `DeviceIoControl` receives input length `8`, output length request+8, and the same buffer pointer for both. | On success, read response length from `+4`, clamp it to the caller capacity, copy that many bytes from `+8` to the caller's output, and update the caller length. Return value is a boolean-shaped `0`/`1` path. |
| `CH375WriteData` | `0x0040194C`; call `0x00401A0F` | At `0x004019C0`, store operation `7` at `+0`; at `0x004019C6`, store payload length at `+4`; copy payload to `+8`. The DLL caps length at `0x400000`. For lengths above `0x400`, it requests a `0x400008`-byte temporary allocation; if that fails, it uses a `0x400`-byte local buffer and sets capacity to `0x400`. Input length is payload+8; output length is 8; same buffer for input/output. | On success, copy the returned dword at `+4` back to the caller's length pointer; return value is boolean-shaped. |
| `CH375WriteRead` | `0x00401AC9`; calls `0x00401B35` and `0x00401B6C` | First construct operation `7` at `+0`, copy the caller's payload, and cap its length at `0x40`. The first buffered request uses the same input/output buffer and payload+8 lengths. After success, replace the header with operation `6`, request length `0x40`, and total buffer length `0x48`, then issue the second IOCTL. | On second-call success, read returned length from `+4`, clamp to `0x40`, and copy from `+8` to the caller's output. Failure returns zero and clears the output length. |

These are exact per-export buffer operations in the old app-shipped helper.
The values `6` and `7` are proven operation fields in this build; interpreting
them as device-side read/write semantics is supported by export names and the
distinct request/copy directions, but actual driver handling and runtime
effect are not observed here.

## Evidence and limits

- **Proven statically:** the pinned DLL imports `DeviceIoControl` at IAT VA
  `0x00401014`; the two `CH375WriteRead` register calls receive that pointer;
  `CH375ReadData`, `CH375WriteData`, and `CH375WriteRead` construct the
  operation/length headers and use the buffer shapes listed above.
- **Inferred:** operation fields `6` and `7` correspond to read and write
  operations based on the exported names and the observed data flow.
- **Unresolved:** driver version paired with this 2022 DLL, operation behavior
  below the user-mode `DeviceIoControl` boundary, device acceptance, return
  values at runtime, and full reachability from UI/model-selection paths.

The separate 2023 archived `CH375WDM.sys` audit describes the same IOCTL and a
kernel request header, but it is a different package/version evidence set.
This follow-up does not claim that driver is the implementation paired with
this DLL, nor that these calls target the user's S98. It also does not resolve
the remaining imported API paths or all register-indirect calls in the R99
package.
