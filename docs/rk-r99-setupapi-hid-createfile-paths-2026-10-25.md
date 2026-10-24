# R99 SetupAPI/HID `CreateFileA` paths — 2026-10-25

## Scope and identity

This report expands the two SetupAPI/HID `CreateFileA` callsites left outside
the earlier R99 CH375 trace. The target is the extracted R99 `RK Driver.exe`
at `C:\Users\shubh\Downloads\sshorcale\.research\rk-selector-software-2026-10-19\R99-Inno-extracted\app\RK Driver.exe`, SHA-256
`61dd118400a4652ba053db6ceb87cdd865e183f59822948ea9018da218aec2e5`. The
executable was not launched. No HID interface was opened and no keyboard
report, updater, or bootloader operation was performed.

The hash-pinned verifier is
[`audit_r99_setupapi_hid_createfile_paths.py`](../scripts/audit_r99_setupapi_hid_createfile_paths.py).
The generated, instruction-level evidence ledger is
[`rk-r99-setupapi-hid-createfile-paths-2026-10-25.csv`](rk-r99-setupapi-hid-createfile-paths-2026-10-25.csv).
Reproduce it from the research checkout with:

```powershell
python scripts\audit_r99_setupapi_hid_createfile_paths.py `
  --binary '..\.research\rk-selector-software-2026-10-19\R99-Inno-extracted\app\RK Driver.exe'
```

The verifier confirmed the pinned digest, import table, exact `CreateFileA`
callsite census, selected-path opener caller census, and each listed code
landmark before writing the ledger.

## Callsite overview

The R99 executable has three direct calls through its sole `CreateFileA` IAT
slot: `0x0041AED9` (the previously documented CH375 path), `0x00475020`, and
`0x00475358`. This report traces the latter two. The first is an ephemeral HID
interface discovery/metadata probe. The second takes a discovered path,
creates a persistent overlapped-I/O context, and is followed by report
read/write helpers.

## Path 1: SetupAPI interface discovery and metadata probe (`0x00475020`)

### Path source and enumeration

At `0x00474E2D`–`0x00474E55`, the function constructs GUID
`{4D1E55B2-F16F-11CF-88CB-001111000030}`, the HID device-interface GUID. It
passes flags `0x12` (`DIGCF_PRESENT | DIGCF_DEVICEINTERFACE`) to
`SetupDiGetClassDevsA` at `0x00474ED6`, then calls
`SetupDiEnumDeviceInterfaces` at `0x00474EF5`. The loop increments the
interface member index and repeats at `0x0047521A` until SetupAPI reports the
end of the list.

For each interface, the code loads `SetupDiGetDeviceInterfaceDetailA` from its
IAT at `0x00474F03`. It first calls the function with a null detail buffer to
obtain the required size (`0x00474F24`), allocates that amount, writes the
x86 detail-structure size value `5` (`0x00474F37`), and calls again to fill the
detail data (`0x00474F4F`). The `CreateFileA` filename expression is that
detail-buffer pointer plus four bytes (`0x0047501A`), the x86
`SP_DEVICE_INTERFACE_DETAIL_DATA_A.DevicePath` offset.

The same function separately enumerates `SP_DEVINFO_DATA` records and queries
registry properties. It compares property 7 with the embedded string
`HIDClass`, then requests property 9 before it reaches the open. These
device-info queries are separate from the interface-detail path acquisition;
static evidence does not establish that each queried record is paired with
the precise interface path passed to `CreateFileA`.

### `CreateFileA` arguments and result handling

At `0x00475020`, the pushed arguments are:

| Parameter | Value |
|---|---|
| `lpFileName` | `SP_DEVICE_INTERFACE_DETAIL_DATA_A.DevicePath` (`detail_buffer + 4`) |
| `dwDesiredAccess` | `0` |
| `dwShareMode` | `3` (`FILE_SHARE_READ | FILE_SHARE_WRITE`) |
| `lpSecurityAttributes` | `NULL` |
| `dwCreationDisposition` | `3` (`OPEN_EXISTING`) |
| `dwFlagsAndAttributes` | `0x40000000` (`FILE_FLAG_OVERLAPPED`) |
| `hTemplateFile` | `NULL` |

The return is checked against `INVALID_HANDLE_VALUE` at `0x0047502C`. The
failure branch skips the HID metadata calls and reaches the common
`CloseHandle` site at `0x004751E2`, so that branch also passes the invalid
sentinel to `CloseHandle`. No runtime failure was induced; the result or
effect of this call is unknown.

On the success path the function calls dynamically resolved
`HidD_GetAttributes` with an initialized 12-byte attributes structure. This
call's return value is not tested in the local block. It then obtains HID
preparsed data, calls `HidP_GetCaps`, accepts only status `0x00110000`, and
frees the preparsed data. The same path queries a product string. The
temporary file handle is closed on the common path, the detail buffer is
freed, and `SetupDiDestroyDeviceInfoList` is called when enumeration ends.

The HID names are resolved at runtime: the executable loads embedded name
`hid.dll` with `LoadLibraryA`, then calls `GetProcAddress` for strings
including `HidD_GetAttributes`, `HidD_GetPreparsedData`, `HidD_FreePreparsedData`,
and `HidP_GetCaps`. These are string-based resolution findings, not static
HID.DLL import declarations.

The enumeration code copies the device path into a returned node whose first
field is the path pointer. This relationship is supported by the path-copy
sequence following the open and by the selected-path callers loading `[esi]`.
The report does not claim that a particular node represented the physical
S98 attached to this PC.

## Path 2: selected-path connection object (`0x00475358`)

The opener starts at `0x00475290` and receives its path in `ECX`. There are 14
direct callers in this image; the verifier checks all 14 callsites and
confirms each passes `[esi]` in `ECX`, the first field of a node returned by
the enumerator described above. The callers test model/device descriptor
fields before opening; for example, the scanner near `0x00474020` compares
vendor/product and HID capability fields. These filters do not identify the
connected physical keyboard without runtime evidence.

The function allocates a zeroed `0x38`-byte context and creates an unnamed
event, saved at context offset `+0x34`. It then calls `CreateFileA` at
`0x00475358`:

| Parameter | Value |
|---|---|
| `lpFileName` | input path from `ECX` |
| `dwDesiredAccess` | `0xC0000000` (`GENERIC_READ | GENERIC_WRITE`) |
| `dwShareMode` | `3` (`FILE_SHARE_READ | FILE_SHARE_WRITE`) |
| `lpSecurityAttributes` | `NULL` |
| `dwCreationDisposition` | `3` (`OPEN_EXISTING`) |
| `dwFlagsAndAttributes` | `0x40000000` (`FILE_FLAG_OVERLAPPED`) |
| `hTemplateFile` | `NULL` |

The returned handle is stored at context offset zero and checked against
`INVALID_HANDLE_VALUE`. Open or HID-capability failures call the error-message
formatter and enter failure cleanup. That cleanup closes the event and file
handle, releases a `LocalFree`-managed diagnostic string and input buffer, and
frees the context. On success, the function obtains preparsed data, requires
successful `HidP_GetCaps`, frees the preparsed data, copies input/output/
feature report lengths from the caps structure into context offsets `+0x0C`,
`+0x08`, and `+0x10`, allocates an input-report buffer, and returns the
context pointer.

### Bounded downstream report I/O and teardown

The same executable has 14 direct callers of the write helper at `0x00475430`
and 12 direct callers of the read helper at `0x00475510`. The static census
shows the selected-path context is used beyond setup:

- The write helper calls `WriteFile` with the context handle, a report buffer,
  the output-report length at `context+0x08`, and an `OVERLAPPED` structure.
  If the requested payload is shorter than the report size, it allocates a
  temporary buffer and pads the remainder with zeros. It treats error 997
  (`ERROR_IO_PENDING`) as pending I/O and waits with `GetOverlappedResult`.
- The read helper uses the input-report length at `context+0x0C`, the input
  buffer at `context+0x20`, and an `OVERLAPPED` structure. It resets the
  context event before `ReadFile`, handles pending completion with
  `GetOverlappedResult`, and contains a branch that skips a leading zero
  report-ID byte when copying input to the caller. These are code-path facts;
  no report was sent or received in this analysis.
- The owner stores the returned context at `owner+0x414`. Its teardown path
  calls `CancelIo` on the context handle, closes the event and file handles,
  releases the diagnostic string and input buffer, and frees the context.

The event is created and separately reset by the read helper. The static
trace does not establish whether that event is assigned to the
`OVERLAPPED.hEvent` field or what runtime completion ordering occurs.

## Evidence boundary

**Proven statically:** both `CreateFileA` sites and exact pushed arguments;
HID interface GUID/flags; SetupAPI interface-detail path source; local handle
checks and cleanup; dynamic HID export resolution; the second open's 14
direct callers; its HID-capability fields; direct `ReadFile`/`WriteFile`
helper behavior; and an owner teardown path that closes the persistent
context.

**Inferred:** the first call is a short-lived HID metadata probe, while the
second establishes the persistent interface handle used for report I/O. The
name and call sequence support that intended role, but neither call's runtime
success is observed.

**Unresolved:** which enumerated path corresponds to any currently attached
keyboard; whether a discovered model's path is successfully opened; whether
the S98 uses these HID routes or the separate CH375 route; runtime
`ReadFile`/`WriteFile` results and report contents; the semantics of the
higher-level report payloads; exact pairing between the separately enumerated
device-info records and interface paths; and the success-path teardown timing
for any particular device session.

This is a static trace of two R99 application call paths, not a complete
device-family protocol map or a claim about the current S98.
