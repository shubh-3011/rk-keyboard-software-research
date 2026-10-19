# 4.06 uninstaller named-pipe helper audit

This is a static call-path audit of the installed RK 4.06 `unins000.exe`. It
resolves the `CreateNamedPipeW`, `SetNamedPipeHandleState`, and
`TransactNamedPipe` imports to an Inno Setup 64-bit helper-process channel.
Neither the uninstaller nor the RK application was run, and no keyboard or
device interface was accessed.

## Artifact and method

The 1,316,301-byte input is `unins000.exe`, SHA-256
`b4ca28b192d5a50307d2b28f3323b58b39cb51edd6682e75706cac2dd69a4a14`. The
hash matches both the installed Program Files copy and the package-matched
research input. Addresses in the first part below are image virtual addresses
in this x86 PE.

The executable contains two complete helper PEs as `RT_RCDATA` (resource type
10), language 1033:

| Resource | Size | Resource RVA / file offset | SHA-256 | PE machine |
| --- | ---: | --- | --- | ---: |
| `HELPER_EXE_AMD64` | 6,144 bytes | `0x149078` / `0x12EA78` | `a4c86fc4836ac728d7bd96e7915090fd59521a9e74f1d06ef8e5a47c8695fd81` | `0x8664` (AMD64) |
| `HELPER_EXE_IA64` | 9,216 bytes | `0x14A878` / `0x130278` | `0c98ee5b35f10abe94148460ab4993101fcdb3d5a9e7bde17252e619953d8f7e` | `0x0200` (IA-64) |

Both bounded resource ranges begin with `MZ`, contain a PE signature at offset
`0xD8`, and match the extracted analysis copies byte-for-byte. The following
helper-code findings are from static disassembly of the AMD64 resource only;
the IA-64 image is identified and hashed but its handler code was not
disassembled in this addendum. No helper or parent process was run.

## Recovered pipe setup

The three named-pipe imports each have one xref in the uninstaller:

| API | Import thunk | Callsite | Static role |
| --- | ---: | ---: | --- |
| `CreateNamedPipeW` | `0x00408F88` | `0x004B1956` | Creates the helper channel's server end. |
| `SetNamedPipeHandleState` | `0x0040930C` | `0x004B19E5` | Sets the separately opened client end to message-read mode. |
| `TransactNamedPipe` | `0x0040933C` | `0x004B2186` | Sends one request and receives its reply through the server end. |

The setup routine starts at `0x004B185C`. It builds this UTF-16 pipe-name
format string at `0x004B1C94`:

```text
\\.\pipe\InnoSetup64BitHelper-%.8x-%.8x-%.8x-%.8x%.8x
```

The five eight-digit fields are populated from the current process ID, an
incremented process-local counter, `GetTickCount`, and the two DWORD halves of
`QueryPerformanceCounter` (with `GetSystemTimeAsFileTime` as the fallback when
the performance-counter call fails). This makes a per-process instance name;
the exact uniqueness guarantee is not tested.

At `0x004B1956`, the stack arguments to `CreateNamedPipeW` resolve to:

| Parameter | Value | Interpretation |
| --- | ---: | --- |
| `dwOpenMode` | `0x40080003` | Duplex, overlapped, first pipe instance. |
| `dwPipeMode` | `0x00000006` | Message-type and message-read mode; wait mode is the zero default. |
| `nMaxInstances` | `1` | One instance. |
| Input/output buffers | `0x2000` / `0x2000` | 8 KiB each. |
| Default timeout | `0` | Zero default-timeout argument. |
| Security attributes | `NULL` | No explicit server-side structure. |

The same constructed name is then passed to `CreateFileW` at `0x004B19AC`,
with `GENERIC_READ | GENERIC_WRITE`, share mode zero, and
`OPEN_EXISTING`. Its static `SECURITY_ATTRIBUTES` structure at `0x004FC31C`
has `nLength=12`, a null security descriptor, and nonzero `bInheritHandle`.
This opens the client end as inheritable. `SetNamedPipeHandleState` at
`0x004B19E5` receives mode `2` (`PIPE_READMODE_MESSAGE`) for that client
handle.

The routine then calls `CreateProcessW` at `0x004B1A8E`. The application-name
argument is the extracted-helper path held at global `0x00502ACC`; the
command-line format string at `0x004B1D98` is `helper %d 0x%x`, formatted with
the constant `0x69` and the client pipe handle. `bInheritHandles` is true and
the creation-flags argument is `0x0C000000`. The associated strings include
“Starting 64-bit helper process.” and “64-bit helper EXE wasn't extracted.”
The parent keeps the overlapped server handle and records it in its helper
state; requests below use that handle. This is a local process-to-process
channel, not a keyboard HID path.

## Message framing visible at the caller

The request routine begins at `0x004B20CC`. Its caller supplies the operation
in `EDX` and payload length in `ECX`. The routine increments a sequence
counter, then stores these values at offsets `+0x20`, `+0x24`, and `+0x28` in
the helper state. It passes `state+0x20` to `TransactNamedPipe` with an input
length of `0x0C + payload_length`. The AMD64 helper reads into a buffer at
`0x140013220`, requires at least 12 bytes, and checks that the declared payload
length equals bytes-read minus 12. The observed request frame is:

```text
u32 sequence | u32 operation | u32 payload_length | payload bytes
```

The call uses a local overlapped structure and a 20-byte response buffer at
`state+0x4034`. The parent requires at least 16 returned bytes, checks that the
reply sequence matches the request, rejects a zero DWORD at
`state+0x4038`, and checks that `returned_bytes - 16` equals the expected
reply-data length stored at `state+0x4040`.

The AMD64 helper constructs a 16-byte reply at `0x140003210`: sequence at
`+0`, an operation-dependent field at `+4`, a second result field at `+8`, and
a trailing-data length at `+12`. It initializes the latter three fields to
zero and writes exactly `16 + trailing_data_length` bytes; the examined
handlers leave the trailing-data length zero. Operation 1 sets the `+4` field
to 1. Operation 2 writes its Win32 return code at `+8` and leaves `+4` zero.
Operation 4 writes its helper result at `+4`. These are observed field uses;
the project-specific names for the two result fields are not present in the
binary.

The AMD64 helper's command-line parser requires three arguments, validates
the decimal selector `0x69`, parses the third argument as a 64-bit handle, and
uses that handle in `ReadFile` / `WriteFile` calls. The selector matches the
parent's `helper %d 0x%x` command line. This confirms the named-pipe handle is
the helper's IPC endpoint in the embedded code.

The AMD64 helper dispatches three operations visible in the code:

| Operation | Required payload | Static handler behavior |
| ---: | ---: | --- |
| `1` | Parent sends an empty payload during helper setup. | Acknowledgment path; sets reply field `+4` to 1. |
| `2` | `0x228C` bytes | Updates a named object's DACL using `GetNamedSecurityInfoW`, `SetEntriesInAclW`, and `SetNamedSecurityInfoW`. Payload begins with object type, count (bounded to 32), and inheritance flags; a UTF-16 object path begins at offset 12. The 32-record array begins at payload offset `0x200C`; each 20-byte record carries a six-byte SID identifier authority, subauthority count, two subauthority DWORDs, and an access-mask DWORD. |
| `4` | `0x2004` bytes | Reads an action DWORD followed by a UTF-16 type-library path. It calls `LoadTypeLib`; action zero selects `RegisterTypeLib`, while nonzero obtains the library attributes and calls `UnRegisterTypeLib`. The reply `+4` status distinguishes the load, register, attribute-query, and unregister stages (1–4); `+8` carries the HRESULT/result. |

The x86 parent has matching callsites: operation `2` with length `0x228C`
(`0x004B2680`) and operation `4` with length `0x2004` (`0x004B2766`). The
operation-2 payload layout also matches the parent builder: it copies a
count-dependent array of 20-byte entries after the fixed `0x2000`-byte path
area. The operation names above describe the embedded helper's static code;
they do not establish that a given handler ran during uninstall.

## Findings and limits

### Proven

- All three named-pipe imports in this exact uninstaller resolve to the
  `InnoSetup64BitHelper` channel described above.
- The parent creates a message-mode overlapped server pipe, opens an
  inheritable client end, launches the extracted helper with that client
  handle, and exchanges request/reply messages on the server handle.
- The request has a 12-byte sequence/operation/length prefix. The reply
  is 16 bytes for the examined handlers and includes the matching sequence.
- The AMD64 helper resource is embedded in the exact uninstaller and is
  byte-bounded and hash-identified. Its operation-2 DACL path and operation-4
  type-library path are visible in the helper's static code and match the
  parent's operation IDs and fixed payload lengths.
- The PE is the Inno Setup 5.3.4 uninstaller engine identified by the package
  audit; this call path is in `unins000.exe`, not `DeviceDriver.exe`.

### Inferred

- The pipe implements generic Inno Setup 32-bit-to-64-bit helper IPC for
  host-side security and type-library operations. The helper name,
  process-launch messages, and helper API calls support this interpretation.
- The pipe does not represent communication with an RK keyboard. The audited
  calls are confined to the generic uninstaller helper path; the uninstaller
  import inventory has no HID or SetupAPI APIs.

### Unresolved

- The parent validates a nonzero reply DWORD at `state+0x4038` for every
  request, but the AMD64 helper's operation-2 handler leaves the corresponding
  reply field at `+4` zero and stores the DACL API return code at `+8`. The
  operation-2 caller later reads `state+0x403C` as its result, but the shared
  request routine's zero-field check precedes that return. This static
  disagreement means successful end-to-end operation-2 behavior is
  unresolved without executing the path.
- Operation-2/4 input layouts and the AMD64 helper's output writes are visible
  statically, but actual path strings, ACL record values, action values,
  runtime replies, and which requests are sent during uninstall are not
  recoverable from static callsites alone.
- The IA-64 resource is hash-identified but its handler logic has not been
  disassembled here. The AMD64 reply fields are described by their offsets
  and use sites; higher-level field names remain unknown.
- Static references do not establish whether this helper path runs during a
  real uninstall, which requests it sends, or what host state those requests
  change.

## Related reports

- [Main reverse-engineering report](reverse-engineering.md)
- [Installer/uninstaller script audit](rk-installer-uninstaller-script-audit.md)
- [System API and static call crosswalk](rk-system-api-crosswalk.md)
- [Native API imports](rk-native-api-imports.md)
- [Native API IAT references](rk-native-api-xrefs.csv)
