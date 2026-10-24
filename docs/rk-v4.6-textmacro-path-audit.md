# RK DeviceDriver.exe 4.6 text-macro persistence path audit

## Scope and safety

Static-only follow-up for the 4.6-labeled `DeviceDriver.exe` with SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
The executable was not run. No RK application was launched, and no keyboard,
HID, or updater API was invoked. This report describes this binary only; it
does not establish that these paths are reachable on a particular RK model.

The companion [`rk-v4.6-textmacro-path-evidence.csv`](rk-v4.6-textmacro-path-evidence.csv)
indexes the principal code references. VAs below use the PE preferred base
`0x00400000`.

The [2026-10-22 command bridge](rk-v4.6-textmacro-command-bridge.md) now
maps the picker save command and one welcome-dialog selection-change path.
It narrows the older UI/event gaps below without proving runtime delivery or
all callers.

## Proven statically

### Path formation and local file operations

The UTF-16 format literal at `0x005CFD8C` is `%s%04X\\%s`; the UTF-16 leaf at
`0x005D50F0` is `textmacro.dct`. Both helpers (`0x0041F540` and `0x004597E0`)
pass these values to the internal bounded wide-string formatter at
`0x00575B4E` (which delegates to `0x00575846`). They pass output limits
`0x104` and `0x103` and reserve a `0x210`-byte local path buffer. The format
therefore describes a wide path assembled from a base string, a four-digit
hexadecimal value, a backslash, and `textmacro.dct`. The base pointer is
`0x006352B0`, which lies in the `.data` virtual-only tail and has no initialized
bytes in the file. Static setup code at `0x00453220` formats this global from
`CSIDL_LOCAL_APPDATA` and the configured `appdir`. The package's
`app/Cfg.ini` contains `[OPT] appdir=RKKB`. If the startup reader selects that
package config, the intended path shape is
`%LOCALAPPDATA%\RKKB\<four-hex-value>\textmacro.dct`. The runtime call,
absolute config path, actual per-user directory, and configured value on any
installed system were not observed.

At `0x0041F59A`, `CreateFileW` is called with `GENERIC_READ | GENERIC_WRITE`,
share mode `3`, `CREATE_ALWAYS`, and `FILE_ATTRIBUTE_NORMAL`. If the handle is
valid, `WriteFile` at `0x0041F5C1` receives buffer `0x0060D3C4` and byte count
`0xC8C8`; the handle is then closed. This is a host-side local-file write path
and its open mode would create or truncate the selected file if the function
runs.

At `0x0045983A`, the other helper opens the constructed path with
`GENERIC_READ`, share mode `1`, `OPEN_EXISTING`, and `FILE_ATTRIBUTE_NORMAL`.
`ReadFile` at `0x00459861` reads `0xC8C8` bytes into the same buffer and the
handle is closed. The shown code checks for an invalid handle before these
calls; it does not visibly branch on the `ReadFile`/`WriteFile` Boolean result
or validate the transferred-byte count in these helper bodies.

### Buffer and record layout

The storage span is `[0x0060D3C4, 0x00619C8C)`, exactly `0xC8C8` bytes. The
record lookup routine at `0x0041F480` starts at `0x0060D3C4`, advances by
`0x404`, and stops at `0x00619C8C`, giving 50 fixed records. It compares the
first DWORD in each record with the requested key. When allocating a slot, the
routine packs metadata into that first DWORD (`0x0041F4F1`–`0x0041F52A`).

Each record is `0x404` bytes: a 4-byte key/metadata word followed by `0x400`
bytes of text storage. At `0x004215B7`–`0x004215D3`, a record returned by
`0x0041F480` is passed from offset `+4` to the internal copy routine
`0x00575E47` with a limit of `0x200`. That routine copies 16-bit units and
writes a 16-bit terminator, supporting a 512-WCHAR text field. The arithmetic
matches the persisted length: `50 * (4 + 512 * 2) = 0xC8C8`.

The complete span is passed directly to `ReadFile` and `WriteFile`; no
per-record transform or version/header step is visible between the calls and
the buffer. Thus the observed implementation persists a fixed-size raw memory
image of these records. Exact field semantics within the packed first DWORD,
compatibility/version behavior, and whether stale/partial files are handled
elsewhere remain unresolved. A separate [record-reclamation trace]
(rk-v4.6-textmacro-record-reclamation.md) maps how the driver scans mapping
cells for the `0x0A00005B` tag/key pair and zero-fills a `0x404`-byte record
when the examined linked-list cells contain no reference. Runtime execution,
list identity, and persistence of the cleared table remain unobserved.

### Call paths and feature gate

The write helper `0x0041F540` has two direct relative callers in the decoded
image: `0x004215DE` and `0x0045A057`. The read helper `0x004597E0` is directly
called at `0x0045A0EE`. Both latter calls are in the same routine beginning at
`0x00459F50`, and are each preceded by a check of global byte `0x0062B8B3`.

The profile loader calls `GetPrivateProfileStringW` through its IAT at
`0x00454A06`, using the key string `ShowTextMacro` at `0x005DF1B0`; the returned
value is stored in `0x0062B8B3` at `0x00454A17`. This establishes a static
configuration gate for the write/read branch, not a user-visible toggle's
reachability or runtime effect.

The routine at `0x00459F50` is itself directly called from `0x0045C620` and
`0x0046C211`. Both callsites supply a 16-bit value read from offset `0x24E` of
a model/device-associated object (the first has a fallback global value).
This is consistent with the `%04X` path component, but the exact type and
meaning of that value are inferred from use, not proven by symbols.

The other write caller is inside the large routine beginning at `0x00421350`.
Its branch at `0x00421596` looks up a record, copies its text field, then calls
the persistence helper. The follow-up identifies this as `CKeyFunPickDlg`'s
`WM_COMMAND` virtual override: it matches the sender HWND of an embedded
`CPngBtn`, then state `5` reads non-empty text, updates the record, and saves.
The sender uses the caption descriptor associated with `tc_apply` (English
`Apply`); its actual runtime caption and the state-`5` option label remain
unobserved.

The same follow-up maps `0x0046C211` to `CWelcomDlg`'s command override. It
matches one of ten child HWNDs, selects a device-associated holder, and
forwards its identifier to `0x00459F50`. The examined change branch gates
old-partition save and new-partition load through `ShowTextMacro` state.

## Inferred

- `CTextMacroBuffer` RTTI at RVA `0x21A198`, the 50-record structure, the
  `ShowTextMacro` profile key, and the file leaf together indicate host-side
  persistence for the text-macro feature.
- The `%04X` path component likely partitions this file by model/device
  identifier. The two callers of `0x00459F50` pass values from model/device
  objects, but runtime path strings were not observed.
- The record/persistence path is now statically linked to a picker command;
  the displayed state-`5` option and exact user interaction remain unresolved.

## Unresolved

- Which absolute `cfg.ini` path and `appdir` value the runtime selects,
  whether the startup path builder executes successfully, and the concrete
  per-user path at runtime.
- The full caller/event ownership of setup helper `0x0045A950`, which contains
  the other call at `0x0045C620`; alternate callers, runtime notification
  delivery, complete selection-lifecycle timing, and actual user interaction.
  The follow-up proves the selected virtual command paths for `0x00421350`
  and `0x0046C211` plus their calls into the persistence routines.
- Exact record key bit meanings, payload text encoding beyond 16-bit WCHAR
  copies, null/partial-file recovery, and any version migration.
- The state-`5` option label, complete editor behavior, physical key meaning,
  and active runtime profile. A follow-up now maps the static device-report
  route through private message `0x07EB`, the `0x0A00005B` mapping-cell gate,
  non-allocating record lookup, and host `SendInput`; exact report semantics,
  message delivery, and user gesture remain unobserved. See the
  [device-trigger audit](rk-v4.6-textmacro-device-trigger.md). This does not
  establish firmware storage or provide a firmware backup method.

