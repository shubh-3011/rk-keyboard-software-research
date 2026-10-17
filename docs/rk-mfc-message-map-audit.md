# Recovered MFC message-map arrays

This audit decodes the recovered MFC `AFX_MSGMAP_ENTRY` arrays in the
installed `DeviceDriver.exe` 4.06 image, SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
It does not run the vendor software, open a HID handle, or send reports.

The starting owner ledger has 30 candidate blocks. Several blocks share the
same map descriptor and entry array, so the parser deduplicates those to 26
unique arrays. Each record is six DWORDs (24 bytes): message, code, first ID,
last ID, signature, and handler VA. Arrays end at an all-zero sentinel. The
hash-pinned binary contains 291 non-sentinel entries across the 26 recovered
arrays: 144 entries have message `0x0111` (`WM_COMMAND`) and 147 carry other
message IDs. The normalized
[`rk-mfc-message-map-entries.csv`](rk-mfc-message-map-entries.csv) preserves
the raw fields and owner evidence for every decoded row.

This is the complete inventory of the 26 recovered arrays, not proof that all
MFC maps or runtime dispatch routes in the executable have been discovered.
The earlier
[`rk-mfc-command-map-candidates.csv`](rk-mfc-command-map-candidates.csv)
contains a narrower 112-row extraction: it selects `WM_COMMAND` rows with
signature `0x39` and equal first/last IDs. The full arrays include additional
command signatures/ranges, so the two CSV files answer different questions.

## RK application-owned arrays

Four arrays are attributed by the RTTI-backed owner evidence to RK application
classes. Together they contain 36 entries: six `WM_COMMAND` entries and 30
other messages.

| Owner | Entries | `WM_COMMAND` | Other messages | Evidence |
| --- | ---: | ---: | ---: | --- |
| `CMacroDlg` | 13 | 2 | 11 | `0x005CD498`–`0x005CD5B8` |
| `CScreenDlg` | 7 | 1 | 6 | `0x005DA458`–`0x005DA4E8` |
| `COemDrvApp` | 1 | 1 | 0 | `0x005D4870` |
| `COemDrvDlg` | 15 | 2 | 13 | `0x005D4B90`–`0x005D4CE0` |

The other recovered maps belong to MFC framework or generic classes. Their
entries are included in the CSV but are not evidence of RK keyboard features.
Two candidate blocks have inherited/shared-getter owner ambiguity, as recorded
in [`rk-mfc-map-owner-evidence.csv`](rk-mfc-map-owner-evidence.csv).

## Device notifications and timer routes

The `COemDrvDlg` array has a concrete `WM_DEVICECHANGE` entry at row VA
`0x005D4C50`: message `0x0219`, signature `0x0E`, handler `0x00447580`.
The entry begins five bytes before the decompiler's function body label
`FUN_00447591`; disassembly confirms the MFC thunk/prologue enters the same
handler. It processes arrival (`0x8000`) and removal (`0x8004`) events,
parses interface paths and profile/VID/PID data, logs IN/OUT, and schedules
timers `0x844` and `0x845` before follow-up processing at `0x00446EE0`.
This resolves the previously open static message-map edge. It does not show
that registration succeeded or that an event occurred on the audited PC.
See the [HID enumeration and notification audit](rk-device-enumeration-notification-audit.md)
for the surrounding device logic.

The same `COemDrvDlg` map has a `WM_TIMER` row at `0x005D4C98` targeting
`0x00447710`. Its branches compare the timer ID with dialog retry state at
`this+0x120C` and with `0x845`; the former path calls device/profile helpers,
updates retry state at `this+0x1208`, and kills its timer, while the latter
kills its timer and calls `0x004360D0`. The handler also refreshes UI through
`0x00475257`. Exact runtime timing and which branch occurs are not observed.

The `CScreenDlg` map has a `WM_TIMER` row at `0x005DA4E8` targeting
`0x0046D570`. For timer `0x900`, the handler calls `KillTimer`, sets dialog
field `this+0x10C` to one, and calls UI refresh `0x00475257`. The semantic
meaning of that state field is not established.

The other app-owned non-command handlers include paint, erase-background,
mouse, private messages `0x040A`, `0x0477`, `0x046C`, `0x07EB`, and help or
session-end messages. Their raw target and signature values are available in
the CSV; a handler target alone does not identify a visible control or a
keyboard operation.

## Reproduction

With Python 3.10 or later and the same installed 4.06 binary:

```powershell
python scripts/audit_mfc_message_maps.py `
  --pe "C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe" `
  --output docs/rk-mfc-message-map-entries.csv
```

The script checks the expected SHA-256 before parsing PE32 section mappings,
validates the all-zero terminator for each recovered array, and checks that
each handler VA belongs to an executable section. The expected hash can be
overridden explicitly for a separately documented binary snapshot.
