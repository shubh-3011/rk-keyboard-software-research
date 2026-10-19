# Recovered MFC message-map arrays

This audit decodes the recovered MFC `AFX_MSGMAP_ENTRY` arrays in the
installed `DeviceDriver.exe` 4.06 image, SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
It does not run the vendor software, open a HID handle, or send reports.

The initial owner ledger has 30 `WM_COMMAND`-derived candidate blocks. Several
blocks share the same map descriptor and entry array, so those candidates
deduplicate to 26 unique arrays. A separate RTTI-backed `CLedDlg` array
was then recovered from its virtual `GetMessageMap` slot, bringing the ledger
to 31 candidate blocks and 27 unique arrays. Each record is six DWORDs (24
bytes): message, code, first ID, last ID, signature, and handler VA. Arrays
end at an all-zero sentinel. The hash-pinned binary contains 305 non-sentinel
entries across the 27 recovered arrays: 144 entries have message `0x0111`
(`WM_COMMAND`) and 161 carry other message IDs. The normalized
[`rk-mfc-message-map-entries.csv`](rk-mfc-message-map-entries.csv) preserves
the raw fields and owner evidence for every decoded row.

This is the current inventory of the 27 recovered arrays, not proof that all
MFC maps or runtime dispatch routes in the executable have been discovered.
The earlier
[`rk-mfc-command-map-candidates.csv`](rk-mfc-command-map-candidates.csv)
contains a narrower 112-row extraction: it selects `WM_COMMAND` rows with
signature `0x39` and equal first/last IDs. The full arrays include additional
command signatures/ranges, so the two CSV files answer different questions.

## RK application-owned arrays

Five arrays are attributed by the RTTI-backed owner evidence to RK application
classes. Together they contain 50 entries: six `WM_COMMAND` entries and 44
other messages.

| Owner | Entries | `WM_COMMAND` | Other messages | Evidence |
| --- | ---: | ---: | ---: | --- |
| `CMacroDlg` | 13 | 2 | 11 | `0x005CD498`–`0x005CD5B8` |
| `CScreenDlg` | 7 | 1 | 6 | `0x005DA458`–`0x005DA4E8` |
| `CLedDlg` | 14 | 0 | 14 | `0x005CCFE8`–`0x005CD120` |
| `COemDrvApp` | 1 | 1 | 0 | `0x005D4870` |
| `COemDrvDlg` | 15 | 2 | 13 | `0x005D4B90`–`0x005D4CE0` |

The other recovered maps belong to MFC framework or generic classes. Their
entries are included in the CSV but are not evidence of RK keyboard features.
Two candidate blocks have inherited/shared-getter owner ambiguity, as recorded
in [`rk-mfc-map-owner-evidence.csv`](rk-mfc-map-owner-evidence.csv).

### `CLedDlg` message-map recovery

The `CLedDlg` array was missed by the original `WM_COMMAND`-shaped scan
because none of its 14 rows is a `WM_COMMAND`. Its six-DWORD entries begin at
`0x005CCFE8` and end at the all-zero sentinel at `0x005CD138`. The map
descriptor at `0x005CD150` contains base-map getter `0x00479866` and entries
pointer `0x005CCFE8`. Getter `0x004215E0` returns that descriptor from the
RTTI-backed `CLedDlg` vtable at `0x005CD2F4`; the same vtable's
`GetRuntimeClass` slot `0x004210B0` returns runtime-class descriptor
`0x005CCFCC`, whose name is `CLedDlg`. Its complete-object locator
`0x005E3DB0` points to type descriptor `0x0060384C`, named
`.?AVCLedDlg@@`. The base getter matches the separately recovered `CDialog`
map getter and descriptor (`0x00479866` -> `0x005A019C`). This is a static
owner chain; it does not observe MFC dispatch at runtime. A neighboring
`CAudioClient` RTTI block is a separate vtable; it is not the owner of this
map.

| Message | Handler | Map row | Static note |
| --- | --- | --- | --- |
| `WM_ERASEBKGND` (`0x0014`) | `0x0046ACB0` | `0x005CCFE8` | Shared MFC default-handler path. |
| `WM_PAINT` (`0x000F`) | `0x00421660` | `0x005CD000` | Paint routine that draws the localized `tc_adv_str1` “Light Brightness” string; see the [brightness UI audit](rk-lighting-brightness-ui-handler-audit.md). |
| Private message `0x0477` | `0x00425570` | `0x005CD018` | Message name and sender are unresolved. |
| Private message `0x0800` | `0x00422190` | `0x005CD030` | Calls formatter `0x00422220`, copies page state, and may signal the settings worker. Five literal `PostMessageW` send sites are recovered; the child control and `lParam` field meaning remain unresolved. |
| Private message `0x0801` | `0x00422220` | `0x005CD048` | Selector `0x95` reads the `LightUI` table. Four literal `PostMessageW` send sites are recovered; no static assignment proves their dynamic `lParam` fields contain `0x95`, and the child control remains unresolved. |
| Private message `0x0481` | `0x00422780` | `0x005CD060` | A position-selection producer posts it with `wParam` from `[ESI+0x80]`; handler toggles a per-position mapping record and signals Apply mode 4. Exact widget and value meaning remain unresolved. |
| Private message `0x0482` | `0x00422640` | `0x005CD078` | A selection-list producer posts it with zero parameters; handler applies the current mapping value to eligible selected positions and signals Apply mode 4. Exact widget and value meaning remain unresolved. |
| Private message `0x05C7` | `0x0040C840` | `0x005CD090` | Message purpose and sender are unresolved. |
| Private message `0x0594` | `0x00422430` | `0x005CD0A8` | Message purpose and sender are unresolved. |
| Private message `0x08B3` | `0x004251E0` | `0x005CD0C0` | Message purpose and sender are unresolved. |
| Private message `0x043E` | `0x0040C840` | `0x005CD0D8` | Shared handler; message purpose and sender are unresolved. |
| Private message `0x0461` | `0x00422580` | `0x005CD0F0` | Message purpose and sender are unresolved. |
| Private message `0x05D1` | `0x00422580` | `0x005CD108` | Shared handler; message purpose and sender are unresolved. |
| `WM_LBUTTONDOWN` (`0x0201`) | `0x00403AD0` | `0x005CD120` | Signature `0x35`; hit-test behavior was not analyzed in this pass. |

The `0x0800` and `0x0801` values above are message fields, not control IDs.
This resolves the earlier ambiguous `.rdata` block: function pointers
`0x00422190` and `0x00422220` are handlers in the `CLedDlg` map. Their literal
senders post through a parent-window wrapper; the likely `CLedDlg` parent
relationship is inferred, and the runtime HWND identity is not observed.
One construction path stores selector `0x95` at child-object offset `+0x9E0`,
and the `0x0800`/`0x0801` senders read that offset for `lParam`; see the
[selector-message sender follow-up](rk-led-selector-message-sender-followup.md).
The association between that constructed instance and a runtime sender call,
the particular brightness widget, and any path from a UI change to a specific
serializer remain unresolved.
The producer and state effects for messages `0x0481` and `0x0482` are traced
in the [key-position mapping follow-up](rk-led-key-position-message-followup.md);
their exact visible controls and runtime parent-window identity remain open.

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
