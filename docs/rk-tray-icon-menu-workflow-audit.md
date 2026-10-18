# RK tray icon and application command workflow audit

## Scope and evidence

This follow-up traces the installed 4.06 main executable's tray callback to
the localized context-menu entries and the two `COemDrvDlg` command handlers.
The executable is the same hash-pinned `DeviceDriver.exe` described in the
UI crosswalk: SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
Evidence is from its x86 disassembly/import table, recovered MFC map, and the
installed English locale XML. The application was not launched; no device
interface was opened and no keyboard report or command was sent.

## Tray callback and menu construction

The `COemDrvDlg` message-map row at `0x005D4C08` routes message `0x046C` to
`0x00447D60`. The tray-icon setup code at `0x00447CA0` stores `0x046C` in
the notification structure's callback-message field at object offset
`+0x6A8`, stores its window handle at `+0x69C`, and calls the imported
`Shell_NotifyIconW` with operation `0` (`NIM_ADD`). This ties message `0x046C`
to the application's shell tray-icon callback.

The callback at `0x00447D60` branches on the callback's mouse event value:

| Event value | Static path | Result |
| ---: | --- | --- |
| `0x0203` (`WM_LBUTTONDBLCLK`) | Calls `0x00446770` directly. | Opens or foregrounds the main Configuration window. |
| `0x0205` (`WM_RBUTTONUP`) | Creates a popup menu, iterates a 10-row text table at `0x00612B90` with stride `0x78`, appends those entries, then appends the two localized application actions and calls `TrackPopupMenu`. | Selection dispatches a `WM_COMMAND` to the tray window. The generated entries' exact labels and meaning remain unresolved. |

The two localized command entries are recovered as follows:

| Command ID | Menu text slot | Localization key and English value | Handler | Static result |
| ---: | --- | --- | --- | --- |
| `0x6400` | global string slot `0x0062B494` | `tc_config` — “Configuration” | `0x00446770` | Brings the existing app window forward or initializes/shows it. |
| `0x6401` | global string slot `0x0062B498` | `tc_exit` — “Exit” | `0x00446820` | Closes helper windows; under the profile-state guard it persists `pro.dct`/`curid.dct` and signals the per-device system-parameter worker event. A separate global-flag branch sleeps 2 seconds and sends `WM_CLOSE` to the dialog. The handler does not directly call `PostQuitMessage`; final process-exit behavior is not established by this path. |

The label mapping is supported by the string-registration code: the key
`tc_config` is at `0x005D3C88` and is registered into slot 3 / pointer slot
`0x0062B494` at `0x00442029`–`0x00442037`; `tc_exit` is at
`0x005D3C9C` and is registered into slot 5 / pointer slot `0x0062B498` at
`0x00442092`–`0x004420A8`. The English XML maps those keys to “Configuration”
and “Exit” at `Text/en/text.xml` lines 4–5. The menu appends these slots with
IDs `0x6400` and `0x6401` in `0x00447E57`–`0x00447E94`; the adjacent imports
resolve to `AppendMenuW` and `TrackPopupMenu`. The `COemDrvDlg` map rows at
`0x005D4C20` and `0x005D4C38` route those IDs to the handlers listed above.

## Interpretation and limits

This resolves the origin and user-facing labels of commands `0x6400` and
`0x6401`: they are tray-menu commands, not unidentified keyboard feature
buttons. `0x6400` is also reached directly by tray-icon double-click. The
`0x6401` handler's recovered device-node event is a shutdown signal for the
periodic `SendSysParam` worker; this handler does not call the reset helper
or establish a reset/factory-restore action. A separate flag-gated branch
sends `WM_CLOSE` to the dialog, but this pass does not establish when or
whether the main process exits. Its persisted `.dct` data schemas and whether
an in-flight family operation completes before the worker exits remain
unresolved.

This finding does not bridge any General Settings label to its generated
control or profile field. It also does not connect `tc_msg2`–`tc_msg6` reset
prompts to a confirmation handler or reset command. The reset prompts,
settings-control mappings, and feature-page command paths listed as open in
the [UI control crosswalk](rk-ui-control-command-crosswalk.md) remain open.

## Reproduction references

- Message-map evidence: `docs/rk-mfc-message-map-entries.csv`, owner
  `COemDrvDlg`, entries `0x005D4C08`, `0x005D4C20`, and `0x005D4C38`.
- Dialog callback and context-menu paths: `DeviceDriver.exe` at
  `0x00447CA0`–`0x00447D5B` and `0x00447D60`–`0x00447F18`.
- Localized action registration: `0x00442029`–`0x004420A8`, strings at
  `0x005D3C88` / `0x005D3C9C`.
- English strings: installed `Text/en/text.xml`, lines 4–5.
- API imports: `Shell_NotifyIconW`, `AppendMenuW`, `TrackPopupMenu`,
  `PostMessageW`, and `SetForegroundWindow` in `DeviceDriver.exe`.
