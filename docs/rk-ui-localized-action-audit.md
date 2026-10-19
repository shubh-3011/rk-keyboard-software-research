# RK localized macro and screen UI event audit

## Scope and evidence identity

This is a static, offline UI trace for the installed RK package at
`C:\Program Files (x86)\RK Keyboard Software`. Its `Cfg.ini` reports
`Ver=0x406` and has SHA-256
`1a9796e706fa64b1821417efda080d481e202ffcf941aa97e6a78efe3a32badd`.
The installed `DeviceDriver.exe` is version `1.0.6.8`, SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`,
and matches `_rk_analysis/inputs/DeviceDriver.exe`. The English locale source
`Text/en/text.xml` has SHA-256
`85b26e0c7cd8317adeb136d37b6877601b0c3e7f6fb072867f937aa46c73de8c`.

Analysis used the installed XML, PE resource/message-map evidence, and
disassembly of the hash-matched executable. No RK executable was run, no
keyboard was accessed, and no keyboard command was sent. The XML has seven
locale siblings and the package-level audit recovers 247 intended UI keys per
locale; Japanese has the already documented malformed `tc_screen1` closing
token. The installed dialog templates are generic/empty MFC shells; the PE has
no `RT_MENU` resource. This is consistent with the recovered runtime control
creation, but does
not by itself prove which locale key is assigned to which control.

## Proven UI-to-control evidence

| Surface | Proven resource and construction path | Proven message/handler path | What the handler does |
| --- | --- | --- | --- |
| Macro editor numeric edit `0x0107` | Macro construction at `0x004284A4` passes control ID `0x0107`, style `0x50802000`, and the parent to wrapper `0x0047AC48`; it stores the returned control wrapper at `CMacroDlg+0x2FA0`. The wrapper uses the static class string `EDIT` at `0x005CD458` and calls a CWnd-like vtable entry at `+0x54`. | `CMacroDlg` map entry `0x005CD558` (`WM_COMMAND`, code `0x0300`/`EN_CHANGE`, ID `0x0107`) points to `0x0042B3B0`. | Reads the numeric edit; accepts 1 through global `DAT_611FEC`, resets other values to 1, formats the warning `Loop Count = 1 ~ %d`, and marks a state bit via `0x0042CC20`. The owner/meaning of the dirty-state object is not recovered. |
| Macro editor numeric edit `0x0117` | Construction at `0x00428065` passes ID `0x0117`, style `0x50802000`, and parent to `0x0047AC48`; stores the wrapper at `CMacroDlg+0x2FA8`. | `CMacroDlg` map entry `0x005CD570` (`WM_COMMAND`, code `0x0300`/`EN_CHANGE`, ID `0x0117`) points to `0x0042B530`. | Reads the edit, clamps to 1–1,048,575, and moves the caret to the end. The numeric domain is proven; the specific setting label is not. |
| Macro editor edit `0x0108` | Construction at `0x00427BD9` passes ID `0x0108`, style `0x50800000`, and parent to `0x0047AC48`; it stores the wrapper at `CMacroDlg+0x2FA4`. Unlike the sibling numeric controls created with style `0x50802000`, this style does not include `ES_NUMBER` (`0x2000`). | The macro event/list path at `0x00428829`–`0x004288EC` reaches the field only when the selected-record state at `this+0x1860` is active. At `0x00428891`, it fetches the edit text through `0x004769C2`, passes the text-derived value to the one-argument routine at `0x0056F224`, and treats the return as an integer. It then calls `0x0042C8E0` with subtype `3` and that integer. The subtype-3 branch at `0x0042C98B` formats it with `%d` (`0x005C8828`) and continues through shared helper `0x0045C8B0`. | **Proven:** the edit supplies an integer-valued parameter for a selected subtype-3 macro event record. The exact record field and user-visible label are not named in the binary. The owner-level helper at `0x0042B030` separately filters notification code `1` for child IDs `0x0107`, `0x0108`, and `0x0109`, then invokes two virtual methods; its virtual targets and notification meaning remain unresolved. No `EN_CHANGE`/`WM_COMMAND` row for ID `0x0108` appears in `CMacroDlg`'s map at `0x005CD498`–`0x005CD5D0`. |
| Screen editor numeric edit `0x0107` | Construction at `0x0046C000` passes ID `0x0107`, style `0x50802000`, and parent to `0x0047AC48`; stores wrapper at `CScreenDlg+0x1FFC`. It formats the current value at `this+0x114` using `%d` (UTF-16 string at `0x005C8828`) and sets that text in the edit. | `CScreenDlg` map entry `0x005DA4D0` (`WM_COMMAND`, code `0x0300`/`EN_CHANGE`, ID `0x0107`) points to `0x0046C5B0`. | Clamps the numeric value to at most 65,535 and stores it at `this+0x114`. The XML key that names this field is not identified. |

The `CMacroDlg` map at `0x005CD498` also contains owner-level message handlers
for `0x000F`, `0x0014`, `0x0019`, `0x040A`, `0x0594`, `0x0592`, `0x0591`,
`0x0595`, `0x0477`, `0x0201`, and `0x0053`. The `CScreenDlg` map at
`0x005DA458` contains handlers for `0x0014`, `0x000F`, `0x0201`, `0x0800`,
`0x0477`, and timer message `0x0113`. These rows establish app-owned event
targets, but their event IDs do not identify their visible translated labels.
The complete map owner chains and raw command candidates are in
[`rk-mfc-map-owner-evidence.csv`](rk-mfc-map-owner-evidence.csv) and
[`rk-mfc-command-map-candidates.csv`](rk-mfc-command-map-candidates.csv).

## Inferred label-to-field matches

| Locale key and English text | Candidate control/handler | Basis and confidence |
| --- | --- | --- |
| `tc_macro_loop1` = “Cycles”; `tc_macro_msg22` = “Number of cycles” | Macro edit ID `0x0107`, handler `0x0042B3B0` | Handler name string `Loop Count = 1 ~ %d` and the 1-to-global-bound validation strongly suggest a cycle-count input. **Inferred, high semantic fit; exact XML key binding is not proven.** |
| `tc_macro_loop2` = “Default Delay”; `tc_macro_loop3` = “Fixed Delay” | Macro edit ID `0x0117`, handler `0x0042B530` | Handler clamps a numeric value to 1–1,048,575. A delay is a plausible interpretation, but the clamp does not distinguish these labels or rule out another numeric field. **Inferred, low-to-moderate confidence.** |
| `tc_screen16` = “Playback interval(ms)”; `tc_screen11` = “Screen size” | Screen edit ID `0x0107`, handler `0x0046C5B0` | The edit is initialized from `this+0x114` and the handler caps it at 65,535. Both labels describe numeric settings, but no text/key lookup or drawing path proves either binding. **Candidate labels only.** |
| `tc_macro_msg15` = “Please enter the delay”; `tc_macro_msg16` = “Delay” | Macro edit ID `0x0108`, selected subtype-3 event row | The edit value is converted to an integer and formatted as decimal on the subtype-3 event-row path. A per-event delay fits the locale vocabulary and macro event model; the `0x0108` field is not linked to either XML key by a recovered lookup or control-label call. **Inferred, moderate semantic fit; exact key and whether the integer is milliseconds remain unresolved.** `tc_macro_msg14` (“Please enter the keys”) is a weaker match because this observed path parses an integer. |

The rest of the English macro keys are present directly in the external XML:
`tc_macro_stop`/`tc_macro_start` (recording state), `tc_macro_list` and
`tc_macro_key_list` (macro/event lists), `tc_macro_auto` (recording delay),
`tc_macro_loop` (insert-event prompt), `tc_macro_msg1`–`tc_macro_msg21`, and
`tc_macro_msg23`–`tc_macro_msg24`. Those message keys include New, Import,
Export, Rename, Delete, Insert, Keyboard, Mouse Events, Save, prompts and
warnings, and repeat-until-key-pressed/released choices. Their exact control
IDs/handlers were not recovered.

The 21 English screen keys are `tc_screen1` crop instruction, `tc_screen2`
drag/zoom instruction, `tc_screen3` frame-limit prompt, `tc_screen4` preview,
`tc_screen5` frame list, `tc_screen6` apply to all frames, `tc_screen7` Load,
`tc_screen8` Add Layer, `tc_screen9` Save, `tc_screen10` Undo,
`tc_screen11` Screen size, `tc_screen12` Apply, `tc_screen13` frame-limit
warning, `tc_screen14` New, `tc_screen15` Import, `tc_screen16` Playback
interval, `tc_screen17` pause-first prompt, `tc_screen18` frames,
`tc_screen19` USB-only transfer warning, and `tc_screen20`/`tc_screen21`
Left/Right. These XML values do not map in the current evidence to screen
control IDs or action handlers. The existing
[`rk-localization-key-matrix.csv`](rk-localization-key-matrix.csv) and
[`rk-resource-localization-audit.md`](rk-resource-localization-audit.md)
retain all seven locale variants and the complete key inventory.

## Unresolved UI/control crosswalk

| Gap | Evidence limit |
| --- | --- |
| Exact `tc_macro_*` key-to-ID mapping, including the choice between cycle-count and delay labels | External XML leaf keys are not PE resource IDs. The app dialog templates do not contain feature controls, and no direct key-to-control string cross-reference was recovered. The XML loader may construct key names or select them indirectly. |
| Exact user action and localized key for macro edit ID `0x0108` | The selected subtype-3 macro-row path reads the text, converts it to an integer, and passes it into the event-row update helper. The XML contains delay labels but has no statically recovered control binding; `0x0042B030` exposes virtual callbacks whose targets and notification meaning are unresolved. The exact field semantics (including units) are therefore still inferred. |
| Macro control behavior for IDs `0x0105`, `0x0106`, `0x0109` and localized action buttons | Some IDs appear in nearby macro code and the `0x0042B030` checks `0x0109`, but this trace does not establish a key-to-control binding or action semantics for each. |
| Exact binding of any `tc_screen*` key to `CScreenDlg` IDs/events | The screen map and numeric edit are proven, but no button/menu/action ID could be joined to `tc_screen1`–`tc_screen21`. Screen artwork or GIF processing does not supply that UI crosswalk. |
| Complete form construction and virtual/reflected event graph | This pass traced the numeric edits and one owner-level ID filter. It did not recover all custom control classes, callback tables, label draw calls, dynamically generated menus, or every path through macro/screen child views. |

The xref scan in `_rk_analysis/reports/device-string-xrefs.txt` contains no
literal `tc_macro_*`, `tc_screen*`, or `text.xml` tokens. Because locale
strings are external XML and can be fetched through constructed keys or
generic lookup helpers, this absence is only a limit of the current static
string scan; it does not prove that the app ignores the XML.

## Device discovery and timer context

These related timer findings are included to anchor the UI map against the
separately recovered device-discovery path:

| Owner/event | Exact static path | Established behavior and limit |
| --- | --- | --- |
| `COemDrvDlg` device-change | Map row `0x005D4C50`: `WM_DEVICECHANGE` (`0x0219`) → `0x00447580`. Handler parses device paths and VID/PID data through `0x00447B20`; classifier `0x004474D0` checks supported families including VID `258A` PIDs `30`, `148`, `150`, and `1BB`, then consults the table at `0x006102B0`. | Local PnP discovery/refresh path is proven statically. Logs include `OnDeviceChange: Device %04x_%04x %s` at `0x005D5070` and `IN`/`OUT` strings at `0x005D505C`/`0x005D5064`. This does not establish successful runtime connection or downstream write behavior. |
| `COemDrvDlg` discovery timers | In the same handler, arrival/removal event values `0x8000`/`0x8004` lead to timers `844` at 2,000 ms and `845` at 500 ms and state fields `this+0x120C`/`+0x1208`; map row `0x005D4C98` sends `WM_TIMER` (`0x0113`) to `0x00447710`. | Timer handler retries helper paths, kills the timer, can signal the event at `this+0x1210`, and dispatches through `0x00475257`. Exact runtime timing, active-device outcome, and later keyboard operation are unobserved. |
| `CScreenDlg` timer | Map row `0x005DA4E8`: `WM_TIMER` (`0x0113`) → `0x0046D570`. In the state-switch block at `0x00459125`–`0x004592F6`, the incoming state is checked against `1`–`8`; the final case compares it with `8`, and, if the child object at parent offset `+0xE68` exists, calls `0x0046D500(TRUE)` at `0x004592C3`–`0x004592CE`. | Helper `0x0046D500` uses `this+0x200C` as a gate: for a true argument and nonzero gate it calls `SetTimer(hwnd=this+0x20, id=0x900, interval=0x2BC, callback=NULL)`; it then invalidates the window with erase enabled. The false-argument path snapshots `this+0x10C` to `this+0x200C`, clears `this+0x10C`, and invalidates. On timer ID `0x900`, handler `0x0046D570` kills that timer, sets `this+0x10C=1`, then calls `0x00475257`. **Proven:** a 700 ms timer is armed from state-switch case 8 and later restores a screen-dialog state before refresh. **Inferred:** state 8 is a screen child/page selection. The exact user-facing label, initiating control, and XML key are not recovered; no direct XML key-to-control binding was recovered in this timer path. |

The device-change path is based on the `COemDrvDlg` map and handlers at
`0x00447580`, `0x00447710`, and their callees. It is evidence of local Windows
device discovery and deferred refresh, not a measurement of connection speed
or proof that every RK model is recognized.

## Evidence limits

All handler, map, and dynamic-control claims above are static observations
from the version/hash-pinned artifacts. XML labels and message-map rows are
directly observed; the candidate key-to-control relationships are labeled as
inferences. The document does not claim complete reverse engineering of every
dialog, localized key, callback, API, device family, or runtime branch. It
does not report any live keyboard interaction.
