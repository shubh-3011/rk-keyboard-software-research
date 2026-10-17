# RK macro capture and editor event path audit

## Scope and evidence basis

This report examines the macro editor's input-related message handlers, event
list updates, dirty state, and local save routes in RK Keyboard Software 4.06.
It is a static analysis of the installed x86 PE snapshot. The application was
not launched, and no keyboard, HID, serial, or GATT interface was opened or
used.

| Artifact | SHA-256 | Evidence |
| --- | --- | --- |
| `DeviceDriver.exe` | `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6` | Exact immutable snapshot at `_rk_analysis/inputs/DeviceDriver.exe`; PE32, image base `0x00400000`, 2,326,528 bytes. |
| `rk-mfc-message-map-entries.csv` | Repository inventory | Recovered message-map rows and handlers for RTTI-attributed `CMacroDlg`. |
| `rk-native-api-xrefs.csv` | Repository inventory | Import-call references for hook and keyboard-state APIs. |

Addresses are image virtual addresses. Instruction checks used the package-
matched binary snapshot and x86 disassembly; message-map and import-reference
cross-checks used the repository's static Ghidra exports. The terms **direct**,
**candidate**, and **unresolved** distinguish instruction-level evidence from
an incomplete producer/call path.

## Findings

The image contains macro-editor handlers that inspect values corresponding to
Windows system-key messages, update editor-side event/list state, and set a
macro dirty bit. That establishes part of the editor event route. It does not
establish how physical keyboard input reaches those handlers, how an input is
turned into the eight-byte event-row representation, or whether these
particular notifications implement the visible recorder controls.

The recovered `SetWindowsHookExW` references do not include a dedicated
`WH_KEYBOARD` (`2`) or `WH_KEYBOARD_LL` (`13`) installation. This is not proof
that the application cannot receive keyboard input: ordinary window messages,
control subclassing, custom-message forwarding, or an unobserved runtime route
remain possible.

## Hook and keyboard-state API callsites

The four direct calls to the imported `SetWindowsHookExW` entry are:

| Callsite | Hook ID placed on the stack | Callback pointer | Interpretation and limit |
| --- | ---: | --- | --- |
| `0x0047735D` | `5` (`WH_CBT`) | `0x004770FE` | Direct arguments show a CBT hook associated with the current thread. No macro event-record write was linked to this callback. |
| `0x0048244D` | `-1` (`WH_MSGFILTER`) | `0x00482292` | Direct arguments show a message-filter hook. The static callsite does not link it to the macro recorder. |
| `0x00499CDC` | `7` (`WH_MOUSE`) | `0x00499B70` | Direct arguments show a mouse hook. It is not a keyboard hook. |
| `0x0054C7B2` | `7` (`WH_MOUSE`) | `0x0054C6F3` | Direct arguments show a second mouse-hook installation path. It is not a keyboard hook. |

The snapshot's direct IAT-reference inventory lists 13 direct
`GetAsyncKeyState` call sites (17 executable IAT references total, including
four non-call references) and two `GetKeyboardState` call sites. The inspected macro-editor
handler range (`0x0042B0D0`–`0x0042B260`) has no direct call to either API.
Some keyboard-state calls are in MFC keyboard-manager helpers, including
`0x0048B6EA` and `0x0048B775`, which translate virtual keys using keyboard
layout/state APIs; no macro-record write edge was recovered from those helpers.
These API imports therefore cannot be cited as proof of macro recording.

## `CMacroDlg` message-map coverage

The RTTI-backed message map has 13 rows. It contains ordinary paint, help,
left-button, and numeric-edit handlers plus custom-range message IDs. The
table below lists the input/editor-related rows reviewed for this audit; it is
not a transcription of all 13 map entries. The map does not contain explicit
`WM_KEYDOWN` or `WM_KEYUP` rows.

| Map row | Message / control | Handler | Static result |
| --- | --- | --- | --- |
| `0x005CD4C8` | `0x0019` | `0x0042B030` | Handler receives a message tuple, filters IDs `0x0107`–`0x0109`, and forwards selected cases to helper logic. Exact producer and recorder role are unresolved. |
| `0x005CD4E0` | Custom message `0x040A` | `0x0042AA50` | Large handler processes editor/window state and child controls. The exact connection to capture is unresolved. |
| `0x005CD4F8` | Custom message `0x0594` | `0x0042B1A0` | Inspects message-kind values passed in its arguments; the `0x0105` branch updates editor-side UI/event state. |
| `0x005CD510` | Custom message `0x0592` | `0x0042B260` | Reads cursor position and branches on message-kind values `0x0105` and `0x0106`; the upstream producer and precise event semantics are unresolved. |
| `0x005CD528` | Custom message `0x0591` | `0x0042B160` | For message-kind `0x0106` and nonzero accompanying data, calls `0x0042A240`. The called routine accesses editor controls/list state; no raw-input API call appears in the route. |
| `0x005CD540` | Custom message `0x0595` | `0x0042B0D0` | Checks `0x0105`/`0x0106`, sends child-window messages, and on one branch marks the selected macro node dirty. |
| `0x005CD558` | `EN_CHANGE`, control `0x0107` | `0x0042B3B0` | Validates the loop-count edit and sets dirty flag `0x40000000` on the selected macro node. |
| `0x005CD570` | `EN_CHANGE`, control `0x0117` | `0x0042B530` | Clamps an edit value to `1..1,048,575`; its semantic label and downstream consumer are unresolved. |
| `0x005CD588` | Custom message `0x0477` | `0x0042BF10` | Large handler includes macro chooser/list and command paths; no proven physical-input producer was found. |
| `0x005CD5A0` | `WM_LBUTTONDOWN` | `0x0042DCF0` | Handles a mouse-button event for the dialog. It is not evidence of the keyboard recorder's mouse-event capture format. |

The values `0x0105` and `0x0106` match `WM_SYSKEYUP` and `WM_SYSCHAR` in the
Windows message namespace. In these handlers they are values inspected inside
custom-message callbacks; the map entries themselves are `0x0591`–`0x0595`.
Thus the code directly proves message-kind tests and subsequent editor actions,
but not who produced the callback or whether the values came from physical
input, a child control, replay, or another internal message path.

## Candidate event/list mutation path

Several instruction-level edges are useful but stop short of event
construction:

1. Handler `0x0042B0D0` tests a callback argument against `0x0105` and
   `0x0106`. Its `0x0105` branch sends message `0x110A` to the child at
   `this+0x2D10`, then calls `0x0042A050`. Its `0x0106` branch uses the child
   at `this+0x2E64`, calls `0x0045C9C0` when the child returns a matching
   editor object, finds the selected macro node through `0x0042CC20`, and ORs
   `0x80000000` into node offset `+8` (`0x0042B149`). This is a direct dirty
   state update; it does not show a write of an event row.
2. Handler `0x0042B160` calls `0x0042A240` when its callback value is
   `0x0106` and the accompanying value is nonzero (`0x0042B177`–
   `0x0042B189`). The callee searches editor list/control state and updates
   local view data. The identity of the original input source remains open.
3. Handler `0x0042B1A0` has a `0x0105` branch. With zero accompanying data it
   refreshes the event display via `0x0043E8F0` and sends child message
   `0x1101`; other branches locate list entries and call editor helpers
   including `0x0045CA10` and `0x00429330`. These are UI/state operations by
   their direct call/field evidence, not a decoded keyboard-to-record encoder.
4. Handler `0x0042B260` calls `GetCursorPos` at `0x0042B290`, tests
   `0x0105`/`0x0106`, and calls UI helper `0x0042B710` on applicable paths.
   Its dialog flag at `this+0x2FAC` gates some branches. Neither the flag's
   name nor the full significance of these callbacks is established.

These are candidate links between editor notifications and event-list state.
The code around them does not directly call `SetWindowsHookExW`,
`GetAsyncKeyState`, or `GetKeyboardState`. The exact callback producers, key
code/scan-code extraction, key-down/key-up pairing, delay capture, mouse event
capture, and event-row constructor remain unresolved.

## Dirty state and persistence boundary

The editor/save boundary is clearer than capture:

- `0x0042B3B0` handles the `0x0107` edit and sets `0x40000000` in the selected
  macro record's `+8` state word when the validated value changes.
- `0x0042B0D0` has a branch that sets `0x80000000` in the selected macro
  node's `+8` state word after its editor/list operation. This establishes a
  second dirty/new-state marker but not its complete meaning.
- The `.mck` writer `0x0042E320` requires one of those high bits, clears both
  before encoding, rotates each of `0x342` record bytes right by two, and
  writes exactly `0x342` bytes. The direct handler-to-writer call route for an
  ordinary event edit was not recovered.
- The profile-local `mac.dct` writer `0x0045A310` writes eligible raw
  `0x342`-byte records. A `CMacroDlg` teardown/destructor path reaches it, as
  described in the [macro format and path audit](rk-macro-format-and-path-audit.md).
  This is local persistence; it is not a device write.
- The macro command dispatcher maps command `0x08` to export and `0x10` to
  import. Import/export file I/O is distinct from physical-input capture and
  from device apply serialization.

The report does not establish that every edit is immediately saved, that every
close path invokes the destructor writer, or how a recorder start/stop action
becomes a dirty record. The two dirty flags and serializer path must not be
treated as proof that all recorded events have been durably written.

## Open questions

- Which callback or window produces the `0x0591`–`0x0595` macro-dialog
  notifications, and whether those messages represent live recording, event
  editing, replay, or key-picker interaction.
- Whether a keyboard-specific input hook, raw-input registration, child-window
  subclass, or other producer is used outside the recovered direct import
  callsites.
- The actual recorder start/stop handler and its relationship to the visible
  localization controls.
- The code path that extracts virtual key, scan code, pressed/released state,
  mouse button/wheel, and timing/delay data and packs each eight-byte event
  row beginning at record `+0x6A`.
- The meaning of event codes `0x110`–`0x116`, message IDs `0x1101`/`0x110A`,
  callback values `0x0105`/`0x0106`, dialog flag `this+0x2FAC`, and state bits
  `0x40000000`/`0x80000000` beyond the directly observed branches.
- The ordinary editor-event route to `.mck`, `mac.dct`, and device apply;
  current evidence establishes separate components but not a complete
  end-to-end flow.

For the macro record/file layout, mouse compatibility gate, apply serializers,
and prior capture gap, see the [macro format and path audit](rk-macro-format-and-path-audit.md).
For recovered `CMacroDlg` map rows, see the [MFC message-map audit](rk-mfc-message-map-audit.md).
