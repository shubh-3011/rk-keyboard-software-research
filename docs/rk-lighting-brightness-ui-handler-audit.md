# RK 4.06 lighting brightness UI handler audit

## Scope and evidence

This focused static audit follows the visible `Light Brightness` localization,
its generated-string slot, the `LightUI` displayed-value path, the three
`tc_kbin` brightness action labels, and the known lighting serializer routes.
It uses the installed 32-bit `DeviceDriver.exe` with SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6` and
installed English `Text/en/text.xml` with SHA-256
`85B26E0C7CD8317ADEB136D37B6877601B0C3E7F6FB072867F937AA46C73DE8C`.
Addresses below are VAs in that exact executable.

The binary was inspected offline with GNU `objdump` and the existing Ghidra
exports in the adjacent `_rk_analysis/reports` directory. The application and
updater were not launched. A separate later read-only HID probe is documented
in the [live selector cross-check](rk-live-hid-selector-crosscheck-2026-10-19.md);
no output report or feature write was sent. The sidecar exports are local
analysis artifacts and are not included in this repository.

**Proven statically** means there is a direct data, call, string-table, or
control-flow edge in this binary. **Inferred** marks a likely interpretation
where the widget or event edge is missing. **Unresolved** means this snapshot
does not support a complete path. None of these terms asserts observed device
behavior.

## Findings

### `Light Brightness` and `LightUI`

**Proven statically.** The English XML has `tc_adv_str1` = “Light Brightness”.
The generated-string loader at `0x00445660` formats `tc_adv_str%d`, starts at
index 1, resolves the localized entry through `FUN_00441AB0`, and stores
successive pointers beginning at `0x0062B730` through `FUN_00405700`. Thus the
first generated-string slot at `0x0062B730` is the `tc_adv_str1` string.

At `0x00421BC2`, code loads the pointer at `0x0062B730`. The indirect call at
`0x00421BDD` resolves statically to text drawing: `FUN_0047105C` at
`0x004216CB` initializes a local adapter with vtable `0x0059F314`; the caller
loads slot `+0x68`, whose entry at `0x0059F37C` targets `0x0047111A`. That
wrapper forwards the text pointer, the preceding DWORD used as its character
count, a local rectangle, and `0x8134` through IAT `0x0059E6B8` to
`USER32!DrawTextW`. The flags are
`DT_VCENTER | DT_WORDBREAK | DT_SINGLELINE | DT_NOCLIP | DT_END_ELLIPSIS`.
Thus the localized `tc_adv_str1` string reaches a runtime text-drawing call;
`0x8134` is not a child control ID or device selector. This resolves the
callee and argument meaning, but not the identity of the surrounding visible
control or its event handler.

`FUN_004513B0` at `0x004513B0` reads `[OPT] LightUI`, parses it into the byte
table at `0x00611854`, and separately parses `[OPT] LightHW` into
`0x00611868`; `[OPT] DefBri` is stored at `0x00611850`. When
`FUN_00422220` receives selector `0x95`, its branch at `0x004222C5` reads the
byte at `0x00611854 + index` (`0x004222D1`) and formats it as text. This
proves a `LightUI`-to-runtime-value-formatting path, but not which visible
widget requests selector `0x95` or how a change to that value is committed.

**MFC ownership and literal message senders recovered; selector/control
attribution still unresolved.** The MFC map
descriptor at `0x005CD150` points to entries at `0x005CCFE8`; getter
`0x004215E0` returns that descriptor from a vtable slot in the RTTI-backed
`CLedDlg` vtable. Its complete-object locator at `0x005E3DB0` points to type
descriptor `0x0060384C`, named `.?AVCLedDlg@@`; the same vtable's runtime-class
getter returns the `CLedDlg` descriptor at `0x005CCFCC`. The base-map getter
`0x00479866` matches the recovered `CDialog` map. Thus the earlier pointer
block is a normal six-DWORD MFC message map, not an unresolved registration
table.

The map row at `0x005CD000` maps `WM_PAINT` to `FUN_00421660`, resolving the
class and message-map route for drawing `tc_adv_str1`. Rows at `0x005CD030`
and `0x005CD048` map private messages `0x0800` and `0x0801` to
`FUN_00422190` and `FUN_00422220`. The numbers `0x0800` and `0x0801` are
message IDs, not control IDs. The `0x0801` handler reads/format-selects
`LightUI` when its selector is `0x95`, and `0x0800` calls that formatter
before copying page state and potentially signaling the settings worker.
Four literal `PostMessageW` send sites for `0x0801` and five for `0x0800` are
now recovered. Their `lParam` sources are child-object fields `+0x54`,
`+0x930`, or `+0x9E0`. A constructor path through `0x004236D9` to
`0x00450140` passes a `LightUI`-selected index, literal selector `0x95`, and
`bar_nr.png`; the helper stores the literal in the passed object's `+0x9E0`
field, which the `0x0800`/`0x0801` sender pair also reads as `lParam`. This
proves selector initialization for that construction path, but not that the
same instance reaches those senders at runtime or which visible control owns
it. The `+0x54` and `+0x930` fields remain unassigned in the reviewed paths,
and the brightness control-to-writer path is still open. See the
[selector-message sender follow-up](rk-led-selector-message-sender-followup.md)
and [full MFC message-map audit](rk-mfc-message-map-audit.md) for callsites,
the complete 14-row array, and owner evidence.

### `tc_kbin10`–`tc_kbin12` brightness action labels

The English XML entries are `tc_kbin10` = “Brightness +”, `tc_kbin11` =
“Brightness -”, and `tc_kbin12` = “Brightness Loop”. The generated-string
loader at `0x004458E0` builds `tc_kbin%d` strings into a pointer table starting
at `0x0062B854`. With four-byte entries, the three strings occupy
`0x0062B878`, `0x0062B87C`, and `0x0062B880`, respectively.

**Proven statically.** The function-action label mapper at `0x0044E3EF`
branches on type/tag 9 and reads the action code from `[edi+0x0C]`. Its code
comparisons and resulting label pointers are:

| Action code in the mapper | Comparison VA | Localized label pointer | Meaning from English XML |
| --- | ---: | ---: | --- |
| `0x08030100` | `0x0044E531` | `0x0062B878` | Brightness + |
| `0x08030200` | `0x0044E4AC`–`0x0044E4B7` | `0x0062B87C` | Brightness - |
| `0x08030000` | `0x0044E52A` | `0x0062B880` | Brightness Loop |

The matching branches call `FUN_00405810` to assign the selected string to an
object. This is an action-code-to-localized-label mapping used by the key
function/action path. It does not show that these labels are three controls on
the lighting page or that their event handlers alter the `LightUI` value.
In the inspected installed S98 profiles, the `0x08030100` and `0x08030200`
tuples occur in `[FN1]`/`[FN2]`; the profile-to-runtime parser path for those
sections is not established by the available audit evidence.

There is a separate type-9 mapping translator: `FUN_00413410` branches on
record tag 9 and sends the extended DWORD at record offset `+0x0C` through
`FUN_00454C30` (byte-order transformation). `FUN_00413B20` uses this helper
while translating 132 records of 16 bytes into a 132-entry output map, using
the per-record output-slot byte associated with table `0x006169D0`. The
RKKB apply method `FUN_00413BF0` contains conditional mapping/write paths; the
G5/3632 settings path uses its separate translator `FUN_00411260` and
orchestrator `FUN_00411B90`. These are family-specific keymap routes. No
static chain in this audit connects a particular `tc_kbin` profile tuple or
visible action selection to either family writer.

### `CLedDlg` message handler and apply worker

The map identifies `FUN_00422190` as handler for message `0x0800`. It calls
`FUN_00422220` at `0x0042219F` and `FUN_00425440` at
`0x004221A6`. Under the `0x00611794` guard it sends a `0x110A` message at
`0x004221C4`, examines a linked structure (including a comparison with
`0x1E`), and can call `FUN_00401080(2)` at `0x004221F7`. The helper signals
the semaphore-backed settings worker. `FUN_00425440` copies generated-dialog
state into profile/UI configuration state. This establishes a general
settings-change-to-mask-2 signal path, but its input selector is passed
through rather than fixed to `0x95`, and the label/widget for this handler is
not recovered. It is therefore only a candidate route, not a proven
`Light Brightness` event handler.

The worker dispatches indirectly through a virtual `+0x3C` method. Its
RTTI-backed class targets include `CDevRKKB` → `FUN_00413BF0` and `CDevG5KB`
→ `FUN_00411B90`; the specific receiver for the candidate event is not known.
For G5/3632, `FUN_00411B90` mask `0x02` reads LED configuration through the
family read path, packs with `FUN_00411700` or `FUN_00411900`, and uses command
4. The `FUN_00411900` packer indexes `LightHW` and places a translated
brightness byte at output `+0x5E` for the selected mode. The RKKB
`FUN_00413BF0` path also indexes `LightHW` and writes a translated byte into
the LED-data payload beginning `02 29`. These establish profile-table-to-
serializer paths, not the visible control that selects them or a measured
brightness effect.

## Evidence status

| Link | Status | Evidence and limit |
| --- | --- | --- |
| English labels `tc_adv_str1`, `tc_kbin10`–`tc_kbin12` | **Proven statically** | Installed English XML; exact file hash above. |
| `tc_adv_str1` generated-string slot, draw call, and page-map owner | **Proven statically** | Loader `0x00445660` stores the string at `0x0062B730`; `0x00421660` is the `CLedDlg` `WM_PAINT` handler and passes it through adapter vtable `0x0059F314`, slot `+0x68` -> `0x0047111A` -> `USER32!DrawTextW` at `0x00421BDD`. `0x8134` is the DrawTextW format mask. The exact child widget/control ID remains unknown. |
| `LightUI` profile value to displayed text | **Proven statically** | `FUN_004513B0` populates `0x00611854`; `FUN_00422220` selector `0x95` reads it at `0x004222D1`. Caller-to-widget binding remains unknown. |
| Brightness action code to localized action label | **Proven statically** | Type-9 mapper at `0x0044E3EF`, comparisons around `0x0044E4AC` and `0x0044E52A`–`0x0044E543`, action-string slots above. |
| Type-9 mapping translator and matrix path | **Proven statically** | `FUN_00413410` → `FUN_00454C30`; `FUN_00413B20` maps 132 records. Specific `[FN1]`/`[FN2]` profile tuple to this runtime input remains unresolved. |
| `CLedDlg` messages `0x0800`/`0x0801` | **Proven statically; selector/control attribution unresolved** | RTTI-backed map rows at `0x005CD030`/`0x005CD048` target `FUN_00422190`/`FUN_00422220`; four and five literal `PostMessageW` sender sites respectively are traced. `lParam` sources are fields `+0x54`, `+0x930`, and `+0x9E0`; static field assignment to selector `0x95` and child-control binding remain unresolved. Message `0x0800` may signal Apply mask 2. |
| Profile `LightHW` values to keyboard LED serializer bytes | **Proven statically** | RKKB `FUN_00413BF0`; G5/3632 `FUN_00411900` and related writer path. UI trigger, active family, and physical units are unresolved. |
| Complete `Light Brightness` control → event → field mutation → writer chain | **Unresolved** | No direct child HWND/control ID and callback link joins the generated `tc_adv_str1` construction, selector `0x95`, `FUN_00422190`, and a concrete device-family writer. |
| Whether `tc_kbin10`–`tc_kbin12` are lighting-page buttons | **Unresolved; evidence points to remapping choices** | Their strings are selected by the type-9 function-action mapper. No lighting-page click handler was found. |
| PC display/monitor brightness control | **Not found in this trace** | `LightUI`/`LightHW` feed keyboard lighting configuration and LED serializers. No PC display-brightness API or monitor-control route was recovered in the searched evidence. |

## Search and disassembly record

The focused check used the existing `_rk_analysis/reports/brightness-global-xrefs.txt`,
`lighting-control-trace.txt`, and `device-targeted-functions.txt`; the current
local reports on UI control crosswalk, profile-to-record lighting data,
keymap flow, Apply worker, and serializers; installed English XML; and
`objdump -d` ranges covering `0x00421660`–`0x00422230`,
`0x00445640`–`0x00445950`, `0x0044E3D0`–`0x0044E570`,
`0x00413400`–`0x00413610`, `0x00413B20`–`0x00413BE7`,
`0x00413BF0`–`0x00413D20`, `0x00411900`–`0x00411B90`, and
`0x00454C30` onward. Searches for the label keys and action literals in the
available export reports found the `LightUI` selector and its direct data
edge, but no label-to-widget/event edge. The `tc_adv_str1` draw adapter and
`0x8134` mask are now resolved from the constructor, vtable, wrapper, and IAT;
the newly recovered MFC map ties the paint handler to `CLedDlg` and resolves
the former pointer block as message-map entries. A subsequent full-image
literal-send search found four `PostMessageW` sites for message `0x0801` and
five for `0x0800`; their dynamic `lParam` fields are documented in the
[selector-message sender follow-up](rk-led-selector-message-sender-followup.md).
The field-to-selector `0x95` assignment, exact child-control identity, and
settings worker's runtime writer remain unknown. This audit therefore does
not claim the entire brightness control path has been reverse engineered.

## Related audits

- [UI control-to-command crosswalk](rk-ui-control-command-crosswalk.md)
- [Lighting profile-to-record path](rk-lighting-profile-record-path-audit.md)
- [Keymap profile-to-UI and serializer path](rk-keymap-ui-path-audit.md)
- [Settings Apply worker](rk-settings-apply-worker-audit.md)
- [Settings serializer paths](rk-setting-serializer-audit.md)
- [Main reverse-engineering report: brightness profile and serializer](reverse-engineering.md#brightness-profile-ui-and-serializer-path)
