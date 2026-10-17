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
updater were not launched; no HID, GATT, serial, or other device interface was
opened, and no report or command was sent. The sidecar exports are local
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

At `0x00421BC2`, code loads the pointer at `0x0062B730`, then passes that
string and the numeric value `0x8134` to a virtual method (`0x00421BDC` call).
This is evidence that the first `tc_adv_str` string participates in runtime
UI construction. It does **not** prove that `0x8134` is a child control ID,
identify the widget type, or establish a callback for the resulting widget.

`FUN_004513B0` at `0x004513B0` reads `[OPT] LightUI`, parses it into the byte
table at `0x00611854`, and separately parses `[OPT] LightHW` into
`0x00611868`; `[OPT] DefBri` is stored at `0x00611850`. When
`FUN_00422220` receives selector `0x95`, its branch at `0x004222C5` reads the
byte at `0x00611854 + index` (`0x004222D1`) and formats it as text. This
proves a `LightUI`-to-runtime-value-formatting path, but not which visible
widget requests selector `0x95` or how a change to that value is committed.

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

### Candidate general settings handler and apply worker

`FUN_00422190` calls `FUN_00422220` at `0x0042219F` and `FUN_00425440` at
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
| `tc_adv_str1` generated-string slot | **Proven statically** | Loader `0x00445660` starts at index 1 and stores from `0x0062B730`; runtime-construction code uses that slot at `0x00421BC2`. The widget/control ID is unknown. |
| `LightUI` profile value to displayed text | **Proven statically** | `FUN_004513B0` populates `0x00611854`; `FUN_00422220` selector `0x95` reads it at `0x004222D1`. Caller-to-widget binding remains unknown. |
| Brightness action code to localized action label | **Proven statically** | Type-9 mapper at `0x0044E3EF`, comparisons around `0x0044E4AC` and `0x0044E52A`–`0x0044E543`, action-string slots above. |
| Type-9 mapping translator and matrix path | **Proven statically** | `FUN_00413410` → `FUN_00454C30`; `FUN_00413B20` maps 132 records. Specific `[FN1]`/`[FN2]` profile tuple to this runtime input remains unresolved. |
| General generated-settings change to mask-2 worker signal | **Proven statically** | `FUN_00422190` and `FUN_00401080(2)` call at `0x004221F7`; worker dispatch is indirect. This is not proven to be the brightness widget's handler. |
| Profile `LightHW` values to keyboard LED serializer bytes | **Proven statically** | RKKB `FUN_00413BF0`; G5/3632 `FUN_00411900` and related writer path. UI trigger, active family, and physical units are unresolved. |
| Complete `Light Brightness` control → event → field mutation → writer chain | **Unresolved** | No direct child HWND/control ID and callback link joins the generated `tc_adv_str1` construction, selector `0x95`, `FUN_00422190`, and a concrete device-family writer. |
| Whether `tc_kbin10`–`tc_kbin12` are lighting-page buttons | **Unresolved; evidence points to remapping choices** | Their strings are selected by the type-9 function-action mapper. No lighting-page click handler was found. |
| PC display/monitor brightness control | **Not found in this trace** | `LightUI`/`LightHW` feed keyboard lighting configuration and LED serializers. No PC display-brightness API or monitor-control route was recovered in the searched evidence. |

## Search and disassembly record

The focused check used the existing `_rk_analysis/reports/brightness-global-xrefs.txt`,
`lighting-control-trace.txt`, and `device-targeted-functions.txt`; the current
local reports on UI control crosswalk, profile-to-record lighting data,
keymap flow, Apply worker, and serializers; installed English XML; and
`objdump -d` ranges covering `0x00421B80`–`0x00422230`,
`0x00445640`–`0x00445950`, `0x0044E3D0`–`0x0044E570`,
`0x00413400`–`0x00413610`, `0x00413B20`–`0x00413BE7`,
`0x00413BF0`–`0x00413D20`, `0x00411900`–`0x00411B90`, and
`0x00454C30` onward. Searches for the label keys and action literals in the
available export reports found the `LightUI` selector and its direct data
edge, but no label-to-widget/event edge. The relevant missing bridge is
structural: the UI is largely generated, the selector is an argument to a
generic formatter, and the settings worker selects its writer through an
unresolved runtime object. This audit therefore does not claim the entire
brightness control path has been reverse engineered.

## Related audits

- [UI control-to-command crosswalk](rk-ui-control-command-crosswalk.md)
- [Lighting profile-to-record path](rk-lighting-profile-record-path-audit.md)
- [Keymap profile-to-UI and serializer path](rk-keymap-ui-path-audit.md)
- [Settings Apply worker](rk-settings-apply-worker-audit.md)
- [Settings serializer paths](rk-setting-serializer-audit.md)
- [Main reverse-engineering report: brightness profile and serializer](reverse-engineering.md#brightness-profile-ui-and-serializer-path)
