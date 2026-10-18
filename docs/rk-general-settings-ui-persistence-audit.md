# RK general settings UI and host persistence audit

## Scope and evidence

This report separates general settings/profile UI state from host-local file
and registry persistence and from calls that can write to a keyboard. It uses
static analysis of the installed RK Keyboard Software 4.06 main executable,
profile/configuration files, and English localization XML. No RK application
or updater was run; no HID, GATT, serial, or keyboard handle was opened, and
no report, command, reset, or firmware operation was sent.

| Artifact | SHA-256 | Scope |
| --- | --- | --- |
| `DeviceDriver.exe` | `C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6` | Installed 4.06 PE32 x86; image base `0x00400000`. All executable addresses below are VAs for this image only. |
| `Cfg.ini` | `1A9796E706FA64B1821417EFDA080D481E202FFCF941AA97E6A78EFE3A32BADD` | Installed model and profile index. |
| `Dev/022F/KB.ini` | `C0D2D796ABBC46D35ED61E9010AF839175D9A6B33F314274AFABF6EE5F06E7B4` | Installed RK-S98 default-profile example; not proof this profile was selected at runtime. |
| `Text/en/text.xml` | `85B26E0C7CD8317ADEB136D37B6877601B0C3E7F6FB072867F937AA46C73DE8C` | English UI labels and confirmation text. |

**Proven statically** means the file/string, call, data flow, or message-map
edge is present in this snapshot. **Inferred** marks an interpretation of
those edges. **Unresolved** means the available static evidence does not
connect the pieces reliably. The companion
[UI control crosswalk](rk-ui-control-command-crosswalk.md) and
[settings serializer audit](rk-setting-serializer-audit.md) contain the
feature-specific command and control limits.

## General settings labels and profile inputs

English localization includes `tc_adv_str9` “Keyboard Settings”,
`tc_adv_str23` “Sleep Time”, `tc_adv_str35` “Automatic detection”,
`tc_adv_str36` “Debounce”, `tc_adv_str37` “Office mode”,
`tc_adv_str38` “Gaming mode”, `tc_adv_str39` “Wireless sleep time”,
`tc_kbin17` “Lock Win”, and `tc_kbin19`/`tc_kbin20` “Windows Layout” /
“Mac Layout”. The profile corpus has corresponding-looking values, including
`ShowSleepTime`, `ShowAutoDetect`, `DebounceUI`, `DebounceHW`, and
`KbLayout`; the profile field ledger records `ShowSleepTime` in 117 profiles,
`ShowAutoDetect` in 46, and each debounce field in 60. These counts show
stored profile variation, not which controls were shown or selected.

| UI/profile edge | Evidence and status | Limit |
| --- | --- | --- |
| General settings labels | **Proven statically:** the English XML has the labels above. The dialog inventory and MFC-map audit do not assign these labels to unique child IDs or handlers. | **Unresolved:** exact windows, model-dependent visibility, event handlers, and whether the labels share controls or use dynamically generated controls. |
| Profile load | **Proven statically:** `FUN_004513B0` formats the selected profile path as `%sDev\\%04X\\KB.ini` and reads multiple `[OPT]` fields into runtime state. The profile loader reads fields such as `DebounceUI`, `ShowSleepTime`, and LED options; the dedicated brightness path traces `LightUI`, `LightHW`, and `DefBri`. | Profile initialization is a host-side read. It does not prove the UI wrote the profile or that these values reached a device. The complete field-to-widget path is not recovered. |
| Automatic detection | **Proven statically:** `ShowAutoDetect` is present in 46 profiles; the executable's imported/dedicated string inventory has no individual literal for this key. | A dynamic/generic INI read remains possible. **Unresolved:** whether this field gates a UI control, whether it is read, and what “automatic detection” changes. |
| Debounce and sleep | **Proven statically:** matching labels and profile fields exist; the shared settings packers contain debounce/sleep-related serialized positions (see the serializer audit). | **Unresolved:** control-to-dirty-flag mapping, exact unit/range, and whether the label value, profile default, or another runtime value is serialized for a given model. |
| Windows/Mac layout and reset action-key labels | **Proven statically:** shortcut labels exist; `KbLayout` is present in all 189 profile files, and `CmdReset` appears in 18. | **Unresolved:** no unique handler or profile-cell-to-command path was recovered. `CmdReset` must not be treated as evidence for the separate “Reset Keyboard” or “Restore factory settings” actions. |

The installed `Cfg.ini` contains 188 named model entries and the `Dev`
directory contains 189 `KB.ini` files, including unregistered profile `01C7`.
The model-table initializer at `0x00447210` reads profile `VID`, `ShowScreen`,
`Fw`, `DevTy`, and wireless VID/PID fields to build its host-side candidate
table. This is evidence of profile-driven discovery and routing, not a
keyboard settings save. The profile corpus is catalogued in
[`models.json`](../models.json) and
[`rk-profile-schema-audit.md`](rk-profile-schema-audit.md).

## Host-local persistence paths

| Path | Static edge | Classification |
| --- | --- | --- |
| Language choice | `FUN_00403270` identifies the language-combo child at `this+0xAC`, reads the selected index at `this+0x11C`, and calls `FUN_00403170`. The latter reloads `Text/<locale>/text.xml` and calls `WritePrivateProfileStringW` at `0x00403243` for `OPT\\LangIndex` in `%LOCALAPPDATA%\\RKKB\\lang.ini`. | **Proven statically:** host-local UI preference persistence. This does not serialize keyboard settings. The visible `Language` label-to-child identity remains an inference; see the [localization audit](rk-resource-localization-audit.md). |
| Framework profile settings | At `0x0047F216`, code calls the integer profile wrapper at `0x00481D22` with literals `CWinApp` and `Settings` and a DWORD from object offset `+0x94`. The wrapper chooses a registry route (`RegSetValueExW`) when its registry-profile field at `this+0x54` is set; otherwise it formats a string and calls `WritePrivateProfileStringW` using the profile filename held at `this+0x68`. The string profile wrapper beginning at `0x00481DAD` has the corresponding registry/INI branches. | **Proven statically:** a general MFC profile-setting write exists and is host-local. **Unresolved:** whether this exact record is used in registry or INI mode on a normal run, the concrete resolved file/registry path, and the semantic name of the stored DWORD. The `CWinApp`/`Settings` setting is not linked to a keyboard-setting control or hardware serializer. |
| Per-device working state on tray-menu Exit (`0x6401`) | The `COemDrvDlg` handler at `0x00446820`, under the profile-state guard, calls helpers that write `pro.dct` (per-device records, `0x3E74` bytes per eligible object) and `curid.dct` (four bytes from a global value) below the active device/profile path. It also signals a per-device event. | **Proven statically:** `tc_exit` is appended to the tray context menu as command `0x6401`; the handler's file writes and event signal are statically present. The worker audit shows the event is used to stop the periodic system-parameter worker; it does not prove a keyboard Apply operation ran. **Unresolved:** both file schemas, active profile path value, and whether an in-flight worker operation completes before exit. See the [tray-menu workflow audit](rk-tray-icon-menu-workflow-audit.md) and [event/worker audit](rk-ui-event-worker-path-audit.md). |

The `lang.ini` write is the only recovered direct feature-specific
`WritePrivateProfileStringW` callsite in the inspected main application. The
other two main-app references are inside generic MFC profile wrappers. These
facts do not prove that the executable never updates other local files by
another API or indirect path. No direct path from the general settings labels
to rewriting installed `Cfg.ini` or `Dev/*/KB.ini` was recovered in this
audit.

Existing local persistence paths for macro definitions, audio settings, and
screen/GIF cache data are covered in the [main reverse-engineering report](reverse-engineering.md)
and the dedicated [macro audit](rk-macro-format-and-path-audit.md). They are
not evidence that keyboard feature settings were saved to those files.

## Apply, reset, and factory restore boundaries

The generated main `tc_apply` control stores a new value in an in-memory row
through `0x0040B3B0` and signals the settings worker with mask `1` when the
Apply gate is enabled. This proves a UI-to-memory/event edge, not profile-file
persistence. The worker's family-specific virtual call can reach active
keyboard writers, but the concrete receiver and per-click flag source remain
unresolved; the [Apply worker audit](rk-settings-apply-worker-audit.md)
documents those limits. The separate key/function-picker `Apply` control at
`0x0041F810` updates local picker/dirty state, with no direct serializer or
worker-signal edge recovered from that handler.

The English strings explicitly distinguish “Reset Keyboard” / “Reset
keyboard data” (`tc_msg2` / `tc_msg4`) and “Restore factory settings”
(`tc_msg5`). Their confirmation messages state that keyboard data is cleared
or erased. The message strings prove intent, not that a user selected either
action. The main executable has a reset helper `FUN_004102D0` and a separate
reset-like branch in the shared serializer; their presence does not connect
them to either localized prompt. No prompt/button-to-handler-to-reset-command
edge is recovered. These are active keyboard-write paths and were not called.

## What remains open

- Most general-settings labels have no recovered child ID or unique message
  handler, and the full control-to-profile/runtime-state mapping is unknown.
- It is unknown which settings are saved only to the host, which settings are
  synchronized to the keyboard, and how the software handles unsaved edits
  after Apply, close, device disconnect, or profile change.
- The MFC profile wrapper's active storage mode and concrete path for the
  `CWinApp`/`Settings` integer are unresolved. Its evidence is generic app
  state, not a keyboard protocol.
- The `.dct` schemas, reset-prompt dispatch, and reset effect remain
  unresolved. No current static evidence permits safely replaying reset or
  factory-restore behavior.
- The results cover one installed 4.06 snapshot and its bundled profiles;
  they do not prove later releases, other language packs, or all RK models
  use the same controls or persistence routes.

