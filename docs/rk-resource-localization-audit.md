# RK Keyboard Software resource and localization audit

## Scope and method

This is a static audit of the installed package at `C:\Program Files (x86)\RK Keyboard Software`, version/catalog value `0x406`. I enumerated its files and inspected INI/XML text, image metadata, and selected image frames. I did not launch any RK executable, contact the keyboard, open a HID handle, run the updater, or enter a bootloader. No keyboard report or command was sent.

The snapshot has **810 files (78,070,176 bytes)**. The existing [package manifest](rk-installed-package-manifest.csv) gives the exact path, byte size, and SHA-256 for every file. The new [resource-group inventory](rk-resource-group-inventory.csv) partitions all 810 files into 14 non-overlapping groups; the [per-profile inventory](rk-model-resource-asset-inventory.csv) records assets for every one of the 189 `Dev/*/KB.ini` profiles. The localization tables below are supported by the [XML file inventory](rk-localization-file-inventory.csv) and [key-level locale matrix](rk-localization-key-matrix.csv); the matrix compares values without republishing the full translated text.

Confidence labels distinguish direct package evidence from interpretation:

- **High**: file path, bytes, XML/INI fields, image metadata, or an observed string directly supports the statement.
- **Moderate**: names, directory placement, or neighboring config fields strongly suggest a role, but the exact app dispatch/control mapping was not recovered.
- **Unresolved**: the package alone does not establish the value or behavior.

## Package groups

The group CSV is exhaustive for this installed snapshot. Key coverage and sizes are summarized here; consult the CSV for exact extensions and role notes.

| Group | Files | Evidence-backed role |
| --- | ---: | --- |
| Root app/config/installer files | 7 | `Cfg.ini`, main `DeviceDriver.exe`, installer helper, uninstall executable/data/DLL, and app icon. |
| Per-model `KB.ini` | 189 | Device-specific layout, feature, lighting, firmware, and screen fields. 188 codes are named by `Cfg.ini`; `01C7` has a profile but no `DevName` registration. |
| Per-model keyboard art | 204 | 102 matching `keyimg.png`/`kbled.png` pairs. Visual inspection confirms key outlines and LED/key legends for the profile. 87 profiles have no such pair. |
| UI locale XML | 7 | One `Text/<locale>/text.xml` per supported locale. |
| Generic LED locale XML | 5 | English, Japanese, Korean, Simplified Chinese, and Traditional Chinese LED-mode/effect dictionaries. |
| Profile-local LED XML | 10 | English and Simplified Chinese label dictionaries for `014E`, `015B`, `01C7`, `020B`, and `023D`. |
| Global ET pattern text | 74 | Numeric pattern folders; includes key-unit groupings and audio-bar/layer mappings. One file, `ET/51/104key.txt`, is zero bytes. |
| Global Cartoon pattern text | 12 | Named key-group layouts in eight numeric folders. |
| Profile-local ET/Cartoon text | 198 | Profile-specific pattern files under 37 model folders (33 with `ET`, 34 with `Cartoon`, 30 with both). |
| Screen GIF samples | 2 | Display-animation resources for profiles `0193` and `01B8`. |
| Skins/UI chrome | 96 | 91 PNG, four BMP menu-state assets, and `skins/mak.skn` (520 bytes). Names such as `_nr`, `_ov`, and `_dn` suggest normal/hover/down states; exact use of every asset is not mapped. |
| Fonts | 4 | Open Sans Light, Regular, Semibold, and ExtraBold TTF files. |
| Updater and firmware package | 2 | `Dev/01AF/Update.exe` and one adjacent `.upf`; neither was run or decoded here. |

The package-wide extension counts are 295 PNG, 284 TXT, 190 INI, 22 XML, four BMP, four TTF, three EXE, two DLL, two GIF, and one each ICO, DAT, SKN, and UPF. The two GIFs are `Dev/0193/screen.gif` (320×172, 60 frames, 40 ms per frame) and `Dev/01B8/screen.gif` (240×240, 70 frames, 80 ms per frame). Their matching `KB.ini` values include the same screen dimensions; the first declares a 60-frame maximum, while the second declares 35 despite the bundled GIF holding 70 frames. Whether that second file is a demo, a two-part loop, or processed differently is unresolved.

No `screen_img*.png` frame cache is shipped. The existing native trace identifies code that decodes `screen.gif` to local PNG frames and maintains a local delay cache; see [the screen/GIF trace](reverse-engineering.md#screen-and-gif-data-paths). The two GIFs visually contain animated screen artwork, but their presence alone does not prove that they are default content or what would be transferred to a keyboard.

The packaged UI chrome has 96 entries, including `main_nr.png`, `welcome.png`, logo/control assets, four menu BMPs, and `mak.skn`. The PNG names strongly indicate controls and states, but the 520-byte SKN structure remains opaque. The four fonts are readily identified by file name; their control-by-control use remains unresolved.

## Language selection and locale coverage

`Cfg.ini` lists seven language choices in this order: Simplified Chinese (`sc`), English (`en`), Traditional Chinese (`tw`), Russian, Turkish, Japanese, and Korean. The visible language setting is named by `tc_adv_str13`. The static driver trace records the selected `LangIndex` in `%LOCALAPPDATA%\RKKB\lang.ini` from `FUN_00403170`; this is code evidence for local language preference persistence, not an observation of a live run. The expected resource organization is `Text/<language>/text.xml` plus `Dev/<language>/led.xml`.

Static UI-handler tracing identifies the language-selection event. `FUN_00403270`
compares a `WM_COMMAND` `lParam` with the language-combo child window at
`this+0xAC`, then passes selected `LangIndex` at `this+0x11C` to
`FUN_00403170`. That routine formats the selected `Text/<language>/text.xml`
path, reloads the string table, and writes `%LOCALAPPDATA%\RKKB\lang.ini`
with section `OPT`, key `LangIndex`, using `WritePrivateProfileStringW`.
The selector's visible label (`tc_adv_str13`) has not been linked to a
specific control ID, and no live language change was observed.

All seven UI XML files define the same **247 intended keys**, with zero empty values and no duplicate leaf keys after parsing. However, **`Text/Japanese/text.xml` is not well-formed XML as installed**: its `tc_screen1` text ends with `/tc_screen1>` instead of `</tc_screen1>`, missing the opening angle bracket on the closing tag. An in-memory-only repair recovers the same 247 keys; no installed file was changed. This is not a root-tag capitalization issue. The key matrix marks this single source defect explicitly.

The native locale-table builder `FUN_00441F20` registers the literal and
formatted `tc_*` lookups through `FUN_00441AB0` and stores results in indexed
global slots. Its lookup templates cover all 247 leaf keys in the English XML.
The binary also probes keys absent from that XML: `tc_hw1`–`tc_hw5`,
`tc_led_mode22`–`tc_led_mode25`, `tc_custom10`, `tc_office8`–`tc_office10`,
and `tc_kbin22`–`tc_kbin30`. These missing keys use the loader's empty-string
fallback at `0x005C90A0`; whether that leaves controls blank, hidden, or on a
different fallback is unresolved. This makes native query coverage broader
than the shipped leaf-key inventory without assuming every lookup appears in
the UI.

Comparing whole string values against English finds exact textual matches in: Simplified Chinese 4/247, Traditional Chinese 4/247, Russian 5/247, Turkish 51/247, Japanese 7/247, and Korean 6/247. Common units, URLs, and short tokens can intentionally remain unchanged; the larger Turkish count is a translation-review lead, not proof of a translation defect. No linguistic quality review was performed. These counts are exact-string comparisons only.

The five generic LED dictionaries each have the same 60-key schema: 21 `tc_led_mode*` names, 20 `tc_led*` alternate names, and 19 `tc_eft*` effect names. They have no empty/duplicate keys, and the four non-English dictionaries have the same schema as English with no values exactly equal to English. The 10 model-local dictionaries also have matching English/Simplified-Chinese schemas: `014E` has `tc_led1`–`tc_led3`; each of the other four profile folders has `tc_led1`–`tc_led13`. No model-local Chinese label is an exact English string. These XML files establish localized names/order, not the meaning of `LedOpt*` tuples or serialized LED commands.

The model-local LED files occur for four registered profiles and the unregistered `01C7` profile. Static callsite inspection establishes the load order: the code formats `%sDev\\%04X\\%s\\led.xml` at `0x00422B84`, then follows a fallback branch to `%sDev\\%s\\led.xml` at `0x00422BDB`. Nearby code builds the `tc_eft%d`, `tc_led_mode%d`, and `tc_led%d` lookup keys. Runtime list builder `FUN_00422AF0` selects among these templates using globals `0x00611760` and `0x006117C4`, builds a 24-entry list, and `FUN_00422DA0` creates the associated controls subject to mask `0x00611798`. The profile-local-first, generic-locale-fallback path is supported, but suffix-to-visible-widget reachability and LED command mapping remain unresolved.

The localized `tc_apply` slot (`0x0062B4B0`) appears in two runtime-generated
controls. In `CKeyFunPickDlg`, RTTI identifies the vtable at `0x005CCE4C`; the
control is stored at `this+0x204` and constructed at `0x0041EC32`–
`0x0041EC3F`. Vtable slot `+0xF0` targets handler `0x0041F810`, which checks
whether the clicked HWND matches that child and updates local selection/dirty
fields. No direct call from this handler to the shared serializer or RKKB
writer was recovered.

A second `tc_apply` control is stored at `this+0x1DD8` and constructed at
`0x0040A3F8`–`0x0040A404`. Its handler checks the child HWND and reaches
`0x0040AE1D`; that path calls `0x0040B3B0` to update an in-memory record under
`0x0062B384+0x458+index*0x10`, then, when global `0x00611794` is set, calls
`0x00401080` to update global state and signal an event. This proves a
UI-to-working-state/app-signal edge, not a persisted profile write or a
keyboard serializer call. The downstream connection from either Apply
control to the settings flags and device writer remains unresolved.

## String families and visible workflows

The key families and counts below come directly from the English UI XML. Prefixes and label text associate them with workflows; the mapping from every XML key to an individual window control/handler is **not** complete.

| Key family | Count | Workflow association | Confidence |
| --- | ---: | --- | --- |
| `tc_macro_*` | 33 | Macro list, recording, delays, events, import/export, and repeat modes. Static native traces independently identify macro dialogs and local `.mck` persistence. | High for workflow; individual control binding unresolved. |
| `tc_adv_str*` | 43 | Advanced settings, language selection, lighting controls, sleep/debounce, software and firmware update prompts. | High for labels; exact control wiring partly unresolved. |
| `tc_msg*` | 29 | Device/search/status, layer/tap, synchronization, reset/factory-restore prompts. Reset strings warn that stored keyboard data is erased. | High for message intent. |
| `tc_screen*` | 21 | Screen preview, frame/layer editing, save/import/undo, interval, limits, and USB-only transfer prompt. Paired with screen-capable profile fields and GIF decode code. | High for feature family; per-control wiring incomplete. |
| `tc_led_mode*` | 21 | Lighting mode choices. | High for label family; mode-to-command mapping unresolved. |
| `tc_custom*` | 9 | Custom lighting effects. | High for label family; exact editor binding unresolved. |
| `tc_music*` / `tc_music_mode*` | 20 | Audio-reactive lighting controls and ten effect labels. ET text explicitly documents audio-bar/layer grouping formats. | High for label/file role; effect rendering and command mapping unresolved. |
| `tc_kbin*` | 21 | Keyboard action labels for light mode/color/brightness/speed, layout, and reset/record functions. | High for labels; which models expose each action varies. |
| `tc_office*`, `tc_kbmedia*`, and standalone media/mouse keys | 31 | Office, media, browser, and mouse shortcut choices in key remapping. | High for label categories; exact control binding partly unresolved. |

Other single-key labels cover general buttons, profile naming, shortcuts, and navigation. Counts are namespace-based and may overlap conceptually: for example, shortcut labels describe choices within key remapping rather than separate top-level pages. The `rk-localization-key-matrix.csv` gives every key and its workflow category, locale presence, exact-English comparison flags, and Japanese source defect without including all translated strings.

## Model and effect resources

Every one of the 189 `KB.ini` profile files has a row in the model-asset CSV. They hold a mixture of `OPT`, `KEY`, function-layer, lighting, and device-feature sections. Existing [profile field analysis](rk-profile-option-field-inventory.csv) and [driver-family mapping](rk-profile-driver-family-map.csv) cover fields/selection logic beyond this file census. Asset coverage is not uniform: 102 profiles have paired key illustrations; two have `screen.gif`; five have local LED dictionaries; only 37 have local ET/Cartoon text. The unregistered `01C7` profile still has a `KB.ini`, images/patterns/LED labels as recorded, but is not selectable by a `DevName` entry in this installed `Cfg.ini`.

The global `ET` tree contains 18 numeric folders and 74 `.txt` files. Most folders carry `audiobar.txt`, `flower.txt`, `happy.txt`, and `stream_h.txt`; folder 51 adds a **zero-byte** `104key.txt`, and folder 52 adds `paoma_unit.txt`. Chinese comments in sample files say that `flower`/`stream_h` describe key-unit groupings and that `happy`/`audiobar` describe audio bars with colon-separated layers and comma-separated keys. Thus these are structured key-pattern data, not ordinary prose. The global `Cartoon` tree has 12 files in eight numeric folders, with names such as `flower.txt`, `wheel_unit.txt`, and `stream_unit.txt`; the text contains rows of key-name tokens under effect-like headings.

Model-local `ET` and `Cartoon` directories contain 198 corresponding text files across 37 profiles. Their names and key tokens support a **moderate-confidence** model-specific pattern role. `KB.ini` `GaoshouIndex` values in this snapshot are 1 (28 profiles), 11 (4), 13 (93), 15 (1), and 17 (63). Only values 1 and 17 coincide with a numeric directory in global `ET`; the global `ET` IDs 2–10, 18–19, 22–23, and 50–52 are not literal `GaoshouIndex` values. Therefore, equating those folder numbers directly with `GaoshouIndex` is unsupported. Exact lookup/fallback rules and all token semantics remain open.

`skins/mak.skn` is the only `.skn` file and is 520 bytes; its format is not recognized. `ET/51/104key.txt` is the only zero-length file in the install. The exact roles of every image-state sprite and several text tokens are also not linked to native control IDs. These are the specific residual resources that remain unclassified or only group-classified; all file paths themselves are present in the package manifest and categorized in the resource-group CSV.

## Evidence limits and related findings

The report's [native screen/GIF analysis](reverse-engineering.md#screen-and-gif-data-paths), [macro analysis](reverse-engineering.md#keymap-and-macro-mapping-details), and [profile catalog](rk-profile-driver-family-map.csv) provide code/config links for the workflows above. This pass establishes resource presence, structure, key/value coverage, image metadata, and selected visual examples. It does not reconstruct every MFC control map, prove successful runtime XML loading, reverse every effect algorithm, or decode the updater's `.upf` payload. The [MFC message-map audit](rk-mfc-message-map-audit.md) and [dialog-resource audit](rk-dialog-resource-audit.md) inventory recovered MFC routes and static PE dialog controls. No keyboard firmware was copied or modified.
