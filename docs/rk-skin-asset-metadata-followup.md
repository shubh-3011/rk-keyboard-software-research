# RK 4.06 skin assets and 4.6 package delta follow-up

## Scope and evidence

This static follow-up expands the skin group beyond the prior aggregate counts. On 2026-10-19, all 810 files under `C:\Program Files (x86)\RK Keyboard Software` were rechecked against [`rk-installed-package-manifest.csv`](rk-installed-package-manifest.csv): 810 present, zero missing, zero extra, and zero size/hash mismatches. The rows below give file-level dimensions and image modes for the 96 installed `skins/` entries; SHA-256 values remain in the package manifest.

The existing [`rk-file-manifest-delta-v4.06-v4.6.csv`](rk-file-manifest-delta-v4.06-v4.6.csv) records 98 skin paths in the 4.6-labeled package: all 96 baseline entries are byte-identical, and two are added: `sideled_nr.png` (991 bytes, SHA-256 `046E82127DEDD3BAF9863D6C9B4A49F10CC7D4527479E2901F25A2838EF5B4F0`) and `sideled_ov.png` (997 bytes, SHA-256 `861FE9DE0F189F99853DB687C186614812507DF39FD36928AFC3893D366CDB5F`). The 4.6 extracted payload is not present in this workspace, so those recorded 4.6 hashes could not be independently rehashed here. The 4.6 driver’s references to the two added assets are documented in the [Side LED static audit](rk-v4.6-side-led-static-audit.md), including the code addresses and path role.

## What the census establishes

- The installed 4.06 skin directory has 91 PNG files, four BMP menu-state files, and one 520-byte `mak.skn` file. Every PNG/BMP is readable as an image by Pillow; dimensions and pixel modes are listed below.
- The filename suffix counts are 39 `_nr`, 36 `_ov`, and four `_dn`; 17 files have none of those suffixes. These names suggest normal/hover/down states, but filenames do not prove custom-control state semantics.
- `main_nr.png` and `welcome.png` are 1500x900 backgrounds by dimensions; `pickfundlg.png` is 825x450. Other files include 131x131 `Colorwheel.png`, 26x160 `audio_bar.png`, 300x8 `rgbbar_*` assets, and 14x14 slider thumbs. Those names and dimensions suggest UI roles only; this report does not bind assets to exact controls or windows.
- `mak.skn` has no recognized image format. Its measured byte entropy is 7.60 bits/byte and 206/520 bytes are printable ASCII; these measurements do not identify its encoding, compression, or format.
- A literal byte search of the installed 4.06 `DeviceDriver.exe` found no `.png`, `.bmp`, `.skn`, `skins`, or `Skins` tokens. This limited raw-string check does not rule out constructed paths, framework resource loading, or indirect references. The 4.6 Side LED audit does recover specific references to its two new skin files.

## Per-file metadata

`nr`/`ov`/`dn` in the last column are filename suffixes only. “unknown” for `mak.skn` means Pillow did not classify it as PNG/BMP; no proprietary decoder was available.

| File | Bytes | Dimensions | Format | Pixel mode / note | Suffix |
| --- | ---: | --- | --- | --- | --- |
| `add_nr.png` | 471 | 20x20 | PNG | RGBA | nr |
| `add_ov.png` | 471 | 20x20 | PNG | RGBA | ov |
| `audio_bar.png` | 8144 | 26x160 | PNG | RGBA | — |
| `bar_nr.png` | 2934 | 240x8 | PNG | RGBA | nr |
| `bar_ov.png` | 2937 | 240x8 | PNG | RGBA | ov |
| `bigexit_nr.png` | 3042 | 30x30 | PNG | RGBA | nr |
| `bigexit_ov.png` | 3144 | 30x30 | PNG | RGBA | ov |
| `bigmin_nr.png` | 2912 | 30x30 | PNG | RGBA | nr |
| `bigmin_ov.png` | 2969 | 30x30 | PNG | RGBA | ov |
| `btn_nr.png` | 3093 | 350x38 | PNG | RGBA | nr |
| `btn_ov.png` | 3071 | 350x38 | PNG | RGBA | ov |
| `buy_nr.png` | 3466 | 30x30 | PNG | RGBA | nr |
| `buy_ov.png` | 3457 | 30x30 | PNG | RGBA | ov |
| `cfg_nr.png` | 3488 | 36x36 | PNG | RGBA | nr |
| `cfg_ov.png` | 3881 | 36x36 | PNG | RGBA | ov |
| `check_dn.png` | 4229 | 24x24 | PNG | RGBA | dn |
| `check_nr.png` | 3392 | 24x24 | PNG | RGBA | nr |
| `check_ov.png` | 3177 | 24x24 | PNG | RGBA | ov |
| `circle_dn.png` | 3236 | 23x23 | PNG | RGBA | dn |
| `circle_nr.png` | 3435 | 23x23 | PNG | RGBA | nr |
| `clear_nr.png` | 578 | 20x20 | PNG | RGBA | nr |
| `clear_ov.png` | 574 | 20x20 | PNG | RGBA | ov |
| `Colorwheel.png` | 28974 | 131x131 | PNG | RGBA | — |
| `custom_nr.png` | 3742 | 36x36 | PNG | RGBA | nr |
| `custom_ov.png` | 3799 | 36x36 | PNG | RGBA | ov |
| `del_nr.png` | 3025 | 20x20 | PNG | RGBA | nr |
| `del_ov.png` | 3059 | 20x20 | PNG | RGBA | ov |
| `direct_down_nr.png` | 3181 | 30x30 | PNG | RGBA | nr |
| `direct_down_ov.png` | 3206 | 30x30 | PNG | RGBA | ov |
| `direct_left_nr.png` | 3159 | 30x30 | PNG | RGBA | nr |
| `direct_left_ov.png` | 3171 | 30x30 | PNG | RGBA | ov |
| `direct_right_nr.png` | 3152 | 30x30 | PNG | RGBA | nr |
| `direct_right_ov.png` | 3168 | 30x30 | PNG | RGBA | ov |
| `direct_up_nr.png` | 3166 | 30x30 | PNG | RGBA | nr |
| `direct_up_ov.png` | 3195 | 30x30 | PNG | RGBA | ov |
| `exit_nr.png` | 3033 | 20x20 | PNG | RGBA | nr |
| `exit_ov.png` | 3128 | 20x20 | PNG | RGBA | ov |
| `export_nr.png` | 3079 | 20x20 | PNG | RGBA | nr |
| `export_ov.png` | 3130 | 20x20 | PNG | RGBA | ov |
| `home_nr.png` | 3483 | 30x30 | PNG | RGBA | nr |
| `home_ov.png` | 3475 | 30x30 | PNG | RGBA | ov |
| `icon_input_delay.png` | 3371 | 20x20 | PNG | RGBA | — |
| `icon_input_delay2.png` | 3386 | 20x20 | PNG | RGBA | — |
| `icon_input_down.png` | 338 | 20x20 | PNG | RGBA | — |
| `icon_input_up.png` | 336 | 20x20 | PNG | RGBA | — |
| `icon_macro.png` | 1048 | 48x48 | PNG | RGBA | — |
| `icon_menu.png` | 273 | 25x20 | PNG | RGBA | — |
| `import_nr.png` | 3156 | 20x20 | PNG | RGBA | nr |
| `import_ov.png` | 3212 | 20x20 | PNG | RGBA | ov |
| `index1.png` | 3204 | 18x18 | PNG | RGBA | — |
| `index2.png` | 3332 | 18x18 | PNG | RGBA | — |
| `key_nr.png` | 3175 | 36x36 | PNG | RGBA | nr |
| `key_ov.png` | 3139 | 36x36 | PNG | RGBA | ov |
| `lang_nr.png` | 1075 | 250x38 | PNG | P | nr |
| `lang_ov.png` | 1064 | 250x38 | PNG | P | ov |
| `light_nr.png` | 3614 | 36x36 | PNG | RGBA | nr |
| `light_ov.png` | 3629 | 36x36 | PNG | RGBA | ov |
| `logo.png` | 4988 | 129x50 | PNG | RGBA | — |
| `logo_kb.png` | 3090 | 67x26 | PNG | RGBA | — |
| `long_nr.png` | 1220 | 451x38 | PNG | L | nr |
| `long_ov.png` | 1206 | 451x38 | PNG | L | ov |
| `macro_nr.png` | 3072 | 36x36 | PNG | RGBA | nr |
| `macro_ov.png` | 3092 | 36x36 | PNG | RGBA | ov |
| `main_nr.png` | 901395 | 1500x900 | PNG | RGBA | nr |
| `mak.skn` | 520 | — | unknown | binary; H=7.60; printable=206/520 | — |
| `menu_nr.bmp` | 12054 | 200x20 | BMP | RGB | nr |
| `menu_ov.bmp` | 12054 | 200x20 | BMP | RGB | ov |
| `menusub_nr.bmp` | 12054 | 200x20 | BMP | RGB | nr |
| `menusub_ov.bmp` | 12054 | 200x20 | BMP | RGB | ov |
| `min_nr.png` | 2890 | 20x20 | PNG | RGBA | nr |
| `min_ov.png` | 2951 | 20x20 | PNG | RGBA | ov |
| `modify_nr.png` | 3027 | 20x20 | PNG | RGBA | nr |
| `modify_ov.png` | 3273 | 20x20 | PNG | RGBA | ov |
| `pickfundlg.png` | 4844 | 825x450 | PNG | RGB | — |
| `radio_dn.png` | 3654 | 19x18 | PNG | RGBA | dn |
| `radio_nr.png` | 3527 | 19x18 | PNG | RGBA | nr |
| `radio_ov.png` | 3231 | 19x18 | PNG | RGBA | ov |
| `record_del_nr.png` | 3035 | 20x20 | PNG | RGBA | nr |
| `record_del_ov.png` | 3059 | 20x20 | PNG | RGBA | ov |
| `record_down_nr.png` | 398 | 20x20 | PNG | RGBA | nr |
| `record_down_ov.png` | 398 | 20x20 | PNG | RGBA | ov |
| `record_up_nr.png` | 3131 | 20x20 | PNG | RGBA | nr |
| `record_up_ov.png` | 3129 | 20x20 | PNG | RGBA | ov |
| `rgbbar_nr.png` | 2944 | 300x8 | PNG | RGBA | nr |
| `rgbbar_ov.png` | 2944 | 300x8 | PNG | RGBA | ov |
| `screen_nr.png` | 250 | 36x36 | PNG | RGBA | nr |
| `screen_ov.png` | 256 | 36x36 | PNG | RGBA | ov |
| `short_nr.png` | 1235 | 376x39 | PNG | L | nr |
| `short_ov.png` | 1218 | 376x39 | PNG | L | ov |
| `slider.png` | 3082 | 14x14 | PNG | RGBA | — |
| `slider2.png` | 2983 | 14x14 | PNG | RGBA | — |
| `start_nr.png` | 3221 | 36x36 | PNG | RGBA | nr |
| `start_ov.png` | 3229 | 36x36 | PNG | RGBA | ov |
| `sw_dn.png` | 3948 | 89x27 | PNG | RGBA | dn |
| `sw_nr.png` | 3152 | 89x27 | PNG | RGBA | nr |
| `welcome.png` | 998582 | 1500x900 | PNG | RGBA | — |

## Limits and next static step

This report verifies the installed skin payload’s metadata and narrows the 4.6
change set, but it does not reconstruct the `mak.skn` format or establish the
complete skin-loader call graph. Individual asset-to-control bindings, image
crop/alpha behavior at runtime, and the 4.6 payload’s independent on-disk
verification remain open. The earlier
[resource/localization audit](rk-resource-localization-audit.md) contains
selected visual observations and the broader UI/resource context. The
package-wide PE and blob scan for `mak.skn` is documented in the
[format/consumer follow-up](rk-mak-skn-package-scan-followup.md).
