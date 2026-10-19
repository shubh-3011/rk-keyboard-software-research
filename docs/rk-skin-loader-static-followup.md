# RK 4.06 skin loader and profile-art selection follow-up

## Scope and pinned inputs

This is a static analysis of the installed `DeviceDriver.exe` at
`C:\Program Files (x86)\RK Keyboard Software`. Its size is 2,326,528 bytes
and SHA-256 is
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`, matching
[`rk-installed-package-manifest.csv`](rk-installed-package-manifest.csv).
GNU `strings` and `objdump` were run against the file bytes only. No RK process,
updater, keyboard, or device interface was opened. There is no source for the
vendor 4.06 program in this repository; `rebuild/windows/` is a separate
clean-room project.

The installed skin files used for representative checks also match the
manifest: `main_nr.png` (901,395 bytes,
`707D25C3D452080778FF2429F7BF83B552AE6CD949411220B393055F43591D71`),
`welcome.png` (998,582 bytes,
`0C8AB58959D34306BA803ADA744E6C1C99FC49CAEA7BC73AE4959A746B88F2E2`), and
`mak.skn` (520 bytes,
`F0970E70282F3823B79BD3818D303DF5B479EE994902A49E33DE30901B93FA7D`). The
file-level sizes, dimensions, and pixel modes for the full installed skin set
are in the [asset metadata follow-up](rk-skin-asset-metadata-followup.md).

## Proven path and image-loading structure

`DeviceDriver.exe` stores the wide format string `%sskins\%s` at VA
`0x005CC958`. Multiple callsites pass that format and runtime path data to
internal string-format helper `0x00405590`; `0x00619518` is the runtime prefix
argument, whose value was not recovered here. The generated wide path is then
passed at the relevant callsites to thunk `0x00589116`, which jumps through
IAT slot `0x0059E9C0` for `gdiplus!GdipCreateBitmapFromFile`. Loaded image
wrappers hold the GDI+ status and returned image pointer in adjacent fields.
This confirms that the external `skins/` PNGs are file-loaded assets, not only
PE resources. It does not establish that every matching string is reached or
that the window later paints each loaded image.

| Asset/workflow | Static path and consumer evidence | What the bytes prove |
| --- | --- | --- |
| Main window artwork | `main_nr.png` is at `0x005D4E3C`; code at `0x00446D4B` formats it with `%sskins\%s` and `0x00619518`. `GdipCreateBitmapFromFile` is called at `0x00446DAC`; the resulting wrapper pointer is stored at global `0x0062AF78`. | A named main-art file is loaded into a persistent global wrapper. Exact MFC class ownership and paint-time use remain unresolved. |
| Welcome artwork and logo | In one code region, `logo.png` is formatted/loaded at `0x00464F07`/`0x00464F68` and stored at object offset `+0x74`; `welcome.png` is formatted/loaded at `0x00464F7B`/`0x00464FE0` and stored at `+0x78` of the same receiver. | The two files are selected together into adjacent object fields. “Welcome background” is inferred from the filename; draw geometry and window class are unresolved. |
| Function-pick artwork | `pickfundlg.png` is passed to the generic skin path builder at `0x0041E9D6`; the resulting path reaches `GdipCreateBitmapFromFile` at `0x0041EA3A`. | Static code loads this named picker image. Exact title/control mapping remains unresolved. |
| Lighting/color controls | `Colorwheel.png` is referenced at `0x004066D9`; `slider.png` at `0x0040660F`/`0x00406672`; `rgbbar_nr.png` and `rgbbar_ov.png` at `0x004067E6`/`0x00406809`. The strings and nearby image-object fields occur in the same initialization region. | These assets are grouped by code and names in a color/lighting-like initialization path. The control class and each widget binding are not established by this trace. |
| Audio visualization | `audio_bar.png` is formatted at `0x00424015` and loaded at `0x00424069`. | The file is consumed by a static GDI+ load path; its exact drawn area and runtime audio state are unresolved. |
| Menu bitmap states | `menu_nr.bmp`, `menu_ov.bmp`, `menusub_nr.bmp`, and `menusub_ov.bmp` have direct string references around `0x00433388`–`0x00433416`. | Code refers to all four state-named files. A full loader/paint route was not recovered in this follow-up. |
| Edit/action controls | Code contains direct references to `add`, `del`, `modify`, `import`, `export`, `record_*`, and `radio_*` image names at multiple sites including `0x00409B2C`–`0x00409CE7` and `0x004279DE`–`0x0042829F`. | The binary selects these named sprites in UI construction paths. It does not by itself bind every sprite to one localized caption or control ID. |

The generic string and the examples above have no locale directory component.
The separate language workflow loads `Text/<locale>/text.xml` and localized
LED tables; see the [resource/localization audit](rk-resource-localization-audit.md)
and [language-module loader follow-up](rk-v406-language-satellite-loader-api-followup.md).
The `lang_nr.png`/`lang_ov.png` image names do have code references, but this
trace does not prove they are the images for the `tc_adv_str13` language
setting or connect them to a particular control ID.

## Profile artwork selection and fallback

A separate helper at `0x004571A0` builds model-art paths with the format
`%sDev\%04X\%s` (format VA `0x005D4EC4`), calls `PathFileExistsW` through
IAT `0x0059E558` at `0x0045720D`, and on a present path delegates image
construction to `0x00416B50`; that helper calls
`GdipCreateBitmapFromFile` at `0x00416B97`.

At caller `0x0041A748`, a global predicate selects between two branches. One
branch requests profile-local `kbled.png`. The other first requests
`keycfg.png`; if the helper returns no image, it requests `keyimg.png` for the
same profile. These names are therefore **not** all `skins/` assets:
`keyimg.png`, `kbled.png`, and the attempted `keycfg.png` are under
`Dev/<profile>/`. The installed tree has 102 `keyimg.png`, 102 `kbled.png`, and
zero `keycfg.png` files across its profile directories. Thus the static
fallback for `keycfg.png` is relevant to this package snapshot, although the
runtime branch chosen and the pixels actually shown were not observed. The
model-by-model counts are independently tracked in the
[per-profile asset inventory](rk-model-resource-asset-inventory.csv).

## Referenced but absent assets; unresolved SKN file

The driver has direct path-building callsites for `%sskins\power_empty.png`,
`%sskins\power_full.png`, and `%sskins\power_charging.png` at
`0x0045850D`, `0x004585DE`, and `0x004586A4`. Each formatted path flows into
`GdipCreateBitmapFromFile` at `0x0045856E`, `0x00458634`, and `0x004586FA`,
respectively. None of the three files exists in the installed skin directory,
and none appears in the complete 4.6 package manifest. The names suggest
power-state imagery, but whether these branches run, whether a caller supplies
an alternate root, and whether the missing loads have any visible effect are
unresolved. This is a proven code-to-path reference and a proven package-file
absence, not proof of a user-visible defect.

`mak.skn` is present in both package inventories and byte-identical across the
recorded 4.06/4.6 delta. A full ASCII and UTF-16 string scan of the pinned
4.06 driver found neither `mak.skn` nor a `.skn` extension literal, and no
such pointer was identified in its code. The file itself remains an opaque
520-byte blob with no recognized image signature. This provides no static
consumer or format identification; it does not rule out an indirect or
external-library consumer.

Other string-pool entries such as `button_nr.png` and
`icon18x18\exit_nr.png` do not have a direct code-pointer reference in the
scan. They are not counted as proven runtime loads. The `icon18x18\exit_ov.png`
string does have a code reference, but its consumer was not followed to an
image loader and the corresponding directory is absent, so that remains only
a candidate.

## Evidence boundary

**Proven statically:** the hash-pinned driver constructs skin/profile paths,
loads multiple external PNGs through GDI+, stores image wrappers in object or
global fields, selects/falls back among profile artwork names, and contains
three references to power-named files absent from both package inventories.

**Inferred:** filenames such as `welcome`, `Colorwheel`, `audio_bar`, and
`power_*` describe likely UI roles; file names and nearby code do not prove
visible labels, final drawing, or runtime branch execution.

**Unresolved:** exact MFC class ownership for every loader, all control-to-sprite
bindings, the complete rendering/alpha/cropping path, why power-named assets
are absent, how/if `mak.skn` is consumed, and the `mak.skn` format. The 4.6
Side LED assets are already tied to code references in the
[4.6 Side LED audit](rk-v4.6-side-led-static-audit.md); this follow-up adds
4.06 loader evidence and does not revise that separate binary’s analysis.
