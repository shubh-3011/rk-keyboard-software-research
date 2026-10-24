# RK package membership and version boundaries — 2026-10-19

## Scope and method

This report audits the repository's local package manifests, package-delta CSV,
resource inventories, and installer notes. It does not re-extract or execute a
vendor package. No RK process was launched; no HID, serial, Bluetooth, or
keyboard interface was opened; no updater, firmware, or bootloader operation
was attempted.

The principal evidence files are the [installed 4.06 manifest](rk-installed-package-manifest.csv),
[4.6 extraction manifest](rk-4.6-package-manifest.csv),
[row-level comparison](rk-file-manifest-delta-v4.06-v4.6.csv),
[4.6 resource inventory](rk-v4.6-resource-inventory.md), and
[official package snapshot](rk-v4.6-package-snapshot.md). Hashes below are
SHA-256 values from those manifests or the hash-pinned installer report.

## What is actually represented

| Evidence set | Identity and inventory | Boundary |
|---|---|---|
| Installed Windows Hub snapshot labeled 4.06 | `docs/rk-installed-package-manifest.csv`: 810 installed-tree paths. It includes `DeviceDriver.exe`, `Dev/01AF/Update.exe`, `InitSetup.dll`, `uninstall.dll`, and generated `unins000.exe`/`.dat`. | This is an installed tree, not the original 4.06 setup executable. |
| Official Windows Hub setup labeled 4.6 | Outer `RK_Keyboard_Software_Setup_V4.6_20261015.exe`: 96,720,579 bytes; SHA-256 `47A1FC21C3AF548B93FA40D499584ABECB3341E62B15948AE537B78CA987AAD8`. Its statically extracted tree has 1,249 files / 104,009,969 bytes: 1,245 under `app/`, three under `fonts/`, and one under `localappdata/`. | The manifest is the extracted tree, not a post-install image. The app's `Cfg.ini` declares `Ver=0x406`; “4.6” is the setup snapshot label. |
| RK Drive Web App | One dated public web snapshot: seven reachable JavaScript bundles, 177 general keyboard descriptors, and two separate RK68 HE profiles. | This is neither a complete package catalog nor proof that every declared model feature is reachable on hardware. |

The official distribution report lists separate Web Driver, Hub Driver,
product-selected driver/firmware, and QMK/VIA routes. The local evidence does
not contain a complete downloaded package set for all those routes, OSes,
regions, revisions, or historical releases. The two Windows snapshots and one
Drive web snapshot therefore define the examined corpus, not all RK software.

## Main executable and helper identity

| Component | Installed 4.06 path and SHA-256 | 4.6 extraction path and SHA-256 | Finding |
|---|---|---|---|
| Main UI/driver | `DeviceDriver.exe`, 2,326,528 bytes; `C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6` | `app/DeviceDriver.exe`, 2,418,176 bytes; `8D8538DE3ADA5FCF80E00C13B364B17ACEFA708480E102EC1E6A0B1309639AE9` | Different file. The 4.6-labeled copy has the same embedded `1.0.6.8` file/product version as 4.06, but its sections differ. The label does not mean its source-level graph is covered by the 4.06 address map. |
| Updater | `Dev/01AF/Update.exe`, 2,109,952 bytes; `27894463B0DFE5BC3F5DC19D4D3351D9DFB692C402BF277BDE3889D37E4A206C` | `app/Dev/01AF/Update.exe`, same size and SHA-256 | Byte-identical in these two snapshots. Existing 4.06 updater findings apply to this exact 4.6 member, but not to other updater versions. |
| Installer helper | `InitSetup.dll`, 69,000 bytes; `59DB7BFD9A92CC9A0998260807F17C536EC71159B727DF10D08B998BC94DE301` | `app/InitSetup.dll`, same size and SHA-256 | Byte-identical in these two snapshots. Presence alone does not prove which 4.6 setup callback invokes it. |
| Uninstall helper | `uninstall.dll`, 146,944 bytes; `9CA1EBC49998B8B2971DEBC1776E7AFF6086AEB86ADCCA6CFB95E9FB399EB03C` | `app/uninstall.dll`, same size and SHA-256 | Byte-identical in these two snapshots. This DLL is distinct from the generated `unins000.exe` and `.dat`. |
| Generated uninstaller | `unins000.exe`, 1,316,301 bytes; `B4CA28B192D5A50307D2B28F3323B58B39CB51EDD6682E75706CAC2DD69A4A14`; `unins000.dat`, 261,476 bytes; `584440EB2154BCC6881846D824C45B2C3074929D653BB0F5E3F306A746AA8F20` | Neither path appears in the extracted 4.6 payload manifest. | This records extraction absence only. It does not establish whether 4.6 setup would generate them when installed, nor their actions. |

The only profile-local update pair in either manifest is under profile
`01AF`: `Update.exe` and
`KB_762_1_v258A_p01AF_F90_8818_V90.0f.1.00.upf` (193,652 bytes;
SHA-256 `E21C11E023247AFC7FDBBE27548570240EFA5B646147741D5354EECB3041B628`).
The `.upf` is a packaged updater input, not firmware read from a keyboard. The
existing parser audit reports a declared section length inconsistent with the
sample's file size; package presence does not validate its contents or imply
firmware coverage for other profiles.

## Cross-version member delta

The normalized comparison maps the 4.6 `app/` directory to the installed root
and maps the separate `fonts/` directory to the old `font/` path. It excludes
`localappdata/RKKB/lang.ini` because that seed is outside the installed program
tree. Results are 743 identical paths, 50 changed, 455 added, and 17 present
in the installed 4.06 snapshot but absent from the extracted 4.6 application
payload. These counts compare recorded trees; they are not a claim about
installer overwrite/delete behavior.

The 50 changed rows include `Cfg.ini`, 15 profile `.ini` files,
`DeviceDriver.exe`, all seven localized `Text/*/text.xml` files, LED
dictionaries, two GIFs, 12 PNGs, and effect text assets. `Update.exe`,
`InitSetup.dll`, and `uninstall.dll` remain hash-identical. The 455 additions
are primarily added profile and model-associated data; profile and resource
counts are summarized below.

For exact traceability, these are the 17 baseline-only rows (path, baseline
size, baseline SHA-256). Their classification comes from the path/hash
comparison; it does not explain why a vendor package changed them.

| 4.06 path absent from extracted 4.6 app payload | Bytes | Baseline SHA-256 |
|---|---:|---|
| `Dev/014D/Cartoon/flower.txt` | 320 | `DE6F110052F09F5ED6B171F8A96DD631955A002FCF13ACF0CCAE89BE35D65F24` |
| `Dev/014D/Cartoon/stream_unit.txt` | 269 | `5419A7E672949EA68AF2E53ACDC6BE5B3B6A9F72A495089FDB1FD5CF8481BF81` |
| `Dev/01A2/Cartoon/flower.txt` | 299 | `B9BD962D308120714D2398F6AB16DACDA482A424BDA4EBD2AD84A01372C06522` |
| `Dev/01A2/Cartoon/stream_unit.txt` | 401 | `F5A376BFB22CF432B4114E9E0381DA072F7D9D186152C39E8AFAFABAA4922228` |
| `Dev/01C7/en/led.xml` | 1,106 | `946EF3B1677B2174C4E006F04C15BC3A88FB65E3D2E6D49747F8E06595B96166` |
| `Dev/01C7/KB.ini` | 5,350 | `9E4381CBC15A9F9BF14F5EAB33D345B33234B521A7999684C348C66D343362FD` |
| `Dev/01C7/sc/led.xml` | 872 | `B304E6E77B0E0909CFDC75B947051BAC2CBA3642370965A049816CF5967286B2` |
| `Dev/01D6/Cartoon/flower.txt` | 299 | `9DCA9DF603F0DE62B1BDF2AD9B0188452A21A507E297C2F38908A4A26B529E9A` |
| `Dev/01D6/Cartoon/stream_unit.txt` | 305 | `CF9B083C91AE4A371524432053519D7EB0254DA1C3EFA278A845B6C905DE4A4A` |
| `Dev/01D6/Cartoon/wheel_unit.txt` | 317 | `FE9C5BF20DE791392C9052C89FA192E66FF26464BB46DA92A65D0D30E2A6556D` |
| `Dev/01D6/ET/audiobar.txt` | 297 | `C71D73ED814CAC599E5BE178C3EADC6E519D63C371054066BC49FDB194E49F4E` |
| `Dev/01D6/ET/flower.txt` | 288 | `74BA4F760239D8EDC01ED72263320630656D5B3FB42D1D0ED58F5085DC790073` |
| `Dev/01D6/ET/happy.txt` | 225 | `3360CB4DB0B0A82D63BC2B46548864FB6BEC01FF1286765E18AFE9B14EAA5220` |
| `Dev/01D6/ET/stream_h.txt` | 294 | `3E047BDCB0498C496C1580FF8B79CD991FE3CE2B4062F2324943D27B57BE03C2` |
| `font/Open Sans Regular.ttf` | 217,360 | `E64E508B2AA2880F907E470C4550980EC4C0694D103A43F36150AC3F93189BEE` |
| `unins000.dat` | 261,476 | `584440EB2154BCC6881846D824C45B2C3074929D653BB0F5E3F306A746AA8F20` |
| `unins000.exe` | 1,316,301 | `B4CA28B192D5A50307D2B28F3323B58B39CB51EDD6682E75706CAC2DD69A4A14` |

The baseline-only `01C7` directory is the unregistered configuration found in
the 4.06 inventory; it is not among the 265 named 4.6 profiles. Several
baseline-only Cartoon/ET text files belong to three profile directories. The
4.06 regular font hash is not present at the normalized `font/` location or
under the 4.6 package's three `fonts/` files. The exact UI/font consumers are
not fully mapped, so this is a content difference, not a confirmed rendering
defect. The two generated uninstaller files are a separate installation-stage
unknown.

## Resource-member coverage differences

| Resource | Installed 4.06 | 4.6-labeled extraction | What the paths establish |
|---|---:|---:|---|
| Profile configuration | 189 `KB.ini` files: 188 named profiles plus unregistered `01C7` | 265 `KB.ini` files, all with catalog rows | 77 more named profiles in the 4.6 catalog; profile records are not verified model support. |
| Unique key-layout records | 90 | 140 | All 90 common IDs have identical geometry; 50 are added and none removed. |
| Per-profile key/artwork PNGs | 204 files across 102 profiles, both `keyimg.png` and `kbled.png` | 338 files across 170 profiles; 168 have both files and two have one each | The 4.6 package has 95 of 265 profiles with neither artwork file. The files' selection and control bindings remain a separate code question. |
| Skin/chrome files | 96 | 98 | The 96 old files are byte-identical; `skins/sideled_nr.png` (991 bytes, SHA-256 `046E82127DEDD3BAF9863D6C9B4A49F10CC7D4527479E2901F25A2838EF5B4F0`) and `skins/sideled_ov.png` (997 bytes, SHA-256 `861FE9DE0F189F99853DB687C186614812507DF39FD36928AFC3893D366CDB5F`) are added. |
| Bundled Open Sans fonts | Four files: ExtraBold, Light, Regular, Semibold | Three files: ExtraBold, Light, Semibold | ExtraBold, Light, and Semibold are hash-identical. Regular (217,360 bytes; SHA-256 `E64E508B2AA2880F907E470C4550980EC4C0694D103A43F36150AC3F93189BEE`) is absent from the 4.6 extracted font files. |
| Screen sample GIFs | Two, for `0193` and `01B8` | Two, for `0193` and `01B8` | Sample asset presence does not establish that all screen features or models are covered. |
| Profile-local firmware/update | One `.upf` and one `Update.exe`, under `01AF` | The same single `.upf` and `Update.exe`, byte-identical | No firmware/update image catalog for the other profile rows is present in these package manifests. |
| Side LED resources | No recorded SideLed group | One profile `02B4` has `sideled.png` and four localized label files; profile `0258` also sets `ShowSideLED` but has neither asset group | Resource absence for `0258` is proven in this extraction; whether runtime fallback exists is unresolved. |

For 4.6, the extracted tree also has seven UI text XMLs, five generic LED
label XMLs, 16 profile LED XMLs, 305 profile ET files, 106 profile Cartoon
files, 78 global ET files, 13 global Cartoon files, and an 18-byte
`localappdata/RKKB/lang.ini` seed. These are manifest-backed counts; they do
not establish that each label, pattern, or seed file is used at runtime.

## Installer-content boundary

The outer 4.6 installer is a separate 96 MB PE with an appended setup-data
overlay; it is not one of the 1,249 extracted member paths. Static metadata
identifies Inno Setup 5.3.3 Unicode and seven languages. The recorded overlay
is 96,445,123 bytes, SHA-256
`60AA03DB85A5ACCF7C76861570AF23C1332E08272F913AAEFF0646CC8E4D69BC`.
The recorded static tools did not recover a compiled 4.6 PascalScript stream,
`.iss` source, or generated 4.6 uninstaller log. No `unins000.exe` or
`unins000.dat` appears in the extracted 4.6 tree. The installer was not run;
therefore callbacks, install actions, uninstaller generation, and runtime
side effects remain unknown. The byte-identical 4.06 helpers and 4.06 Inno
script evidence do not prove that the 4.6 installer performs the same actions.

## Takeaway

The manifests establish a strong path/size/hash boundary for two Windows
snapshots and one small web-bundle snapshot. They also expose concrete content
asymmetries—especially the changed 4.6 main driver, missing 01C7 profile data,
reduced font set, uneven profile artwork, one bundled firmware package, and
generated-uninstaller gap. They do not identify why RK made those changes,
prove an installer deletes any baseline file, or establish compatibility for
all models/releases.

## Installed-tree revalidation — 2026-10-25

The current `C:\Program Files (x86)\RK Keyboard Software` tree was rechecked
read-only against `rk-installed-package-manifest.csv` with
[`verify_installed_manifest.py`](../scripts/verify_installed_manifest.py).
It found 810 manifest paths and 810 installed files, with zero missing paths,
extra paths, size mismatches, SHA-256 mismatches, or unsafe manifest paths.
This confirms that the locally installed tree still matches the 4.06 snapshot
at revalidation time; it does not identify the original installer or establish
that the program is currently running.
