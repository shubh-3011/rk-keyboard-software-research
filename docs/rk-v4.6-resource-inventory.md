# RK 4.6-labeled package resource and profile-asset inventory

## Scope and identity

This inventory classifies resources in the statically extracted package
identified as `RK_Keyboard_Software_Setup_V4.6_20261015.exe`. The package's
own `Cfg.ini` still says `Ver=0x406`; “4.6-labeled” describes the installer
snapshot and does not assert that every embedded component is a distinct 4.6
runtime version. The installer was not run. No RK executable was launched,
and no device interface or keyboard report was used.

The extracted tree contains 1,249 files totaling 104,009,969 bytes. The new
[aggregate resource-group inventory](rk-resource-group-inventory-v4.6.csv)
assigns every file exactly once to one of 17 path/role groups. The separate
[profile asset inventory](rk-model-resource-asset-inventory-v4.6.csv)
records per-profile files for all 265 configured models. The package's
original vendor payload is not included in this repository; these tables
contain path, size/hash metadata, filenames, counts, and profile names.

The audit script verifies the extracted tree's full path set, byte sizes, and
SHA-256 values against the existing package manifest before writing either
table. It also reconciles all 265 catalog rows with `Cfg.ini` `DevName` rows
and `Dev/<code>/KB.ini` files. Recreate the inventories after obtaining and
extracting the same package:

```powershell
python scripts/audit_rk46_resource_inventory.py `
  --root "C:\path\to\extracted\package" `
  --manifest docs/rk-4.6-package-manifest.csv `
  --catalog models-4.6.json `
  --groups-output docs/rk-resource-group-inventory-v4.6.csv `
  --profiles-output docs/rk-model-resource-asset-inventory-v4.6.csv
```

## Resource findings

| Group | Files | Static finding |
| --- | ---: | --- |
| Application root and configuration | 5 | `Cfg.ini`, `DeviceDriver.exe`, two DLLs, and the app icon. |
| UI localization/text XML | 7 | Seven `Text/<locale>/text.xml` files. String/control reachability remains a separate question. |
| UI skins and chrome | 98 | The extracted `skins/` directory; individual runtime use is not fully mapped. |
| External font files | 3 | TTFs under the package's `fonts/` directory. |
| Generic localized LED labels | 5 | `Dev/{en,Japanese,Korean,sc,tw}/led.xml`. |
| Profile LED label XML | 16 | Profile-specific locale dictionaries. Labels do not assign meaning to serialized tuples. |
| Profile keyboard artwork | 338 | `keyimg.png` and/or `kbled.png` across 170 profiles (168 have both; two have one each). |
| Profile side-light artwork | 1 | One `sideled.png`, under profile `02B4`. |
| Profile `SideLed` resources | 4 | Four localized `SideLed/<locale>/led.xml` files, all under `02B4`. |
| Profile ET / Cartoon patterns | 305 / 106 | Local pattern files in per-profile directories. |
| Global ET / Cartoon patterns | 78 / 13 | Shared pattern files outside profile directories. |
| Profile screen/GIF resources | 2 | `screen.gif` files for profiles `0193` (RK S85) and `01B8` (RK N99); no complete screen-to-device route is implied. |
| Profile updater/firmware files | 2 | The model updater and `.upf` package under profile `01AF`. |
| Extracted localappdata seed | 1 | An 18-byte `localappdata/RKKB/lang.ini`; installer consumption is unresolved. |

The remaining resource groups are listed in the CSV with their own extension
counts, path examples, evidence basis, and unresolved role notes. Every row in
the package manifest was assigned; role classifications based on filenames
and directory structure are not claims about runtime execution.

## Per-profile resource gaps

All 265 catalog profiles have a matching `Cfg.ini` name record and
`KB.ini`. The per-profile CSV shows that artwork and optional resources are
not uniformly present. In particular, both `02B4` (`K71R Pro`) and `0258`
(`RK K99`) set the `ShowSideLED` profile option, but only `02B4` has
`sideled.png` and the four English, Japanese, simplified Chinese, and
traditional Chinese SideLed label files. `0258` has neither a side-light
image nor a `SideLed` locale directory in this package. Whether its UI uses a
fallback or whether the setting is stale remains unresolved.

The rows also distinguish general key diagrams, LED diagrams, profile-local
LED label XML, screen GIF/cache files, update packages, and ET/Cartoon data.
The table records file presence, not a model/firmware compatibility result.
The [profile catalog](rk-profile-catalog-v4.6-delta.md) and
[Side LED code trace](rk-v4.6-side-led-static-audit.md) provide the related
configuration and code evidence.

## Evidence boundary

- **Proven statically:** 1,249 paths, sizes, and hashes match the package
  manifest; 265 catalog/profile codes match both `Cfg.ini` and on-disk
  `KB.ini` files; all files receive one inventory classification; and the
  two Side LED profile directories differ as recorded above.
- **Inferred from path/name:** likely resource roles such as keyboard
  artwork, localized labels, patterns, and screen samples.
- **Unresolved:** exact UI reachability for every asset, whether every
  profile directory reflects a sold device, and the runtime fallback for
  profiles with declared features but missing assets. This snapshot does not
  cover every RK package, historical release, or hardware revision.
