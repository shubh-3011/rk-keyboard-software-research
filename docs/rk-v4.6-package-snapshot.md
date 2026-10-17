# RK Keyboard Software 4.6 package snapshot

## Source and acquisition

The snapshot reviewed here is the Windows **Keyboard Hub Driver** linked from
RK's official driver-download page. The installer identifies itself as
`RK_Keyboard_Software_Setup_V4.6_20261015.exe`; it was downloaded on
2026-10-18 from the official media URL below. The downloaded installer is
96,720,579 bytes with SHA-256
`47A1FC21C3AF548B93FA40D499584ABECB3341E62B15948AE537B78CA987AAD8`.

- Official download page: <https://en.rkgaming.com/download/>
- Official installer URL:
  <https://en.rkgaming.com/media/RK_Keyboard_Software_Setup_V4.6_20261015_N87rjnh.exe>
- Extraction utility: `innoextract 1.9`, obtained from its project site after
  checking the published SHA-256 for the Windows archive. The archive hash was
  `6989342C9B026A00A72A38F23B62A8E6A22CC5DE69805CF47D68AC2FEC993065`.

The installer was **not run**. The archive was statically extracted with
`innoextract`; neither RK's application nor updater was launched. No device
interface was opened and no keyboard command was sent.

## Derived inventory

The extracted root contains 1,249 files totaling 104,009,969 bytes. This
includes the `app`, `fonts`, and `localappdata` directories. The `app`
directory contains 1,245 files, including 265 `KB.ini` profiles and
`DeviceDriver.exe`. Static catalog extraction found 265 named model profiles
and 140 unique layouts; see the [catalog delta](rk-profile-catalog-v4.6-delta.md)
for a field-by-field comparison with the 4.06 installed baseline.

The package's public installer label is 4.6, but its extracted `Cfg.ini`
contains `Ver=0x406`, the same internal configuration value as the installed
4.06 baseline. The catalog report preserves this distinction. “4.6” here
identifies the official installer/package snapshot, not a claim that every
embedded component reports an internal 4.6 version.

The full extracted tree's relative paths, byte sizes, and SHA-256 hashes are
recorded in [`rk-4.6-package-manifest.csv`](rk-4.6-package-manifest.csv).
The manifest contains metadata only; it does not redistribute the package.
Recreate it after static extraction with:

```powershell
python scripts/create_package_manifest.py `
  "C:\path\to\extracted\package" `
  docs/rk-4.6-package-manifest.csv
```

The 4.6 `DeviceDriver.exe` SHA-256 is
`8D8538DE3ADA5FCF80E00C13B364B17ACEFA708480E102EC1E6A0B1309639AE9`.
The 4.06 baseline driver hash is
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
By contrast, `Dev/01AF/Update.exe` is 2,109,952 bytes and has the exact
4.06 updater SHA-256 `27894463B0DFE5BC3F5DC19D4D3351D9DFB692C402BF277BDE3889D37E4A206C`.
Its bundled `.upf` is also byte-identical to the 4.06 package:
193,652 bytes, SHA-256
`E21C11E023247AFC7FDBBE27548570240EFA5B646147741D5354EECB3041B628`.
`InitSetup.dll` and `uninstall.dll` likewise match the hashes recorded for
4.06. Thus the 4.06 updater, UART, firmware-readback, installer-helper, and
uninstaller-component findings apply to those identical files in this
package. This hash identity does not validate the `.upf` as a firmware image
or demonstrate a safe firmware-copy operation; see the
[firmware readback audit](rk-firmware-readback-audit.md).

The 4.6-labeled `DeviceDriver.exe` is the changed main binary, and its
version-specific API/address evidence is tracked separately in the
[native-binary delta audit](rk-v4.6-native-binary-delta-audit.md). That delta
does not yet reconstruct the new driver's call graph.

## Scope and limits

This is one official Windows Hub Driver package snapshot, not all RK
software. RK's current download page separately presents a cross-platform Web
Driver, Hub Driver, and model-specific driver/firmware selection; it lists
M75 HE, X87 HE, and RK68 HE as unsupported by its general Web Driver. That
means this package alone cannot establish coverage of every product, model
revision, region, protocol, firmware, or official configurator. The public
profile catalog is evidence of software configuration entries, not proof of
physical-device compatibility.

Only original analysis, derived metadata, and tooling are published here.
The installer, executables, libraries, firmware, fonts, images, and other
vendor payloads remain excluded. Findings separate observed static structure,
inference, and unresolved questions; see [coverage](../COVERAGE.md).
