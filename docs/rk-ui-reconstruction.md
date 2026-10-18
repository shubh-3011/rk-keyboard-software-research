# RK Windows UI reconstruction

## Local source package

The installed 4.06 package is under `C:\Program Files (x86)\RK Keyboard Software`.
The app reads these resources from that local folder at runtime. It does not
copy them into the public repository or the generated executable. Product
photos shown in the device overview instead come from the official RK Drive
image catalog over HTTPS.

| Resource | Local path | Use in RK Rebuild |
| --- | --- | --- |
| Main shell background | `skins/main_nr.png` (1500 × 900) | Window background |
| RK logo | `skins/logo.png` (129 × 50) | Header branding |
| Window controls | `skins/bigmin_{nr,ov}.png`, `skins/bigexit_{nr,ov}.png` | Minimize and close buttons, normal and hover states |
| Navigation icons | `skins/home_{nr,ov}.png`, `key_{nr,ov}.png`, `light_{nr,ov}.png`, `macro_{nr,ov}.png`, `custom_{nr,ov}.png` | Matching app sections and hover states |
| Action button states | `skins/btn_{nr,ov}.png` | Standard buttons, normal and hover states |
| Font family | `font/Open Sans*.ttf` | Main window and dialogs |
| Tray icon | `appico.ico` | Notification area |
| Profile illustrations | `Dev/<code>/kbled.png`, `keyimg.png`, `sideled.png` | Device overview and clickable keymap artwork |

The package's `Cfg.ini` declares `Title=RK Keyboard`, uses a main text color
of RGB 220, 220, 220, and sets the selected list accent to RGB 201, 81, 0.
The reconstructed shell uses that text/accent palette and the official image
states. The app tries the selected profile code first. When a newer catalog
code has no corresponding folder in an older local install, it matches the
profile family against the installed `DevName` list and uses the first
compatible image set.

For the local S98 profile, the installed package identifies code `0174` as
`RK S98RGB`; its keyboard art is `Dev/0174/kbled.png` and `Dev/0174/keyimg.png`.
The current 4.6 model catalog also lists S98 variants under codes such as
`021E`, so family fallback is necessary when using that catalog with the
older installed package.

## Implementation

`rebuild/windows/RKRebuild.cs` loads the RK skin from the detected installation
path, or from the folder selected by the user. The UI uses the original shell
image and RK state assets without embedding those files. The keymap page uses
the profile illustration as its base and places local-draft click regions over
the catalog's per-key coordinates. Changing a displayed label only saves a
local draft.

The static analysis in [`rk-resource-localization-audit.md`](rk-resource-localization-audit.md)
found that feature windows are mostly built dynamically at runtime. The 520-byte
`skins/mak.skn` format remains opaque; the static dialog inventory does not
recover every widget coordinate, skin binding, or message route. As a result,
this work restores the exact package artwork, palette, font family, and button
states, while the placement of the community app's feature controls remains a
reconstruction rather than a pixel-measured copy.

REA's Ghidra workflow also opened the installed `DeviceDriver.exe` as an
immutable native x86 PE for static analysis. The analyzed file SHA-256 is
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`; the
summary reported 13,735 recovered procedures and 3,838 defined strings.
Evidence ID: `ev_7046f0bac41c3e281e41732de87069f947f65906f269780d40f6d71acd16b444`.
These inventory counts do not prove that all code or strings were identified.
This pass did not execute the RK program or observe keyboard traffic.

## Hardware boundary

The native app reads package files for its shell and uses the official image
catalog for model photography. Device discovery uses the Windows SetupAPI
present-device list and USB/HID PnP properties only; it does not open the keyboard's HID interface or send
device reports, configuration writes, screen transfers, or firmware commands.
PnP metadata does not expose the live RGB mode or color.
