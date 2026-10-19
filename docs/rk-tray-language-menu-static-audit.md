# RK tray language menu: static mapping audit

## Scope and artifacts

This audit follows the generated rows in the right-click tray menu of the
installed RK 4.06 `DeviceDriver.exe`. It maps each populated row to the
configured language label, locale directory, and command ID. It does not
establish the command-selection handler or runtime effect.

The installed artifacts are hash-pinned in
[`rk-installed-package-manifest.csv`](rk-installed-package-manifest.csv) and
were rechecked for this audit:

| Artifact | SHA-256 |
| --- | --- |
| `DeviceDriver.exe` | `C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6` |
| `Cfg.ini` | `1A9796E706FA64B1821417EFDA080D481E202FFCF941AA97E6A78EFE3A32BADD` |
| `Text/en/text.xml` | `85B26E0C7CD8317ADEB136D37B6877601B0C3E7F6FB072867F937AA46C73DE8C` |

The executable was inspected statically. It was not launched, and no device
interface was opened or written.

## Table initialization and menu construction

The ten-row text table begins at VA `0x00612B90`; each row is `0x78` bytes.
The data is not embedded in the executable's raw `.data` bytes: this address
lies in the section's zero-initialized virtual tail. The configuration loader
at approximately `0x00454549`–`0x00454618` fills it from `[OPT] Lang1` through
`Lang10` in `Cfg.ini`:

1. It formats each key as `Lang%d` and reads it with `GetPrivateProfileStringW`
   from the installed `Cfg.ini` (callsite `0x00454594`).
2. It stops when a key is absent or empty. For each value it splits on the
   first comma.
3. The text before the comma is written to the start of the row (up to 30
   UTF-16 characters); the text after it is written at row offset `0x3C` (up
   to 30 UTF-16 characters).
4. It advances by `0x78` bytes, for at most ten rows.

In the tray callback, `0x00447D60`, the right-button-up path loops over this
table and skips rows whose first UTF-16 character is zero. At
`0x00447E2C` it forms each command ID as `0x6A00 + row_index`; at
`0x00447E35` it calls the `AppendMenuW` import with the row's first string as
the item label. The popup is displayed through `TrackPopupMenu` at
`0x00447EBA` with flags value `2`. The table/ID relation and displayed strings
are statically established; the menu selection's downstream behavior is not.

## Populated row mapping

The installed configuration has seven contiguous language entries. `Lang8` is
absent, so the loader stops after row index 6; rows 7 through 9 remain empty
and are skipped by the callback.

| Zero-based row | Config key | Menu label (as stored) | Locale suffix (as stored) | Command ID |
| ---: | --- | --- | --- | ---: |
| 0 | `Lang1` | `简体中文` | `sc` | `0x6A00` |
| 1 | `Lang2` | `English` | `en` | `0x6A01` |
| 2 | `Lang3` | `繁體中文` | `tw` | `0x6A02` |
| 3 | `Lang4` | `Русский` | `Russian` | `0x6A03` |
| 4 | `Lang5` | `Türkçe` | `Turkish` | `0x6A04` |
| 5 | `Lang6` | `日本語` | `Japanese` | `0x6A05` |
| 6 | `Lang7` | `한국어` | `Korean` | `0x6A06` |

These seven labels and suffixes come directly from the installed `Cfg.ini`;
they are not keys looked up in `Text/en/text.xml`. The suffix is passed into
the locale-loading path elsewhere in the executable, but that fact alone does
not prove the tray command uses that path.

## Selection handler: unresolved

The recovered `COemDrvDlg` message-map entries include tray commands
`0x6400` and `0x6401`, but no direct entries for `0x6A00`–`0x6A06` appear in
[`rk-mfc-message-map-entries.csv`](rk-mfc-message-map-entries.csv). A static
scan of `DeviceDriver.exe` found the `0x6A00` base only in the menu-ID
construction at `0x00447E2C`; it did not reveal a direct comparison or a
recovered command handler for these IDs. The language-selection combo path
(`0x00403270` → `0x004032D0` → `0x00403170`) separately reloads locale text
and persists `OPT\LangIndex`, but no call edge from the tray callback to that
path was established.

Therefore the exact row-to-label-to-command-ID mapping is known, while the
action taken after selecting a row remains unresolved. A dynamic MFC route,
unrecovered handler, or another dispatch path has not been ruled out. Static
presence also does not prove that the loader or tray path is reachable in a
particular runtime state, nor establish observed UI behavior.

## Evidence references

- Installed settings: `Cfg.ini`, `[OPT] Lang1`–`Lang7`; hash recorded above.
- Loader pseudocode and global references: `_rk_analysis/reports/brightness-global-xrefs.txt`, around lines 3231–3255.
- Tray callback: `DeviceDriver.exe` at `0x00447D60`–`0x00447EBA`.
- Table base: `0x00612B90`; row stride `0x78`; locale field offset `0x3C`.
- Message map: `docs/rk-mfc-message-map-entries.csv`; the recovered `COemDrvDlg` rows include `0x6400` and `0x6401` only.
- Related workflow: [`rk-tray-icon-menu-workflow-audit.md`](rk-tray-icon-menu-workflow-audit.md).
