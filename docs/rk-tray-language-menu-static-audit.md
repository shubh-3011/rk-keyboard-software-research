# RK tray language menu: static mapping audit

## Scope and artifacts

This audit follows the generated rows in the right-click tray menu of the
installed RK 4.06 `DeviceDriver.exe`. It maps each populated row to the
configured language label, locale directory, and command ID, then traces the
static Windows/MFC dispatch boundary. It does not establish a handler or
runtime language-change effect for those IDs.

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

## Selection dispatch and handler gap

At `0x00447EBB`, the tray callback calls the imported `TrackPopupMenu` with
flags `2` (`TPM_RIGHTBUTTON`). Its owner-window argument is the value saved from
`this+0x20` earlier in the callback; the callback itself is the
`COemDrvDlg` target in the recovered message map. The call does not include
`TPM_NONOTIFY` (`0x80`) or `TPM_RETURNCMD` (`0x100`), and the return value is
not examined. Under the Win32 API contract, choosing an entry therefore
delivers a `WM_COMMAND` to that owner window; the menu item ID becomes the
command identifier. The subsequent `PostMessageW` at `0x00447ECF` posts
`WM_NULL` to the same owner window after displaying the popup; it is not a
consumer of the selected language ID. See Microsoft's
[`TrackPopupMenu` documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-trackpopupmenu).

This establishes the expected Win32 notification edge from a selected language
row to the `COemDrvDlg` window. The subsequent MFC command-map search has no
recovered match: the `COemDrvDlg` map contains command IDs `0x6400` and
`0x6401`, not `0x6A00`–`0x6A06`; a range-overlap check across all 27 recovered
MFC message-map arrays also found no `WM_COMMAND` entry spanning those IDs.
Thus a `CCmdTarget`/MFC command-dispatch attempt is consistent with the
owner's class and the framework map evidence, but no static map handler or
`ON_COMMAND_RANGE`-style route for these menu IDs is established. The recovered
map inventory is documented as an inventory of discovered arrays, not proof
that every possible runtime dispatch route in the executable was found.

The callback forms IDs as `0x6A00 + row_index` at `0x00447E2C` and does not
inspect a selected ID after `TrackPopupMenu`. A direct relative-call scan of
the executable found the locale loader `0x00403170` called from `0x004032D0`;
no other direct caller was found. That
caller is the separate language-combo path in `0x00403270`, which compares the
notification's child HWND, reads the selected `LangIndex`, reloads locale
strings, and persists the host preference. No call or recovered map edge from
the tray callback to that loader/persistence path was found. This does not
exclude an unrecognized indirect route or a missing map; the tray selection's
final action remains unresolved.

Therefore, the proven edge ends at Win32 delivery of `WM_COMMAND` to the
`COemDrvDlg` owner. MFC command-map handling is expected by the class/framework
structure, but no matching static handler or range entry is recovered and no
locale reload or `lang.ini` write is linked to the tray command. Runtime
selection behavior remains unobserved.

## Evidence references

- Installed settings: `Cfg.ini`, `[OPT] Lang1`–`Lang7`; hash recorded above.
- Loader pseudocode and global references: `_rk_analysis/reports/brightness-global-xrefs.txt`, around lines 3231–3255.
- Tray callback: `DeviceDriver.exe` at `0x00447D60`–`0x00447EBA`.
- Menu dispatch: owner HWND is sourced from `this+0x20`; `TrackPopupMenu` is
  called at `0x00447EBB` with flags `2`; `PostMessageW` follows at `0x00447ECF`.
- Table base: `0x00612B90`; row stride `0x78`; locale field offset `0x3C`.
- Message map: `docs/rk-mfc-message-map-entries.csv`; its recovered
  `COemDrvDlg` command rows include `0x6400` and `0x6401` only. No recovered
  command range overlaps `0x6A00`–`0x6A06`.
- Locale loader call site: `0x004032D0` -> `0x00403170`, on the separate
  language-combo event path.
- Related workflow: [`rk-tray-icon-menu-workflow-audit.md`](rk-tray-icon-menu-workflow-audit.md).
