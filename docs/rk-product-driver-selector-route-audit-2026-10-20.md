# Official RK product-driver selector routes — static coverage audit (2026-10-20)

## Scope

This report resolves every row in the dated keyboard **Driver** selector
snapshot, then inventories static web assets for each listed Web route. It
does not extend those rows into a historical or universal RK product list.
The source snapshot and collector are the [2026-10-19 selector audit](rk-official-selector-api-catalog-audit-2026-10-19.md)
and [selector CSV](rk-official-download-selector-catalog-2026-10-19.csv).
No vendor program was run and no keyboard interface was accessed.

The reproducible collector reads those two ledgers and fetches same-origin
HTML, JavaScript, and CSS only from the selector's Web routes. It does not
fetch images, fonts, APIs, firmware, installer payloads, or source maps, and it
does not execute JavaScript. Raw web responses are in ignored `.research/`;
the repository contains only route rows, hashes, sizes, and lexical symbol
candidates.

## Complete row-level coverage of the dated Driver selector

The captured Driver selector has **11 distinct product records represented
by 19 platform rows**, with **seven distinct non-empty target URLs**. The
seven URLs comprise five vendor download files and two Web application roots.
All non-empty selector targets map to an existing package record or to an
acquired web-route asset group; seven OS rows have no URL in the selector.
There is no newly discovered Windows installer beyond the four already
catalogued packages.

| Selector rows | Listed product/version route | Static coverage |
| ---: | --- | --- |
| 6 | C61, C68, C84, C96, C98, and M75 HE → `https://drive2.rkgaming.com` | Same shared Web app root; 9 HTML/JS/CSS files, 3,419,809 bytes. It does not return a separate binary per model. |
| 1 | RK68 HE → `https://rk.hubx.pro/` | Separate Web app root; 91 HTML/JS/CSS files, 8,928,311 bytes. |
| 1 | F99 AI, Tri mode → Windows `RK-Setup-3.2.2.exe` | Existing package hash and static analysis; Windows Electron app. |
| 1 | F99 AI, Tri mode → Mac `RK-3.2.2-universal.dmg` | Existing package hash and partial static analysis; outer DMG/APFS and carved ASAR/Mach-O evidence. |
| 1 | R99, Tri mode → Windows `20260908161817_9675.exe` | Existing package hash and static analysis; Inno Setup package. |
| 1 | RK918, USB → Windows `20260603165321_7285.rar` | Existing package hash and static analysis; contains a GamingForceZ installer. |
| 1 | S108, USB → Windows `20260318154501_4537.zip` | Existing package hash and static analysis; contains a GamingForceZ installer. |
| 7 | F99 AI Linux; R99 Mac/Linux; RK918 Mac/Linux; S108 Mac/Linux | No URL is listed for these rows in the dated selector response. This is not evidence that no other release exists. |

The row-by-row mapping, including the exact URL and package SHA-256 when
available, is in the [Driver selector coverage ledger](rk-product-driver-selector-coverage-2026-10-20.csv).
Package names, installer types, hashes, and family-level file findings for
the five downloaded files remain in the [product-specific package audit](rk-product-specific-software-package-audit-2026-10-19.md)
and its [package catalog](rk-product-specific-software-package-catalog-2026-10-19.csv).
The Mac package's additional static evidence is in the [F99 macOS findings](rk-f99-macos-static-findings-2026-10-20.md).

## Web route package groups

### `drive2.rkgaming.com`

The selector points six product rows to this one shared route. Its HTML shell
is 649 bytes, titled `RK Web驱动`, and references a Vite-style entry module
and stylesheet. The static group contains one HTML shell, four JavaScript
files, and four CSS files. The entry JS is
`index-Cq0ERv1u.js` (513,749 bytes;
SHA-256 `26eb7d4cbc70e3d5784ba77e41024d0c6f8b46ee8d022727d619a41217a0e011`).
Other recovered JS modules are `ConnectDrivePage-ssQP7GIK.js`,
`DeviceSettingPage-D_XFuI9e.js`, and `VBtn-BDi64M-u.js`. These file names
indicate page/component bundles, not proof of a reachable UI action.

The route's JavaScript has lexical candidates for `navigator.hid` (4
occurrences), `requestDevice` (4), `getDevices` (1), `sendReport` (1), and
`inputreport` (1). It also contains `fetch` and `XMLHttpRequest` tokens. In
the four acquired JS files, this scan found no literal
`sendFeatureReport` or `receiveFeatureReport` token. That is a bounded string
result, not proof those operations are absent or unused. Model-name literals
found include C61, C68, C84, and R99; C96, C98, and M75 HE are absent from the
scanned JS text, which may reflect remote configuration, indirection, or
other unresolved paths.

This is a different build from the 2026-10-18 `drive.rkgaming.com` capture:
the latter's entry file is 20,417,509 bytes with SHA-256
`ec50777e49f34f24f4564c8624d5c39b52447980199fad43e24734826e6531ee`; the
current selector's `drive2` entry is 513,749 bytes with a different name and
hash. The older [Drive worker/WebHID audit](rk-drive-communication-module-audit-2026-10-19.md)
must not be treated as a byte-level or call-graph audit of this `drive2`
build.

### `rk.hubx.pro`

The selector routes RK68 HE to a separate root. The shell title is `RK`, and
it declares a minimum body size of 1920 × 919 pixels. The HTML has one main
entry, three modulepreloads, and a stylesheet. The recovered group contains
one HTML file, 71 JavaScript bundles, and 19 CSS files. The main JS is
`app-BqfTKFxh.js` (4,411,291 bytes; SHA-256
`b6144986513c0e91b17f340c9fbd126911d9596132ef466e7b25e760d6586ef8`).
Static JS literals include C61, C68, C84, C96, C98, RK68 HE, and S108, plus
terms associated with lighting, brightness, macro, firmware, battery, and
display UI. These are lexical labels and catalog values, not verified
model-to-feature mappings.

The main bundle has lexical candidates for `navigator.hid` (7),
`requestDevice` (1), `getDevices` (2), `sendReport` (89),
`sendFeatureReport` (39), `receiveFeatureReport` (2), and `inputreport` (22).
The exact call graph, model/revision gates, report schemas, and whether any
particular selector model reaches each branch remain unresolved.

Both route-specific inventories and SHA-256s are in the [web asset ledger](rk-product-driver-route-web-asset-ledger-2026-10-20.csv).
Lexical candidate counts and byte offsets are in the [static symbol ledger](rk-product-driver-route-static-symbols-2026-10-20.csv).

## Acquisition and transport provenance

The Windows installer/archives and F99 Mac DMG were already hash-pinned in the
product package catalog. This pass added no new installer or firmware binary.
It acquired the two listed Web application trees' same-origin HTML/JS/CSS
assets into ignored `.research/` and recorded their hashes; it intentionally
left media, fonts, firmware, and network/API responses out of scope.

Python's normal TLS verification rejected `drive2.rkgaming.com` because its
certificate was expired at acquisition time. The `drive2` assets were
therefore collected with certificate validation disabled, using only the
exact HTTPS hostname present in the official selector snapshot. Treat that
transport provenance as a limitation. A normal certificate-verified request
to `rk.hubx.pro/` returned HTTP 200, but the saved `hubx` asset bytes in this
snapshot were initially acquired during the same unverified crawl; the asset
ledger preserves that fact rather than retroactively calling them verified.
The selector's link to `rk.hubx.pro` is direct provenance for why it was
examined, not a claim that the domain belongs to the RK company.

## Unresolved scope

- Neither Web app has a complete function graph from page controls through
  feature gates, serializers, browser HID calls, and response handling.
- Model names and token counts do not establish supported product revisions,
  firmware compatibility, or physical-keyboard behavior. Dynamic model data
  and server/API routes have not been resolved.
- The scan does not inventory image, keyboard-photo, font, or other media
  assets, and it does not join those assets to model cards.
- The browser WebHID boundary is not traced into browser internals, Windows
  HID drivers, kernel calls, or USB traffic.
- The four Windows package audits remain partial call-path investigations;
  the Mac DMG pass lacks APFS path recovery and an exact Windows/Mac member
  diff. See their linked reports for package-specific limits.
- Missing OS URLs, this current catalog snapshot, and absent model choices do
  not prove unsupported hardware or the absence of historical, regional, or
  retired releases.
- This audit did not contact, read, configure, update, or send a report to a
  keyboard.

## Reproduction

From the repository root, with network access:

```powershell
python scripts/audit_rk_product_driver_routes.py --fetch-web-assets --allow-invalid-tls --overwrite
```

The scanner verifies hashes before reusing any prior local web asset. The
`--allow-invalid-tls` flag is required for the expired `drive2` certificate;
it disables verification only for that selector-listed host. On a clean
checkout, the verified TLS context remains enabled for `rk.hubx.pro`. Raw
responses stay under ignored `.research/`; the scanner writes only the three
CSV evidence ledgers linked above.
