# RK QMK selector package and source audit

**Snapshot:** 2026-10-19 16:22:37 UTC
**Scope:** The 83 keyboard QMK rows in the dated official selector snapshot. This is a separate product family from the 118-row firmware selector. It covers the seven QMK model choices returned by the English keyboard selector on the snapshot date.

**Companion data:** [83-row artifact and SHA-256 ledger](rk-qmk-selector-artifact-audit-2026-10-19.csv) and [source ZIP member ledger](rk-qmk-source-archive-members-2026-10-19.csv). These are derived from the [dated selector snapshot](rk-official-download-selector-catalog-2026-10-19.csv), whose API and collection boundaries are described in the [selector API audit](rk-official-selector-api-catalog-audit-2026-10-19.md).

## Coverage summary

The selector returned **83 rows and 83 distinct artifact URLs**: 38 rows called “Json file” and 45 called “Source code.” The latter label groups two actual file formats: 38 ZIP source packages and seven `.hex` firmware images. The 38 ZIPs and 38 JSON files were downloaded from their listed official URLs and statically inventoried in this QMK-source pass. The seven `.hex` files were acquired separately by the firmware-image workstream; their listed URLs do not overlap the 118 firmware-selector result URLs in the same dated snapshot.

| Model choice | Rows | USB / Tri mode | JSON | ZIP source | HEX listed | Locale labels and raw codes captured in the `pid` field |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| R65 QMK | 24 | 15 / 9 | 11 | 11 | 2 | US, Turkish, Thai, Spanish, Russian, German, French, Brazil; E453, E508 |
| R75 Pro | 12 | 2 / 10 | 6 | 6 | 0 | US, Taiwan, Spanish, German, French |
| R75 QMK | 25 | 22 / 3 | 11 | 11 | 3 | US, Turkish, Thai, Spanish, Russian, Korean, German, French, Brazil, Arabic; E483, E484, E487 |
| R87PRO QMK | 16 | 14 / 2 | 7 | 7 | 2 | US, Thai, Spanish, Russian, Korean, Arabic; E48E, E4CF |
| RK98 Pro | 2 | 0 / 2 | 1 | 1 | 0 | US |
| S108 | 2 | 2 / 0 | 1 | 1 | 0 | US |
| X108 QMK | 2 | 2 / 0 | 1 | 1 | 0 | US |
| **Total** | **83** | **57 / 26** | **38** | **38** | **7** | **11 locale labels; seven additional E-prefixed values** |

`USB` and `Tri mode` are the selector’s product-connection variants, not software release numbers. The QMK result rows leave the selector’s `language` and `language_id` fields blank. Locale coverage above is preserved from the returned `pid` field and confirmed where possible by source archive directory names; it is not a claim that these labels are USB product IDs. The seven E-prefixed values occur on `.hex` rows and their meaning is unresolved.

The selector exposes a “Firmware download” QMK type, but the captured result set contains no records for that type. The seven `.hex` rows appear under “Source code” despite their file extension.

## Acquisition and hash-pinned artifacts

The QMK source audit script fetched 76 listed `.zip`/`.json` URLs over HTTPS. The fetcher accepts only the official `en.rkgaming.com/media/files/` host/path and rejects redirects away from that host. It saved the 76 artifacts to an external local cache, not to this repository. The separate firmware audit acquired the seven `.hex` images. The QMK source CSV stores the listed URL, filename, byte length, SHA-256, static JSON summary or ZIP summary, acquisition state, and exact-JSON/source-archive matches. The ZIP member CSV records each member path, byte sizes, CRC32, SHA-256, and a non-execution classification.

| Artifact set | Listed | Obtained and inspected | Bytes | Distinct SHA-256 values |
| --- | ---: | ---: | ---: | ---: |
| JSON definition files | 38 | 38 (100%) | 550,941 | 19 |
| ZIP source packages | 38 | 38 (100%) | 1,056,281 | 38 |
| HEX images listed as source code | 7 | 7 (100%) | 1,421,851 | 7 |
| **Total** | **83** | **83 (100%)** | **3,029,073 acquired** | **64 acquired hashes** |

All 38 JSON objects parse as JSON. Every JSON file’s SHA-256 exactly matches a `keyboard.json` member in one or more of the 38 ZIP packages. Thus the “Json file” selector records expose the declarative QMK keyboard definition also embedded in the source package; they are not separate compiled firmware files. The 38 selectors yield 19 unique JSON byte contents, because several locale result rows point to byte-identical definitions.

All 38 source ZIPs have distinct whole-file SHA-256 values. Each contains exactly 21 files beneath one keyboard-variant root directory, with a consistent QMK keyboard overlay layout: a keyboard C source and JSON definition, `config.h`, HAL/MCU configuration, a default keymap and its build rules, `post_rules.mk`, RGB record/effect support, wireless support, and a README with QMK build-target information. Across all ZIPs the member ledger contains 798 files: 228 `.c`, 266 `.h`, 152 `.mk`, 76 `.json`, 38 `.md`, and 38 `.inc` files.

These are per-keyboard source overlays rather than a complete standalone QMK checkout or Windows settings application. Their `post_rules.mk` files refer to the shared `keyboards/royalkludge/linker/wireless/wireless.mk` path, which is not included in the per-model archive. All 38 keymap rule files enable VIA and encoder maps; all 38 post-rule files select custom RGB matrix/RGB-light handling and include the `rgb_record` and `wls` modules. No ZIP was extracted to disk, built, or executed.

## Source and definition findings

The 19 distinct JSON definitions all identify processor `WB32FQ95`, bootloader `wb32-dfu`, and an RGB matrix using the `ws2812` driver. They describe six matrix rows, model-specific column counts and LED layouts, and dynamic-keymap layer limits. Those are package declarations; no connected board was checked against them.

| Model family | Key positions in `LAYOUT` | Matrix | RGB LED layout entries | Dynamic layers |
| --- | ---: | ---: | ---: | ---: |
| R65 QMK | 67–68 | 6 × 16 | 66–67 | 5 |
| R75 Pro | 82–83 | 6 × 15 | 81–82 | 5 |
| R75 QMK | 81–82 | 6 × 15 | 80–81 | 5 |
| R87PRO QMK | 89–90 | 6 × 17 | 121–122 | 5 |
| RK98 Pro | 100 | 6 × 19 | 100 | 5 |
| S108 | 108 | 6 × 21 | 118 | 3 |
| X108 QMK | 108 | 6 × 21 | 130 | 3 |

Static source inspection found a common custom VIA handler body in all 38 ZIPs. In `wls/wls.h`, the package-local custom field enum assigns IDs `0x01`–`0x04` to sleep timeout, RGB-record channel, per-key hue/saturation data, and RGB-record buffer access. The get/set hook reads or changes those values; sleep-timeout changes call the configuration persistence routine, and the reset case calls the keyboard-settings reset routine. The source also declares four RGB-record channels. The hue/saturation value is passed as a 16-bit quantity with row/column coordinates; buffer requests use offset and size fields, with a source comment stating a maximum chunk size of 26 bytes. The generic VIA command IDs and their on-wire report framing are supplied outside these per-model packages and were not reconstructed here.

The `wls` code also detects USB/Bluetooth/2.4 GHz mode-switch input and coordinates wireless mode changes, RGB status indication, and sleep behavior. These are source-level findings only. They do not establish the behavior of a particular physical keyboard or a complete host-app-to-device protocol.

## What this does and does not cover

- **Selector metadata:** all 83 QMK rows and all 83 distinct URLs are in the dated catalog. Model, connection variant, raw locale/code labels, QMK type, and acquisition state are preserved row by row.
- **JSON definitions:** 38/38 acquired, parsed, hashed, and compared against ZIP-embedded `keyboard.json`; 19 unique JSON byte contents.
- **ZIP source packages:** 38/38 acquired and hashed; all 798 member records are inventoried and SHA-256 pinned. Source/build organization and the shared custom VIA/wireless/RGB hooks have been traced statically.
- **HEX images:** 7/7 acquired and SHA-256 pinned by the separate firmware-image audit. A second static pass verifies all Intel HEX checksums and record framing, records their sparse flash address ranges, and compares shared-address bytes across all 21 image pairs. It does not disassemble or execute the images.
- **Still open:** deeper function-by-function comparison of all 38 board C/keymap variants, QMK-core and shared-linker behavior, exact generic VIA report encoding, hardware-revision compatibility, and runtime/device acceptance.

This is complete coverage of the dated selector’s metadata rows and all 83 listed artifact URLs across its two acquisition passes. It is not a complete reverse engineering of every source statement, every upstream QMK revision, every RK model or historical/regional QMK package, or any connected-device behavior. The Intel HEX structural comparison is documented in [the separate static HEX report](rk-qmk-hex-static-comparison-2026-10-20.md) and its [validator](../scripts/audit_qmk_hex_records.py).

## Reproduction

Run from the repository root. The optional fetch flag downloads only ZIP and JSON artifacts; it deliberately skips HEX files. ZIP members are read in memory for inventory and hashing, never extracted or executed.

```powershell
python scripts/audit_rk_qmk_selector_catalog.py --fetch --artifact-cache <local-cache-directory>
```

To regenerate the CSV ledgers from an existing cache without network requests:

```powershell
python scripts/audit_rk_qmk_selector_catalog.py --artifact-cache <local-cache-directory>
```
