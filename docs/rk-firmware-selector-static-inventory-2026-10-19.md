# RK firmware selector artifact inventory

**Selector snapshot:** 2026-10-19. **Static inventory run:** 2026-10-20.

## Scope and method

This report reconciles the firmware category in the dated public selector
snapshot [`rk-official-download-selector-catalog-2026-10-19.csv`](rk-official-download-selector-catalog-2026-10-19.csv)
with local official download artifacts. The inventory script
[`audit_rk_firmware_catalog.py`](../scripts/audit_rk_firmware_catalog.py)
deduplicates by listed URL, associates model/mode/language/PID metadata, checks
the ignored research tree for already acquired files, fetches listed files
only from `https://en.rkgaming.com`, and records file size, SHA-256, content
signature and selected PE/archive metadata. Redirects to another host are
refused; downloads are capped at 512 MiB per URL.

The vendor files are held under the sibling ignored `.research/` tree and are
not included in Git. Eight S98 updater packages already present in
`.research/rk-selector-software-2026-10-19/S98-firmware-packages/` were
matched by their official URL filename suffix and SHA-256, so they were not
downloaded again. New files were cached in
`.research/rk-firmware-catalog-2026-10-19/`. The script reads PE imports and
ZIP member names; it does not execute vendor files or extract archives.

## Catalog coverage

The firmware subset has **354 selector rows**, of which 118 contain a listed
artifact URL. Those 118 URLs are all unique and cover **51 model labels**. The
listed hardware variants include 79 Tri mode and 39 USB rows, 116 RGB and two
Single LED rows. Language/PID differences are retained per URL in the
artifact ledger rather than collapsed into a single model-level record.

| Measure | Result |
| --- | ---: |
| Distinct firmware artifact URLs | 118 |
| New official files fetched during this audit | 109 |
| Previously acquired S98 files, SHA-256 matched | 8 |
| URLs with local bytes and a recorded SHA-256 | 117 / 118 (99.15%) |
| Selector rows associated with a uniquely resolved artifact and local bytes | 349 / 354 (98.59%) |
| Separate QMK HEX selector URLs with local bytes and SHA-256 | 7 / 7 (100%) |

The single failed firmware URL is the F99 row `https://en.rkgaming.com/0218`,
which returned HTTP 404 in this audit. F99 has three rows with the same model,
mode, attribute and language tuple: one links an EXE, one is blank, and one
links `/0218`. The blank row is left unresolved because those two URLs cannot
be uniquely associated with it. Three R87 PRO USB / PID `E48E` rows also have
blank artifact URLs and no linked URL for their exact selector tuple. The row
coverage percentage counts only records mapped to acquired bytes; the failed
F99 URL and four unresolved rows are excluded.

See [artifact URL inventory](rk-firmware-artifact-inventory-2026-10-19.csv)
for the 118 unique URLs and file identity, and
[selector row coverage](rk-firmware-selector-row-coverage-2026-10-19.csv)
for all 354 selector rows with original catalog line numbers and resolution
status.

## Artifact families found

The 117 artifacts with available bytes total 239,433,118 bytes in this
snapshot. Static signatures classify them as follows:

| Content classification | Count | Notes |
| --- | ---: | --- |
| PE32 x86 Windows packages with direct HID/SetupAPI imports | 90 | Strong static evidence of device/updater code; imports alone do not reveal the full call graph or exact device effects. |
| PE32 x86 Windows packages with no direct HID/SetupAPI import identified | 10 | Eight import `mscoree.dll`; two RK68 HE packages have large PE overlays. Role and dynamically resolved behavior need focused analysis. |
| Opaque `.bin` / `.upf` image candidates | 9 | Eight `.bin` files and one `.upf`; proprietary container fields are not decoded here. |
| Intel HEX text image candidates | 2 | F99 AI and R87 PRO firmware selector rows. |
| RAR packages | 4 | Signature identified; no RAR member inventory was available in this pass. |
| ZIP packages | 2 | Member names read without extraction; one contains an `.upf` plus `PH_UpdateTool_V1.30_20240913.exe`, the other contains `903 RK 8001-USB S10.01_20250331 (2).exe`. |

The PE group includes both updater applications and PE packages whose precise
role is unresolved. Of the PEs, 82 have an appended overlay beginning with
`5A A5 SINO`; the S98 report
[`rk-s98-firmware-updater-static-audit-2026-10-19.md`](rk-s98-firmware-updater-static-audit-2026-10-19.md)
already covers the eight S98 language packages in detail. The shared marker
and overlay signatures across other models are useful clustering evidence,
but do not establish the same payload format, compatibility rules, or update
behavior for those models.

Three exact file-hash duplicate groups appeared under different selector
records:

| Selector records | Shared SHA-256 |
| --- | --- |
| C96 USB and C84 USB `.bin` | `8255ecd13ff22e6aff540cfb6bcc9bd7c5afac6f42657aeb0b8b72b93c50b3b9` |
| C60 USB and C61 USB `.bin` | `fd51d8591e729ae81190bdda2012fd5f409be6322fa8a776ebd6671e6d5ad72d` |
| R98 PRO Tri mode and RK98 Pro Tri mode `.exe` | `730bdbd29e15563554541f3039ec17f70689f3a17efe6eb7a98d9b36aa1a1e65` |

These are byte-identical files despite separate URLs and selector metadata;
they do not by themselves prove cross-model compatibility.

## Separate QMK HEX selector subset

The seven `.hex` URLs from
[`rk-qmk-selector-artifact-audit-2026-10-19.csv`](rk-qmk-selector-artifact-audit-2026-10-19.csv)
were acquired and hashed separately from the 118 firmware-category URLs. All
seven files identify as Intel HEX text. Exact files and hashes:

| Model / mode / PID | File in ignored research cache | Size | SHA-256 |
| --- | --- | ---: | --- |
| R65 QMK / USB / `E508` | `.research/rk-firmware-catalog-2026-10-19/qmk-hex/20260811092153_5697.hex` | 197,525 B | `06ade27a7df58564d21b50cc6441e5a271362c20b7b2bb8b2e3b3a96ab54e7d7` |
| R65 QMK / Tri mode / `E453` | `.research/rk-firmware-catalog-2026-10-19/qmk-hex/20260811092233_1324.hex` | 203,158 B | `153fe65cceb16d832d43663c62f6cefb407a70e12548af7728a4a9f4fd070641` |
| R75 QMK / USB / `E484` | `.research/rk-firmware-catalog-2026-10-19/qmk-hex/20260811092303_9713.hex` | 192,612 B | `4e79a5a71c5fa532c34be935b73211c9cc08bf9b282145e560b0c26163e75d91` |
| R75 QMK / USB / `E483` | `.research/rk-firmware-catalog-2026-10-19/qmk-hex/20260811092507_6532.hex` | 195,902 B | `43b248342aa454847aaccdb065bbdd2e81a8487be1e5af1f55d6b3e747d14859` |
| R75 QMK / Tri mode / `E487` | `.research/rk-firmware-catalog-2026-10-19/qmk-hex/20260811092538_1945.hex` | 204,881 B | `27490e3d2a76bc4fb1a2e58655fa15c793787c2adeb0b8ed4fbd601bec2acee5` |
| R87PRO QMK / USB / `E48E` | `.research/rk-firmware-catalog-2026-10-19/qmk-hex/20260811093052_8435.hex` | 212,330 B | `de52698602ee33e05664626c6c7c68770c2fe8d336e90e34e5dd2888d8401c1a` |
| R87PRO QMK / USB / `E4CF` | `.research/rk-firmware-catalog-2026-10-19/qmk-hex/20260811135140_8329.hex` | 215,443 B | `06213b0185897b524adc30f0e978f7471ef6dd50a57b5b617b90420ac69677f4` |

The QMK `E4CF` file is byte-for-byte identical to the separate firmware
selector file `20260701124254_9175.hex` for R87 PRO USB / PID `E4CF`. Their
URLs differ, but their SHA-256 values match. The full separate ledger is
[`rk-qmk-hex-firmware-artifact-inventory-2026-10-19.csv`](rk-qmk-hex-firmware-artifact-inventory-2026-10-19.csv).

## What this inventory does not establish

This pass identifies and clusters downloadable artifacts; it is not a
complete reverse engineering of the updater suite. No vendor package was
executed, no archive was extracted, no keyboard HID interface was opened, and
no firmware was sent to a keyboard. The direct-import sweep does not resolve
API callsites, control flow, dynamic loading, driver behavior, update command
semantics, or the model-to-image compatibility rules. The opaque `.bin` and
`.upf` formats, four RAR member lists, PE overlay payloads outside the detailed
S98 sample, and all non-S98 updater binaries still need package-specific
static disassembly and payload-format analysis. Firmware integrity and
post-transform image layouts remain unverified.
