# RK official keyboard download selector: API catalog snapshot

**Observed:** 2026-10-19 16:22:37 UTC  
**Scope:** The English public [Drivers, Firmware & QMK Downloads page](https://en.rkgaming.com/download/), keyboard category (`category_id=1`), and its public JSON selector/result endpoints.  
**Companion data:** [`rk-official-download-selector-catalog-2026-10-19.csv`](rk-official-download-selector-catalog-2026-10-19.csv), captured by [`capture_rk_public_selector_catalog.py`](../scripts/capture_rk_public_selector_catalog.py).

This is a dated view of records currently returned by the vendor's public catalog. It is not a complete historical catalog or a claim that a listed target is retrievable, safe, or compatible with a physical keyboard. No keyboard or device interface was accessed. The collector requested the selector page and JSON metadata endpoints only; it recorded file URLs as data and did not request those URLs.

## Selector implementation and fields

The page's inline JavaScript declares these selector and result routes:

| Tab | Selector metadata route | Result route | Row fields used by the page |
| --- | --- | --- | --- |
| Drive | `/download/get_version_or_attr_ajax/` | `/download/drivers/` | model, version, attribute, drive type, OS, package URL |
| Firmware | `/firmware/get_firmware_version_or_attr_ajax/` | `/firmware/get_firmwares/` | model, version, attribute, OS, language, package URL |
| QMK | `/download/get_qmk_version_or_attr_ajax/` | `/download/get_qmk_files/` | model, version, attribute, QMK type, URL |

Each selector metadata request accepts `category_id`; result requests also accept `version_id`, `attr_id`, and `page`, and can be narrowed by `product_id`. The Drive route also accepts `drive_type` and `os`; firmware accepts `language` and `os`; QMK accepts `qmk_type`. The captured result calls used `category_id=1`, `version_id=0`, `attr_id=0`, and each selectable keyboard `product_id`, paginating every returned result page. The script verifies that the sum of per-model records matches the aggregate endpoint count before it writes the CSV.

The site uses the word **Version** for the product connection option, not a software release number: `USB` (selector ID 1) or `Tri mode` (ID 2). Attributes are `RGB` (ID 1); the firmware selector also offers `Single LED` (ID 5). Drive type values are `Web` (1) and `Hub` (2). The OS choices are Windows, Mac, and Linux. Firmware language selector IDs are 1 Simplified Chinese, 2 Traditional Chinese, 3 English-US, 4 French, 5 German, 6 Spanish, 7 Thai, 8 Russian, 9 Japanese, 10 English-UK, and 11 Universal. QMK types are `Json file` (`json_file`), `Source code` (`source_code`), and `Firmware download` (`firmware_download`).

The returned API record's `id` is retained as `record_id`; it is distinct from the selectable `product_id`. The CSV also retains the selected model ID/name, product version and attribute IDs/labels, drive/driver type, OS route, language, QMK type, PID, description, listed target URL, and exact metadata request URL. For Windows/Mac/Linux package fields, it emits one row per OS field, including empty fields as `target_url_listed=no`. For web driver entries it records the Web route once because the page renders it as a browser link rather than as an OS-specific package.

## Counts returned by the keyboard selectors

| Catalog | Model choices | Distinct returned records | CSV rows | Current route summary |
| --- | ---: | ---: | ---: | --- |
| Drive | 11 | 11 | 19 | Seven Web records, four Hub records. All four Hub rows list Windows targets; F99 AI also lists a Mac target; none lists Linux. Web targets are `drive2.rkgaming.com` for C61, C68, C84, C96, C98, and M75 HE, and `rk.hubx.pro` for RK68 HE. |
| Firmware | 51 | 118 | 354 | 117 records have a Windows URL field, none has a Mac URL field, and one has a Linux URL field. The Linux-field row is F99 / Tri mode / RGB / English-US and points to `https://en.rkgaming.com/0218`; the URL was not opened. R87 PRO / USB / RGB / English-US / PID `E48E` has no Windows target URL in its current record. |
| QMK | 7 | 83 | 83 | 38 records are labeled `Json file`; 45 are labeled `Source code`; no current result is returned for the offered `Firmware download` QMK type. |

The Drive page's broad Web Driver card lists M75 HE, X87 HE, and RK68 HE as unsupported on that general route, while the current product-specific result API returns Web records for M75 HE and RK68 HE. X87 HE does not appear among the 11 current Drive model options, though it does appear in the firmware selector. The page does not explain the apparent route distinction; it should not be collapsed into a universal support claim.

For S98 specifically, the current selector lists eight firmware records, all `Tri mode` and `RGB`: PID/language pairs `01BF`/English-UK, `01AF`/English-US, `022B`/Spanish, `0223`/Thai, `022F`/Japanese, `023F`/Traditional Chinese, `0230`/Russian, and `0224`/German. S98 is not among the current model options in the product-specific Drive or QMK selectors. This is evidence about the current public catalog only, not an exhaustive S98 revision map.

## Acquisition and analysis status

- **Acquired and statically analyzed:** The general Keyboard Hub Driver setup linked by the same page is `https://en.rkgaming.com/media/RK_Keyboard_Software_Setup_V4.6_20261015_N87rjnh.exe`. Its locally held package snapshot and analysis are documented in [`rk-v4.6-package-snapshot.md`](rk-v4.6-package-snapshot.md); the installer hash is recorded in that report. The separately installed 4.06 tree is an installed-file snapshot, not evidence that the original 4.06 setup executable is present. See [`rk-package-membership-and-version-boundary-audit-2026-10-19.md`](rk-package-membership-and-version-boundary-audit-2026-10-19.md).
- **Catalog metadata only:** The 118 firmware rows, 83 QMK rows, and product-specific Drive routes in this CSV have not been downloaded or analyzed as packages by this capture. Their listed URLs are preserved for future evidence tracking; they are not evidence of successful retrieval or execution.
- **Not present in this snapshot:** Prior/retired releases, regional sites, undocumented support files, and records removed from the current public endpoints. An absent model or QMK type is bounded to the endpoint response observed on the access date. Other product categories on the page (mice, audio, controllers) are outside this keyboard-only CSV.

## Reproduction

From the repository root, run:

```powershell
python scripts/capture_rk_public_selector_catalog.py
```

By default, it writes a new CSV named with the current UTC date and refuses to
replace an existing snapshot. Pass `--output <path>` to select another path;
pass `--overwrite` only when intentionally replacing that exact file. It reads
the public page and JSON metadata endpoints, but never visits a `listed_file_url`,
downloads firmware or QMK assets, or runs an installer.
