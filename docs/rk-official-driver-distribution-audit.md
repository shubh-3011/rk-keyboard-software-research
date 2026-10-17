# Royal Kludge official driver distribution audit

**Access date:** 2026-10-18  
**Coverage:** Public pages on Royal Kludge's English global site (`en.rkgaming.com`) and the web app linked from it. This is a snapshot of the distribution routes and published support statements visible on that date, not an inventory of every model, revision, package, or regional site.

## Summary

The official site presents multiple keyboard software paths rather than one universal application:

1. a browser-based **Keyboard Web Driver**;
2. a downloadable **Keyboard Hub Driver** package;
3. product-selected **driver and firmware** downloads, keyed by model and hardware/configuration attributes;
4. **QMK/VIA** guidance and keyboard-specific definition files for the subset of products sold as QMK/VIA-compatible.

The site itself documents exceptions to the general Web Driver route and asks users to select a product-specific package. Its selectors expose distinctions such as product version, RGB attribute, connection mode, drive type, operating system, language, and QMK type. These are meaningful compatibility axes: the existence of one general package does not establish support for all RK products or revisions.

This audit does not establish that RK software automatically identifies every connected model. The public pages show product selection and device-connection flows, but do not document a universal USB identity database or detection algorithm. It also does not establish that every listed keyboard supports every function offered by a particular software family.

## Distribution paths

### 1. Browser-based Keyboard Web Driver

The official [Downloads page](https://en.rkgaming.com/download/) labels a **Keyboard Web Driver**, lists Windows, macOS, and Linux support, and names Chrome, Edge, and Opera as supported browsers. It explicitly lists **M75 HE, X87 HE, and RK68 HE** as unsupported by this general Web Driver, directing users to select a driver for those products below. The linked [RK Web App](https://drive.rkgaming.com/) describes wired and 2.4 GHz receiver connections and repeats the Chrome/Edge/Opera browser limitation.

**Evidence:** These are direct statements from the RK download page and web app landing page.  
**Limit:** The landing page does not provide a complete model-by-model compatibility matrix, protocol specification, or feature matrix. Browser claims do not imply that every OS/browser combination supports every model. The page's exclusion refers to the general Web Driver route; it is not proof that the named devices have no web-based configuration route at all.

### 2. Downloadable Keyboard Hub Driver

The [Downloads page](https://en.rkgaming.com/download/) separately lists a **Keyboard Hub Driver** download. On the access date, its download link resolved to the official package URL [`RK_Keyboard_Software_Setup_V4.6_20261015_N87rjnh.exe`](https://en.rkgaming.com/media/RK_Keyboard_Software_Setup_V4.6_20261015_N87rjnh.exe). The page does not display a useful keyboard-model exclusion list beside this keyboard package.

The same page separately shows a model-selected catalog, with examples labeled `Hub` and `Web` and with OS/version/attribute values. For example, the page's surfaced records include F99 AI (Hub, tri-mode, RGB, Windows/macOS), R99 (Hub, tri-mode, RGB, Windows), RK918 (Hub, USB, RGB, Windows), and S108 (Hub, USB, RGB, Windows). These examples demonstrate that the catalog routes some products to the Hub family; they do **not** prove that the general package supports every revision or feature of those products.

**Evidence:** The package category, link, and surfaced catalog records are on the official download page.  
**Limit:** A shared setup package is not evidence that all model-specific profiles, firmware, or feature handlers are present or compatible. No package was run as part of this audit.

### 3. Product-selected drivers and firmware

The official [Downloads page](https://en.rkgaming.com/download/) and separate [Firmware selector](https://en.rkgaming.com/firmware/) offer product-specific selection. The download page describes selecting a customized driver and firmware according to the product and exposes categories for **Drive**, **Firmware**, and **QMK**, plus selectors for product model, product version, product attributes, drive type, computer system, language, and QMK type. The firmware page exposes model, version, and attribute selection.

Search-visible records on the download page show that the catalog distinguishes at least `Hub` and `Web` drive types and includes records for both general mechanical keyboards and newer HE/magnetic products. For example, RK68 HE appears as Web/USB/RGB/Web, while other products appear as Hub. This supports treating the selectors as a compatibility boundary, not merely a convenience for finding one universal installer.

**Evidence:** Selector categories, field names, and representative records appear on the official pages.  
**Limit:** These catalog pages are dynamic. The publicly rendered page does not provide a stable, complete static export of every model × revision × attribute × OS × language × package combination. A selector result is specific to the selected variant; absence from a search snippet is not proof that a product has no package. This audit did not enumerate every selectable record or download firmware.

### 4. QMK/VIA assets and guidance

RK publishes a [QMK/VIA how-to article](https://en.rkgaming.com/news/14/) and a separate [RK61 QMK web-version tutorial](https://en.rkgaming.com/news/12/). The articles direct users to VIA and to a keyboard-specific JSON definition (examples include `RK61.json` / `RK-61.json`) from RK's download area. RK's general download page also exposes a QMK category and a QMK type selector.

The published guidance explicitly says to verify that the keyboard is a QMK/VIA version and to obtain the definition file for the specific keyboard. The RK61 tutorial documents VIA's keymap, macro, save/load, and lighting modules, as well as multiple layers and other programmable key functions. That is guidance about QMK/VIA-capable variants; it must not be generalized to conventional proprietary-driver RK models.

The articles refer to `https://en.rkgaming.com/download/12/` as the configuration-file location. That legacy route returned a 404 when directly checked for this audit, so the article's historical link should not be treated as proof that the asset is currently retrievable at that exact URL. The current download page is the better entry point.

**Evidence:** RK's own QMK/VIA articles and the current selector labels.  
**Limit:** This audit does not establish that every QMK-labeled model has upstream QMK source, that all VIA JSON definitions are current, or that proprietary Hub/Web firmware is QMK-based. No keyboard was connected and no configuration was applied.

## Published support caveats and apparent inconsistencies

- The current Downloads page excludes **M75 HE, X87 HE, and RK68 HE** from the general Web Driver route, yet search-visible product records show those products among the model-selected download catalog, with RK68 HE labeled `Web`. The best-supported reading is that the general browser entry point and the product-specific route are distinct. The site does not fully explain the relationship, so do not infer that the exclusion means “no web support.”
- RK's 2023 [general driver guide](https://en.rkgaming.com/news/9/) says the first general software is suitable for most RK models and names RK-S108 and RK918 as examples requiring their own drivers. This is useful historical support guidance, but it predates the current Web/Hub/product-selector taxonomy and should not override current product-specific entries.
- The selectors distinguish product version, attribute, connection/drive type, OS, language, and QMK type. Matching the family name alone may therefore be insufficient to choose a package. The site advises users in the older guide to identify the exact model and version and to contact support if the general driver fails.
- The official [S98 product page](https://en.rkgaming.com/product/20/) identifies S98 as a model, but the static page content reviewed here does not expose a resolved S98 driver/firmware selector record. Therefore this report does not claim which package, operating modes, or software functions are supported by every S98 revision.
- RK's public pages use product-family names and selected examples; they do not state that the listed records cover every retail SKU, regional variant, PCB revision, radio receiver, language pack, or historical driver release.

## What this audit does and does not establish

### Established from official public pages

- RK publishes both browser and downloadable Hub Driver entry points.
- The general web entry point has published browser/platform claims and named unsupported models.
- RK publishes model-selected driver and firmware categories and selectors that encode compatibility dimensions.
- RK publishes a separate QMK/VIA path that requires QMK-capable hardware and a keyboard-specific definition file.
- RK's own guidance warns that a general driver is not appropriate for every model.

### Not established

- A complete list of every RK keyboard, revision, firmware file, driver package, feature, or supported OS.
- Automatic identification behavior for all products, USB/HID IDs, transport protocol details, or implementation internals.
- Whether the product selector's full current data set includes every historic or regional SKU.
- Whether a software function shown in a general UI exists on a given keyboard, or whether a package can safely write that function to it.
- A safe firmware backup/read operation, ability to extract factory firmware from a device, or permission to redistribute RK binaries, configuration files, or artwork.
- That the public download portal represents RK's complete software ecosystem. Regional pages, dealer-provided files, retired releases, service tools, and unpublished support packages are outside this snapshot.

## Method and safety boundary

This was a read-only review of public official web pages and their visible links on 2026-10-18. No RK installer, driver, updater, or firmware image was downloaded or executed for this audit; no keyboard was opened, connected to, queried, or written. The official Hub Driver URL is recorded as a distribution link only. Dynamic selector contents were sampled as surfaced by the official page and search indexing, not exhaustively enumerated.

## Sources

All sources below are official RK pages or official RK-hosted assets. Access date: **2026-10-18**.

1. [Drivers, Firmware & QMK Downloads](https://en.rkgaming.com/download/) — browser and Hub driver entries, exclusions, product-selected catalog, fields and example records.
2. [RK Web App](https://drive.rkgaming.com/) — browser requirements and wired/2.4 GHz receiver statements.
3. [Firmware selector](https://en.rkgaming.com/firmware/) — product-specific firmware selector.
4. [Keyboard Hub Driver package URL](https://en.rkgaming.com/media/RK_Keyboard_Software_Setup_V4.6_20261015_N87rjnh.exe) — link target shown by the official downloads page on the access date; link target may change.
5. [How to use the software for QMK/VIA keyboard](https://en.rkgaming.com/news/14/) — QMK/VIA conditions and keyboard-specific configuration guidance.
6. [RK61 QMK tutorial (web version)](https://en.rkgaming.com/news/12/) — VIA workflow and RK61 QMK example.
7. [User Guide for RK's Driver](https://en.rkgaming.com/news/9/) — 2023 statement that a general driver fits most models and examples of exceptions.
8. [S98 product page](https://en.rkgaming.com/product/20/) — product identity; no resolved driver record visible in the static content reviewed.
