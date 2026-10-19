# Full-suite reverse-engineering gap matrix — status updated 2026-10-20

## Scope of this review

This is a documentation-level audit of the repo's coverage ledger, artifact
index, package manifests, and existing component reports. It identifies the
largest evidence gaps and the next static work that would reduce them. It is
not a new binary analysis and does not claim that the vendor suite has been
fully reverse engineered.

The dated catalog/package evidence below was refreshed through 2026-10-20. The
repo still has bounded evidence sets rather than a proof of the complete RK
release universe:

- The installed Windows Hub package labeled 4.06: 810 inventoried files,
  including the main driver, updater, setup helper, uninstall helper, and
  generated uninstaller. Static code and data coverage is deepest for this
  snapshot, but it is not a complete function-by-function CFG or runtime map.
- The official Windows Hub installer labeled 4.6: 1,249 extracted files and
  265 named profiles. The main `DeviceDriver.exe` differs from 4.06 and has
  significant targeted audits, but its full call graph has not been rebuilt.
  The updater, `.upf`, `InitSetup.dll`, and `uninstall.dll` match the 4.06
  files by hash; this extracted payload does not contain the generated
  `unins000.exe`/`.dat`.
- One dated RK Drive Web App snapshot: seven reachable JavaScript bundles,
  177 general keyboard descriptors, and two separate RK68 HE profiles. It
  contains registry and selected feature-path analyses, not a full audit of
  every bundle function or every official web/product-specific tool.
- One current official keyboard-selector metadata snapshot captured on
  2026-10-19: 11 product-specific driver records, 118 firmware records across
  51 model choices, and 83 QMK records across 7 model choices. Four Windows
  product-specific package samples (F99 AI, R99, RK918-labeled/RK919 member,
  and S108) have been fetched and statically inventoried; the F99 Mac DMG now
  has a static UDIF/APFS-block/Mach-O/ASAR carve pass, but APFS file paths and
  exact Windows/macOS member differences remain unresolved. The eight S98
  Tri-mode RGB updater variants are hash-pinned and statically audited. Current
  firmware-selector acquisition is 117/118 distinct URLs (one F99 `/0218`
  returns HTTP 404); 349/354 selector rows map to acquired bytes, with four
  rows unassociated. All 38 QMK JSON definitions, 38 ZIP source overlays, and
  seven separately acquired QMK HEX files are hash-pinned. The HEX files have
  static checksum/address-map comparison, not disassembly. Other updater
  callgraphs, some driver routes, historical/retired releases, and exact model
  revisions remain unresolved. See the [selector API audit](rk-official-selector-api-catalog-audit-2026-10-19.md),
  [product-specific package audit](rk-product-specific-software-package-audit-2026-10-19.md),
  [firmware inventory](rk-firmware-selector-static-inventory-2026-10-19.md),
  and [macOS F99 findings](rk-f99-macos-static-findings-2026-10-20.md).
  A route-specific follow-up resolves all 19 dated Driver platform rows: five
  package downloads, two Web roots, and seven OS rows with no URL. It collected
  hash-indexed HTML/JS/CSS for the shared `drive2.rkgaming.com` app and separate
  `rk.hubx.pro` route. The first host had an expired TLS certificate during
  capture; the hubx bytes were initially acquired without TLS validation.
  This does not add an installer or close either web app's call graph. See the
  [Driver route audit](rk-product-driver-selector-route-audit-2026-10-20.md).
- The QMK selector audit covers all 83 dated rows and artifact URLs: 38 JSON records match the
  same definition embedded in the 38 ZIP source overlays. These overlays are
  per-model source/config extensions, not complete QMK trees or the vendor
  configuration application. The shared QMK/linker implementation, generic
  VIA report encoding, HEX disassembly, model revisions, and device acceptance
  remain open. See the [QMK source audit](rk-qmk-selector-software-audit-2026-10-19.md)
  and [HEX static comparison](rk-qmk-hex-static-comparison-2026-10-20.md).
- Three additional product-specific Windows software families now have
  package snapshots: GamingForceZ NSIS, R99 RK Driver (Inno), and F99 AI RK
  Setup (Electron/ASAR with native HID addon). Their file manifests, assets,
  configuration, imports/exports, and selected static paths have partial
  coverage. A hash-pinned R99 scanner records all seven package PE import
  tables and 4,110 linear-sweep call/tail-jump candidates; 30 CH375 helper
  calls use IOCTL `0x223CDC`. A separate S98 firmware-updater audit covers all
  eight regionalized selector packages, their embedded container, resources,
  imports, and static HID transfer candidates. Complete call graphs, installer
  effects, device protocols, model mapping, and runtime behavior remain open; see the
  [product-specific package audit](rk-product-specific-software-package-audit-2026-10-19.md).

See the [coverage ledger](../COVERAGE.md), [4.6 package snapshot](rk-v4.6-package-snapshot.md),
[4.6/4.06 binary delta](rk-v4.6-native-binary-delta-audit.md),
[Drive audit](rk-drive-web-app-audit.md), and
[official distribution boundary](rk-official-driver-distribution-audit.md).

## Priority matrix

| Priority | Component or scope | Evidence already present | Gap that blocks a whole-suite claim | Next bounded static audit |
|---|---|---|---|---|
| **P0** | Official package/version universe | Public distribution routes, dated Hub 4.6, Drive snapshots, current selector metadata, and a route-by-route audit of all 19 dated Driver platform rows are documented. The firmware catalog has bytes for 117/118 unique URLs; the QMK catalog has all 83 URLs acquired across JSON, ZIP, and HEX passes. Four Windows product-specific samples and an F99 Mac static package pass are documented. | Current catalog is still bounded to the dated English selector; other product-specific routes, historical/retired/regional packages, model revisions, and 404/unassociated records remain unresolved. Firmware PE metadata is not per-package full reverse engineering. The two selector Web apps have only static asset inventories and lexical candidates, not complete function/UI-to-device graphs. | Analyze unique firmware updater/package hash families, recover call paths for the two newly indexed Web routes, then expand to historical and regional catalogs where public evidence exists. Record inaccessible, removed, and unassociated targets distinctly. |
| **P1** | Product-specific Windows/macOS app families | Static archive/PE/ASAR inventories cover GamingForceZ packages for RK918-labeled/RK919 and S108, R99 RK Driver, and F99 AI RK Setup. Focused paths include GamingForceZ UI/configuration → plugin relationships and report wrappers; R99 CH375/HID discovery, request buffers, shared IOCTL, and archived installer paths; F99 Windows model and OTA paths; and a macOS DMG with 17 universal Mach-O candidates, HID symbols, and one carved ASAR candidate. | None is a full function map. GamingForceZ slider/event-to-Writer serialization, R99 helper/driver semantics and model gates, F99 renderer-to-native paths, APFS file-to-binary attribution, macOS assets and exact Windows/macOS member differences, and actual hardware behavior remain unresolved. | Complete hash-pinned graphs per package; recover APFS directory/path mappings; resolve remaining UI state → helper/native boundary → model gate → serializer edges. Keep strings/imports separate from caller evidence. |
| **P0** | Changed 4.6 `DeviceDriver.exe` | Hash-pinned imports/callsites, selected API paths, RTTI family routing, vtables, feature traces, and a new MFC scan with 145 structurally validated accessor/table candidates (1,214 rows; 144 with RTTI/vtable association evidence) exist. A new hash-pinned Capstone linear sweep covers the 1,723,392-byte executable section: 570,401 decoded instruction boundaries, 102,205 direct call/branch sites, 18,517 indirect call/jump candidates, 10,970 return sites, and 313 undecoded bytes. A follow-up proves that the registry helper at `0x004ACEF8` recursively processes child keys and then deletes the parent key. | This changed native image still lacks a complete function map or CFG. Linear sweep can decode data as instructions; its direct targets are not necessarily function entries or reachable, and vtable/callback/COM/computed/dynamic targets remain unresolved. The PDB path in debug metadata did not yield a local matching PDB. The bounded MFC scan does not prove dispatch or complete map coverage; the recursive delete's UI caller and concrete registry path remain unknown. | Establish validated function starts and code/data boundaries for this hash; resolve direct, vtable, callback, COM, delayed/dynamic, and register-indirect edges. Then map each MFC owner/page and runtime-created control to handlers, persistence, worker, family serializer, and imported API. Diff normalized functions/data against 4.06 and list unmatched regions. The [linear-sweep report](rk-v4.6-driver-linear-sweep-inventory.md) and [reproduction script](../scripts/audit_rk46_driver_linear_sweep.py) provide a baseline, not CFG closure. |
| **P1** | Setup, install, and uninstall behavior | 4.06 Inno and helper findings exist; the 4.6 installer is identified as Inno 5.3.3 and statically extracted. A hash-pinned audit maps its 135 ordinary imports to decoded IAT stubs and 281 relative calls. The 4.6 setup callbacks were not recovered; its generated uninstaller is absent from the extracted payload. | Import transfer coverage does not reveal exact callback order, file/registry/shortcut actions, overwrite rules, rollback behavior, generated uninstaller contents, or runtime side effects. The 4.06 script is only a baseline, not proof of 4.6 behavior. | Continue offline recovery of the 4.6 compiled PascalScript and setup-data structures; separately trace the version-specific loader/helper code. Compare all recovered callback actions with 4.06. Mark each callback/action proven, inferred, or unrecovered; do not infer missing actions from the baseline. |
| **P1** | Updater and firmware package semantics | The Hub updater is hash-identical across the two Windows snapshots. Its command `0x0419`, mode-3 preflight/status-to-worker path, all 15 UART dispatch entries and direct state-store edges, feature-read/write sites, conditional file sink, and mode-3 `.upf` section transform have targeted reports. The S98 selector's eight Tri-mode RGB updater variants are also mapped at package/container/resource/import level, with selected HID report construction and comparison paths. | Neither updater has a closed end-to-end UI-to-transfer graph or established device acceptance. The Hub `.upf` validation/length issues remain; S98's post-transform image format, report meanings, model/revision gates, retry/cancel lifecycle, and profile-to-firmware compatibility remain unresolved. | Reconcile all updater state transitions with callers; map retry, timeout, cancellation, progress, and cleanup from UI to HID/UART helper. Acquire the remaining firmware artifacts and compare headers/sections to code checks. Keep host-side transfer separate from device flash/readback evidence. See the [S98 updater audit](rk-s98-firmware-updater-static-audit-2026-10-19.md). |
| **P1** | Family protocols and 265-profile compatibility | 4.06 and 4.6 profile routes are statically mapped to RKKB/G5/3632 classes; selected serializers and worker paths have detailed reports. | Class routing is package logic, not physical support. Many command fields, family-specific request/response meanings, firmware revisions, model aliases, and hardware acceptance remain unresolved. The profile catalog is not a universal SKU matrix. | For each family, inventory every virtual method and serializer branch; derive field-level schemas from all callers and response consumers; map profile flags to reachable branches; reconcile with every acquired package/profile. Maintain separate rows for static route, declared descriptor, verified model/revision, and observed behavior. |
| **P1** | API/system-call coverage | 4.06 PE imports and references are broadly inventoried; 4.6 main-driver/helper callsites and selected dynamic/COM/hook paths are audited. A new hash-pinned pass adds the outer 4.6 installer's 135 import rows and 281 decoded calls to IAT thunks. Raw syscall-byte candidates were checked in these named images. | An import/callsite ledger is not a full CFG or proof of API purpose/reachability. Ten 4.06 import rows remain without a recovered invocation path in the cited audit; 4.6 reconciled main-driver callsites and installer calls still leave callbacks, indirect data flow, branch reachability, and arguments incomplete. No direct syscall instruction was identified in the scanned user-mode sections; this does not cover OS/kernel or HID-class-driver behavior. | Finish per-binary API semantics for remaining unresolved rows, then trace call arguments/results and resource ownership along reachable functions. For dynamically resolved APIs, prove descriptor→resolver→consumer chains. Scope any “system calls” statement to exact binaries and scan method; distinguish Win32 imports from native syscalls and OS driver behavior. |
| **P2** | RK Drive Web App and model-selected web tools | The seven-bundle snapshot inventories model data and selected RK68 HE lighting, keymap/macro/display, and mouse paths. A new hash-pinned pass documents all six communication workers, their 78 constructor sites in the entry bundle, queue/retry schedulers, and direct WebHID discovery/report API callsite candidates. The selector audit adds nine files for the shared `drive2.rkgaming.com` route and 91 files for `rk.hubx.pro`, with byte hashes and lexical symbol candidates. | None of the three route builds is fully deminified/reconstructed. Full UI routes, packet serializers, dynamic selectors, firmware gates, browser-to-OS behavior, and per-model operation reachability are not covered. The public registry is explicitly not a full catalog. Two new route snapshots also have TLS verification caveats recorded in their acquisition report. | Recover module boundaries and feature call graphs for each bundle. Trace device chooser → protocol factory → feature check → read/apply/readback/rollback for each protocol family; separately enumerate product-selected web packages and selector results. Record missing/dead/unknown routes without interpreting strings as implemented behavior. |
| **P2** | UI, assets, localization, and model-specific presentation | Profile/resource/localization inventories and selected loader/control paths exist for 4.06 and 4.6. New 4.6 traces link a `CKeyDlg` right-button selection to localized knob-option arrays, map shared `0x0477` popup senders to RTTI-attributed page handlers, and identify the screen map owner as `CScreenDlg`. A focused argument-origin audit also checks the known popup creators. | Resource inventories do not establish every asset's runtime owner, every dynamic control's handler, every localized label's feature, or the model/version rules choosing photos, skins, layouts, and effects. None of the statically traced senders establishes delivery to `CKeyDlg` with `lParam=2`; the source and visible control remain unresolved. | Create a per-page crosswalk from resource/control or runtime constructor → localization key → handler → state field → persistence/worker. Trace all profile artwork and fallback selection rules independently of public product photos. |

## Recommended work order

1. Establish the official package/version inventory first; otherwise new binary
   work can be mistaken for universal coverage.
2. Rebuild the full static graph for the changed 4.6 main driver and reconcile
   it against 4.06. This is the largest known binary delta and the main
   blocker to claiming the latest Hub driver is understood.
3. Recover installer callbacks and complete updater state/data flow, preserving
   each package version boundary.
4. Close family protocol schemas and profile compatibility as static evidence;
   separately label anything that cannot be confirmed without runtime/device
   observations.
5. Expand the Drive/web audit, then finish UI/resource crosswalks across each
   acquired package.

This sequence supports reverse engineering before clone parity work. It does
not make full-suite completion a percentage: the denominator is not known
until the supported official package universe is enumerated, and several
remaining claims require runtime evidence that static disassembly alone
cannot supply.

## Evidence discipline

Use **proven statically** only for a fact tied to a hash-pinned package, bytes,
resource, profile row, import, or decoded control-flow path. Use **inferred**
for likely feature purpose. Use **unresolved** for unobserved runtime
reachability, actual model/revision identity, device acceptance, unsupported
package versions, and behaviors hidden behind dynamic or external code. A
missing scan hit is not evidence that a function or API is unused.
