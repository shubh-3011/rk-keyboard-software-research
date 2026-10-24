# Full-suite reverse-engineering gap matrix — status updated 2026-10-21

## Scope of this review

This audit combines the repo's coverage ledger, artifact index, package
manifests, and component reports with the hash-pinned static analyses added on
2026-10-20. It identifies the largest remaining evidence gaps and the next
static work that would reduce them. It does not claim that the vendor suite
has been fully reverse engineered.

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
  has a static UDIF/APFS-block/Mach-O/ASAR carve pass. Member comparison finds
  4,362 raw-hash matches and 185 additional CRLF/LF-only matches; one common
  `background.js` still differs, while APFS paths and asset ownership remain
  unresolved. A focused pass ties its changed Webpack factory to the same HID
  wrapper and byte-identical worker source while leaving the larger semantic
  delta unattributed. The eight S98
  Tri-mode RGB updater variants are hash-pinned and statically audited. Current
  firmware-selector acquisition is 117/118 distinct URLs (one F99 `/0218`
  returns HTTP 404); 349/354 selector rows map to acquired bytes, with four
  rows unassociated. All 38 QMK JSON definitions, 38 ZIP source overlays, and
  seven separately acquired QMK HEX files are hash-pinned. The HEX files have
  static checksum/address-map comparison, not disassembly. A new static PE
  family pass verifies the 117 acquired files and groups 99 PE hashes into 16
  executable-section byte profiles; 80 hashes match two S98 updater code
  profiles, while their appended data/PIDs still differ. It records SINO
  overlay-to-selector PID mismatches and unvalidated comparison candidates.
  A representative follow-up covers six non-S98 native profiles and all eight
  CLR images: 27,082 linear import-call candidates, 1,810 entrypoint-rooted
  imports, 14 rooted generic file/device-I/O calls, and no rooted HID, SetupAPI,
  WinUSB, or serial-specific references. The eight CLR images now have metadata
  and linear IL evidence: 1,456 decoded method bodies, 30,774 instructions, and
  6,332 resolved call references, including a WMI/VID/PID discovery and
  embedded-helper extraction/process-launch path. A follow-up verifies 24
  parent-to-resource links to three unique embedded PE payloads and inventories
  their sections, imports, exports, resources, and strings; the helper declares
  HIDAPI and libusb imports. Its 6,523 linear-sweep call/jump results remain
  unvalidated candidates. No helper CFG or reachable transfer path is proven.
  Other updater callgraphs, indirect transfers, some driver routes,
  historical/retired releases, and exact model
  revisions remain unresolved. See the [selector API audit](rk-official-selector-api-catalog-audit-2026-10-19.md),
  [product-specific package audit](rk-product-specific-software-package-audit-2026-10-19.md),
  [firmware inventory](rk-firmware-selector-static-inventory-2026-10-19.md),
  and [macOS F99 findings](rk-f99-macos-static-findings-2026-10-20.md).
  A route-specific follow-up resolves all 19 dated Driver platform rows: five
  package downloads, two Web roots, and seven OS rows with no URL. It collected
  hash-indexed HTML/JS/CSS for the shared `drive2.rkgaming.com` app and separate
  `rk.hubx.pro` route. The first host had an expired TLS certificate during
  capture; the hubx bytes were initially acquired without TLS validation.
  Static follow-ups trace drive2 connect/initialization and RK68 HE setup,
  lighting, and selected keymap/macro/advanced/performance/settings routes;
  they do not close either web app's full call graph.
  See the
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
| **P0** | Official package/version universe | Public distribution routes, dated Hub 4.6, Drive snapshots, current selector metadata, and a route-by-route audit of all 19 dated Driver platform rows are documented. The firmware catalog has bytes for 117/118 unique URLs; the QMK catalog has all 83 URLs acquired across JSON, ZIP, and HEX passes. Four Windows product-specific samples and an F99 Mac static package pass are documented. Static representative analyses cover six non-S98 native updater families, eight CLR metadata/IL images, and bounded WebHID paths for drive2 and RK68 HE. | Current catalog is still bounded to the dated English selector; other product-specific routes, historical/retired/regional packages, model revisions, and 404/unassociated records remain unresolved. Firmware PE metadata and representative call paths do not complete each package's graph. The selector Web apps have partial connection and feature paths, not full per-page behavior or hardware evidence. | Expand CFG/call-path analysis for remaining firmware profiles and the embedded CLR helper/DLLs; complete drive2 response/UI paths and remaining RK68 HE routes; then expand to historical and regional catalogs where public evidence exists. Record inaccessible, removed, and unassociated targets distinctly. |
| **P1** | Product-specific Windows/macOS app families | Static archive/PE/ASAR inventories cover GamingForceZ packages for RK918-labeled/RK919 and S108, R99 RK Driver, and F99 AI RK Setup. Focused paths include GamingForceZ UI/configuration → plugin relationships and report wrappers; R99 CH375/HID discovery, request buffers, shared IOCTL, and archived installer paths; F99 Windows DPI selection → `App_Set_Dpi` → report queue → native HID write and firmware query/OTA → OTA report writer; and a macOS DMG with 17 universal Mach-O candidates, HID symbols, a validated ASAR, and member-hash comparison against Windows. The F99 trace scans 95 literal renderer IPC calls across 91 hash-pinned sidecar scripts. Of 4,548 common in-archive files, 4,362 match byte-for-byte and 185 more differ only by CRLF/LF. A focused `background.js` pass shows unchanged entry factory 338 requires changed factory 607 on both platforms, which reaches the same HID wrapper and byte-identical worker source; it records 1,409 coarse changed spans. | None is a full function map. The F99 renderer sidecars are not indexed in the pinned ASAR header, so their pairing with the main bundle is unproven; the scan found no literal renderer lighting/keymap channel and its DPI/version endpoint evidence is mouse-oriented. GamingForceZ slider/event-to-Writer serialization, R99 helper/driver semantics and model gates, APFS file-to-binary attribution, macOS assets, semantic attribution of the 1,409 spans and 129 unmatched module hashes per side, and actual hardware behavior remain unresolved. | Complete hash-pinned graphs per package; establish F99 renderer/main package provenance and trace any remaining UI-to-controller routes, recover APFS directory/path mappings, and attribute the F99 changed spans and remaining UI state → helper/native boundary → model gate → serializer edges. Keep byte identity, lexical/import evidence, call paths, and runtime behavior separate. See the [F99 renderer-to-HID report](rk-f99-windows-ui-ipc-to-hid-trace-2026-10-20.md). |
| **P0** | Changed 4.6 `DeviceDriver.exe` | Hash-pinned imports/callsites, selected API paths, RTTI family routing, vtables, feature traces, and an MFC scan with 145 structurally validated accessor/table candidates (1,214 rows; 144 with RTTI/vtable association evidence) exist. The hash-pinned linear sweep covers the 1,723,392-byte executable section. The bounded root-seeded CFG pass starts from the PE entrypoint, 1,033 unique MFC handlers, and 77 proven entries across the `CDevG5KB`, `CDevRKKB`, and RTTI-identified `CDev3632` vtables (52 unique targets). It processes 3,450 candidate roots and records 31,639 basic blocks, 13,677 unique direct-call edges, 3,030 unique exact IAT call sites, 73 IAT tail jumps, and 447 imported API names with rooted transfers. The seeded paths visit 582,534 instruction bytes (33.80% of raw `.text`). Follow-ups prove that registry helper `0x004ACEF8` recursively processes child keys and then deletes the parent key, and manually resolve two branch-spanning `SetupDiGetDeviceInterfaceDetailW` calls through their query/retrieval arguments to `CreateFileW`. See the [root-seeded CFG audit](rk-v4.6-rooted-cfg-callgraph-audit.md) and its reproducible scanner. | This changed native image still lacks a complete function map or CFG. Root addresses are candidates, not validated function boundaries; linear sweep can decode data as instructions, and neither pass proves reachability or runtime behavior. The raw scanner ledger has 3,568 indirect-call contexts (3,564 distinct sites); manual review resolves four in the `WM_DEVICECHANGE` handler and two SetupAPI detail calls, leaving 3,562 contexts (3,558 distinct sites) unresolved. It also leaves 123 indirect jumps, 147 possible tail transfers, and 66.20% of `.text` bytes outside selected paths. It records 402 instruction addresses attributed to multiple roots. Vtable/callback/COM/computed/dynamic targets remain unresolved. The PDB path in debug metadata did not yield a local matching PDB. The bounded MFC scan does not prove dispatch or complete map coverage; the recursive delete's UI caller and concrete registry path remain unknown. | Validate function starts and code/data boundaries for this hash; resolve indirect, vtable, callback, COM, delayed/dynamic, and tail-transfer edges; and extend coverage beyond seeded paths. Then map each MFC owner/page and runtime-created control to handlers, persistence, worker, family serializer, and imported API. Diff normalized functions/data against 4.06 and list unmatched regions. The [linear-sweep report](rk-v4.6-driver-linear-sweep-inventory.md) and [reproduction script](../scripts/audit_rk46_driver_linear_sweep.py) provide a baseline, while the [root-seeded CFG report](rk-v4.6-rooted-cfg-callgraph-audit.md) narrows but does not close the full graph gap. |
| **P1** | Setup, install, and uninstall behavior | 4.06 Inno/helper findings and a new 4.6 hash-pinned recovery cover six exported callback bodies plus the reconstructed setup descriptor: nine callback evidence rows and 1,271 action rows, including 1,249 file records and two `AfterInstall` links. The outer installer also has 135 ordinary import rows and 281 decoded calls to IAT thunks. | The recovered bytecode and descriptor do not establish Inno dispatch order, branch execution, file/registry/shortcut effects, overwrite/rollback behavior, or runtime side effects. SourceForge's direct innounp download was unavailable; extraction-tool provenance is through a pinned Chocolatey package and its upstream verification note. The generated 4.6 uninstaller is absent. | Resolve installer-engine callback order/conditions and version-specific loader/helper behavior from static evidence; compare recovered actions with 4.06. Recover the generated uninstaller if an exact installed artifact becomes available. Keep bytecode, descriptor metadata, inferred Windows effects, and runtime outcomes separate. See the [callback recovery](rk-v4.6-inno-installer-callback-recovery-2026-10-20.md). |
| **P1** | Updater and firmware package semantics | The Hub updater is hash-identical across the two Windows snapshots. Its command `0x0419`, mode-3 preflight/status-to-worker path, all 15 UART dispatch entries and direct state-store edges, feature-read/write sites, conditional file sink, and mode-3 `.upf` section transform have targeted reports. The S98 selector's eight Tri-mode RGB updater variants are mapped at package/container/resource/import level with selected HID paths. A selector PE-family pass identifies 16 executable-section profiles, including two exact S98 code profiles reused by 80 PE package hashes, and records SINO overlay/PID fields. Six non-S98 native representatives have bounded entrypoint-rooted scans. All eight non-S98 CLR images have metadata and linear IL inventories: 6,074 selected metadata rows, 1,456 decoded method bodies, 30,774 instructions, and 6,332 resolved call references. The IL statically links WMI USB discovery, VID/PID classification, extraction of an updater helper and native DLLs, and a helper-process launch. | Neither Hub nor S98 has a closed end-to-end UI-to-transfer graph or established device acceptance. The Hub `.upf` validation/length issues remain; S98's post-transform image format, report meanings, model/revision gates, retry/cancel lifecycle, and profile-to-firmware compatibility remain unresolved. The six native representatives retain 972 unresolved indirect transfers. The CLR IL scan is linear and has no CFG/reachability proof; embedded payloads have PE inventories but no validated helper CFG or reachable API paths. Five selector/overlay PID discrepancies are not traced to acceptance behavior. | Reconcile updater state transitions with callers; map retry, timeout, cancellation, progress, and cleanup from UI to HID/UART helper. Build CFG/call graphs for the CLR event/update paths and statically analyze the embedded helper/native payloads; continue entrypoint/API analysis for remaining code families and investigate overlay discrepancies without treating comparison hits as gates. Keep host-side transfer separate from device flash/readback evidence. See the [S98 updater audit](rk-s98-firmware-updater-static-audit-2026-10-19.md), [firmware PE family audit](rk-firmware-pe-family-static-audit-2026-10-20.md), [native call-path report](rk-firmware-pe-call-path-static-audit-2026-10-20.md), [CLR metadata report](rk-firmware-clr-metadata-static-audit-2026-10-20.md), and [CLR IL report](rk-firmware-clr-il-static-audit-2026-10-20.md), plus the [embedded payload report](rk-embedded-payload-static-audit-2026-10-20.md). |
| **P1** | Family protocols and 265-profile compatibility | 4.06 and 4.6 profile routes are statically mapped to RKKB/G5/3632 classes; selected serializers and worker paths have detailed reports. Bounded 4.06 scans resolve five additional direct `+0x68` candidates as rectangle/layout paths and 78 register-mediated candidates through constructor-established local vptrs to `USER32!DrawTextW`; five more resolve on listed helper/paint-handler caller paths. Together with seven earlier classifications, this accounts for all 90 loose-pattern rows. The 2026-10-22 stack-normalization correction retracts the prior overwritten-receiver/GDI+ claims. See the [correction](rk-406-stack-alias-corrections.md) and [forwarded-receiver report](rk-406-forwarded-text-receivers.md). | Class routing is package logic, not physical support. Many command fields, family-specific request/response meanings, firmware revisions, model aliases, and hardware acceptance remain unresolved. The 4.06 G5 command-`0x88` caller and returned-buffer consumer remain unresolved. In 4.6, the command-`0x88` helper conditionally copies response chunks into caller memory after a request write, but no caller, complete range, or file sink is attributed and the response meaning is unknown. The five forwarded sites retain unknown alternate callers/runtime receivers; other dispatch forms and aliases are not exhausted, and the profile catalog is not a universal SKU matrix. | For each family, inventory every virtual method and serializer branch; derive field-level schemas from all callers and response consumers; map profile flags to reachable branches; reconcile with every acquired package/profile. Maintain separate rows for static route, declared descriptor, verified model/revision, and observed behavior. |
| **P1** | API/system-call coverage | 4.06 PE imports and references are broadly inventoried; 4.6 main-driver/helper callsites and selected dynamic/COM/hook paths are audited. A hash-pinned 4.6 HID rescan follow-up traces report-ID selection, the 80-row availability gate, and the copied capability fields; the cross-version call-path audit records unchecked `HidD_GetAttributes` returns and a successful-capability preparsed-data release gap. Two consumers compare profile-row VID/PID and HID usage/report-length fields, and a follow-up links those arguments to selector rows and `Fw`-selected `CDevRKKB`, `CDev3632`, or `CDevG5KB` routes. This closes the static software profile-to-driver bridge for the examined 4.6 package, not physical model/revision compatibility. The outer installer imports and compiled callbacks are separately mapped; raw syscall-byte candidates were checked in named images. A separate 4.6 trace joins the selected language index to `WritePrivateProfileStringW` for `[OPT] LangIndex` in host `lang.ini`; the package app/Cfg.ini and startup code imply the intended prefix if that config is selected, but the absolute cfg.ini path, runtime execution, and write success remain unproved. The same report traces a `GetTempPathW`/`GetTempFileNameW`/delete-on-close `CreateFileW` factory, with toolbar-property-page callers reaching MFC serializer 0x004A49B9; the state-dependent byte stream remains incomplete. The shared registry is RTTI-identified CMenuHash; a [lifecycle follow-up](rk-v4.6-temp-registry-lifecycle.md) maps single-key close/remove and bulk close from a COemDrvApp loop-termination branch. The global destructor frees storage separately. A selected local replacement-failure path can retain the old closed-handle value under stated assumptions; actual failure, reuse, concurrency, cleanup success, and all exit paths remain unobserved. | An import/callsite ledger is not a full CFG or proof of API purpose/reachability. Ten 4.06 import rows remain without a recovered invocation path in the cited audit; 4.6 reconciled main-driver callsites and installer calls still leave indirect data flow, branch reachability, and arguments incomplete. No direct syscall instruction was identified in the scanned user-mode sections; this does not cover OS/kernel or HID-class-driver behavior. | Finish per-binary API semantics for remaining unresolved rows, then trace call arguments/results and resource ownership along reachable functions. For dynamically resolved APIs, prove descriptor→resolver→consumer chains. Scope any “system calls” statement to exact binaries and scan method; distinguish Win32 imports from native syscalls and OS driver behavior. |
| **P2** | RK Drive Web App and model-selected web tools | The seven-bundle snapshot inventories model data and selected RK68 HE lighting, keymap/macro/display, and mouse paths. A hash-pinned pass documents all six communication workers, their 78 constructor sites, queue/retry schedulers, and direct WebHID candidates. The selector audit adds nine `drive2.rkgaming.com` files and 91 `rk.hubx.pro` files. `drive2` has a connect-to-WebHID trace and 17-packet initialization path; `rk.hubx.pro` has a `/setup` device-picker/model-gate trace and selected `/lighting`, `/keyboard`, `/macro`, `/advanced`, `/performance`, `/features`, `/settings`, and `/devices` paths through V3 controller/report calls. | None of the three route builds is fully deminified/reconstructed. The drive2 inbound parser, device page, packet semantics, and PID-to-model mapping remain open. HubX rhythm receiver behavior, custom-layout device effects, several non-RT performance chains, remaining feature-page handlers, browser/device runtime behavior, firmware gates, and per-model operation reachability remain open. The public registry is not a full catalog. Two route snapshots have TLS verification caveats recorded in their acquisition report. | Recover module boundaries and feature call graphs for each bundle. Trace remaining page → controller → report paths, complete drive2 response parsing/UI gates and PID-to-model mapping, and identify missing/dead/unknown routes without treating strings as implemented behavior. |
| **P2** | UI, assets, localization, and model-specific presentation | Profile/resource/localization inventories and selected loader/control paths exist for 4.06 and 4.6. New 4.6 traces link a `CKeyDlg` right-button selection to localized knob-option arrays, map shared `0x0477` popup senders to RTTI-attributed page handlers, and identify the screen map owner as `CScreenDlg`. The 4.06 LED label builder has a profile-wide 24-slot candidate crosswalk, with `Fw`/`RGBKb` family choice and `LedMask` skip rules. A full-code LightUI reference census finds writes only in the profile loader. A 4.06 profile-art caller builds `Dev\\%04X\\<name>` paths, selects `kbled.png` or tries `keycfg.png` then `keyimg.png`, and loads the asset through GDI+; the installed folders contain 102 `kbled.png`, 102 `keyimg.png`, and no `keycfg.png`, while runtime display remains unknown. A new RTTI/MFC trace joins `CLedDlg+0x1A6C` to `CPngSliderBar`, selector `0x95`, its `0x0800`/`0x0801` sender methods, and matching parent handlers; runtime dispatch and user-visible meaning remain unknown. The runtime `+0x04` record field is initialized from `DefBri`; the selected-row helper and its five direct callers do not write that field. The `0x0800` parent handler can conditionally signal worker mask `0x02` and save eligible `0x3E74`-byte objects to `pro.dct`, including their current `+0x04` bytes; the observed save-loop mutation is selected-row `+0x213C`, not brightness. Family serializers can conditionally consume the current value through `LightHW`, but the runtime worker receiver and UI-to-value-writer edge remain unresolved; see the [brightness field-boundary audit](rk-406-brightness-handler-field-boundary.md). A 4.6 [text-macro command bridge](rk-v4.6-textmacro-command-bridge.md) maps CKeyFunPickDlg virtual WM_COMMAND, its Apply-caption CPngBtn sender, state-5 text read/copy/local save, and a CWelcomDlg selection-to-old-save/new-load path. Runtime delivery, option labels, COM getter, and other setup callers remain open. A separate [device-trigger trace](rk-v4.6-textmacro-device-trigger.md) joins `CDev3632` and `CDevG5KB` read-worker decoders through private message `0x07EB`, a mapping cell tagged `0x0A00005B`, non-allocating macro lookup, and host `SendInput`; packet meaning, physical gesture, active profile, delivery, and runtime success remain unobserved. A hash-pinned join covers 22,680 locale/profile/slot rows across all five installed dictionaries (`en`, `Japanese`, `Korean`, `sc`, `tw`): 18,825 carry same-numbered six-cell `LedOptN` tuples and 3,855 lack the key. Static tracing of private `0x0594` identifies a dynamically created `CTreeCtrlExRk` control with ID `0x0105`: localized choices are tree rows identified by `HTREEITEM` tokens, and the selected generated ordinal indexes the corresponding profile slot. A follow-up maps tuple cells 2, 3, 5, and 6 to gated child-object offsets passed through `CWnd::ShowWindow`; numeric control IDs and labels remain unknown. Runtime `wParam`, visibility, and events are unobserved. | Resource inventories do not establish every asset's runtime owner, every dynamic control's handler, every localized label's feature, or the model/version rules choosing photos, skins, layouts, and effects. For LED controls, tuple-cell semantics, exact control-to-cell mapping, option-to-device-effect meaning, runtime message delivery, active device identity, and hardware effect remain unresolved. None of the statically traced senders establishes delivery to `CKeyDlg` with `lParam=2`; the source and visible control remain unresolved. | Continue per-page crosswalks from resource/control or runtime constructor → localization key → handler → state field → persistence/worker. Trace all profile artwork and fallback selection rules independently of public product photos. Determine the six tuple-cell meanings, identify controls for each cell, and continue through the existing serializers. |

## Recommended work order

1. Establish the official package/version inventory first; otherwise new binary
   work can be mistaken for universal coverage.
2. Rebuild the full static graph for the changed 4.6 main driver and reconcile
   it against 4.06. This is the largest known binary delta and the main
   blocker to claiming the latest Hub driver is understood.
3. Resolve remaining installer dispatch, generated-uninstaller, and updater
   state/data-flow gaps, preserving each package version boundary.
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
