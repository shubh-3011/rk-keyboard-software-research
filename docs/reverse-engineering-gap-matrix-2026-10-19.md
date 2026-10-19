# Full-suite reverse-engineering gap matrix — 2026-10-19

## Scope of this review

This is a documentation-level audit of the repo's coverage ledger, artifact
index, package manifests, and existing component reports. It identifies the
largest evidence gaps and the next static work that would reduce them. It is
not a new binary analysis and does not claim that the vendor suite has been
fully reverse engineered.

The repo currently has three bounded evidence sets:

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

See the [coverage ledger](../COVERAGE.md), [4.6 package snapshot](rk-v4.6-package-snapshot.md),
[4.6/4.06 binary delta](rk-v4.6-native-binary-delta-audit.md),
[Drive audit](rk-drive-web-app-audit.md), and
[official distribution boundary](rk-official-driver-distribution-audit.md).

## Priority matrix

| Priority | Component or scope | Evidence already present | Gap that blocks a whole-suite claim | Next bounded static audit |
|---|---|---|---|---|
| **P0** | Official package/version universe | Public distribution routes and dated Hub 4.6, installed 4.06, and Drive snapshots are documented. A new membership audit pins the outer 4.6 installer, its extracted 1,249-file payload, the 810-file installed 4.06 tree, and the seven-bundle Drive snapshot; it verifies the 17 baseline-only paths and key resource deltas. | No complete current or historical inventory of Hub, Web, product-selected drivers, firmware, QMK/VIA definitions, regional releases, or older driver packages. Therefore the inspected files cannot define “the whole RK software.” | Enumerate the official selectors and reachable package metadata by model, revision/attribute, OS, language, and route. Record source URL, date, size, hash, and package family for each discovered artifact; then choose version representatives and compare them. Keep a “not acquired” list for unavailable/retired items. |
| **P0** | Changed 4.6 `DeviceDriver.exe` | Hash-pinned imports/callsites, selected API paths, RTTI family routing, vtables, feature-specific traces, and a new MFC scan with 145 structurally validated accessor/table candidates (1,214 rows; 144 with RTTI/vtable association evidence) exist. | It is a changed native image; the 4.06 address/control-flow evidence cannot simply be carried over. Current 4.6 work is selective, and the repo explicitly says its full CFG and new-driver call graph are not reconstructed. The MFC scan is signature-bounded and does not prove dispatch or complete map coverage. | Build function boundaries and a CFG/callgraph for this hash; resolve direct, vtable, callback, COM, delayed/dynamic, and register-indirect edges. Then map each MFC owner/page and runtime-created control to handlers, persistence, worker, family serializer, and imported API. Diff normalized functions/data against 4.06 and list unmatched regions. |
| **P1** | Setup, install, and uninstall behavior | 4.06 Inno and helper findings exist; the 4.6 installer is identified as Inno 5.3.3 and statically extracted. A hash-pinned audit maps its 135 ordinary imports to decoded IAT stubs and 281 relative calls. The 4.6 setup callbacks were not recovered; its generated uninstaller is absent from the extracted payload. | Import transfer coverage does not reveal exact callback order, file/registry/shortcut actions, overwrite rules, rollback behavior, generated uninstaller contents, or runtime side effects. The 4.06 script is only a baseline, not proof of 4.6 behavior. | Continue offline recovery of the 4.6 compiled PascalScript and setup-data structures; separately trace the version-specific loader/helper code. Compare all recovered callback actions with 4.06. Mark each callback/action proven, inferred, or unrecovered; do not infer missing actions from the baseline. |
| **P1** | Updater and firmware package semantics | The updater is hash-identical across the two Windows snapshots. Its command `0x0419`, mode-3 preflight/status-to-worker path, UART states, feature-read/write sites, conditional file sink, and mode-3 `.upf` section transform have targeted reports. | The complete UI-to-state-machine-to-transport graph, all mode/model gates, all frame and status fields, `.upf` format/validation, and profile-to-firmware compatibility are not established. The one packaged `.upf` declares an A length larger than its remaining payload; static transform arithmetic also yields a one-byte B boundary overrun if reached. Allocator/read behavior and runtime acceptance remain unresolved; no successful update/readback is evidenced. | Complete the updater's 15 dispatch entries and every state transition from UI event to HID/UART helper, including retry, timeout, cancellation, progress, and cleanup. Parse all statically available update-package examples and compare headers/sections to code checks. Keep “host image transfer” separate from “device flash readback.” |
| **P1** | Family protocols and 265-profile compatibility | 4.06 and 4.6 profile routes are statically mapped to RKKB/G5/3632 classes; selected serializers and worker paths have detailed reports. | Class routing is package logic, not physical support. Many command fields, family-specific request/response meanings, firmware revisions, model aliases, and hardware acceptance remain unresolved. The profile catalog is not a universal SKU matrix. | For each family, inventory every virtual method and serializer branch; derive field-level schemas from all callers and response consumers; map profile flags to reachable branches; reconcile with every acquired package/profile. Maintain separate rows for static route, declared descriptor, verified model/revision, and observed behavior. |
| **P1** | API/system-call coverage | 4.06 PE imports and references are broadly inventoried; 4.6 main-driver/helper callsites and selected dynamic/COM/hook paths are audited. A new hash-pinned pass adds the outer 4.6 installer's 135 import rows and 281 decoded calls to IAT thunks. Raw syscall-byte candidates were checked in these named images. | An import/callsite ledger is not a full CFG or proof of API purpose/reachability. Ten 4.06 import rows remain without a recovered invocation path in the cited audit; 4.6 reconciled main-driver callsites and installer calls still leave callbacks, indirect data flow, branch reachability, and arguments incomplete. No direct syscall instruction was identified in the scanned user-mode sections; this does not cover OS/kernel or HID-class-driver behavior. | Finish per-binary API semantics for remaining unresolved rows, then trace call arguments/results and resource ownership along reachable functions. For dynamically resolved APIs, prove descriptor→resolver→consumer chains. Scope any “system calls” statement to exact binaries and scan method; distinguish Win32 imports from native syscalls and OS driver behavior. |
| **P2** | RK Drive Web App and model-selected web tools | The seven-bundle snapshot inventories model data and selected RK68 HE lighting, keymap/macro/display, and mouse paths. | The bundles are not fully deminified/reconstructed. Full UI routes, all protocol-module implementations, dynamic selectors, firmware gates, and per-model operation reachability are not covered. The public registry is explicitly not a full catalog. | Recover module boundaries and feature call graphs for each bundle. Trace device chooser → protocol factory → feature check → read/apply/readback/rollback for each protocol family; separately enumerate product-selected web packages and selector results. Record missing/dead/unknown routes without interpreting strings as implemented behavior. |
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
