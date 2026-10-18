# Coverage and open work

This file prevents the package snapshot from being mistaken for a universal RK
model or runtime map.

## Native Windows reconstruction milestone

- The research repository now includes a source-first C# WPF Windows app in
  [`rebuild/windows/`](rebuild/windows/), separate from the Keydeck web app
  and the earlier Python/WebView2 workbench. It browses the 265-profile
  4.6-labeled catalog and a second 177-row RK Drive keyboard directory with
  on-demand photos linked to RK's hosts and a manual S98 appearance selector,
  read-only Windows PnP matching for
  catalogued VID/PID pairs, local-only key-label drafts, macro notes,
  notification-area restore/exit, and opt-in per-user startup.
  Its standalone EXE is built by the project script; it does not need Python,
  a browser, or WebView2.
- The app uses Windows SetupAPI's present-device list and reads USB/HID PnP
  properties to match known VID/PID pairs to catalog entries. It does not open a keyboard interface,
  read HID reports, or learn current RGB color/mode. Key and macro edits are
  local drafts, and lighting writes, hardware settings, screen transfer,
  updates, reset, and firmware operations remain unavailable. The native
  reconstruction is incomplete and is not a full RK clone. See the
  [rebuild README](rebuild/windows/README.md) and
  [parity roadmap](REBUILD-ROADMAP.md).

## Public RK Drive Web App snapshot

- A dated static snapshot of the public RK Drive Web App enumerates seven JS
  bundles, 177 keyboard connection descriptors across 96 labels, and two
  separate RK68 HE Bytech model profiles. It records 93 keyboard product
  photos, two HE layout backgrounds, and one mouse photo by public URL. The
  extracted declarations include key layers, OS tables, layout-group counts,
  lighting-effect fields, HE product IDs/UUIDs, and profile feature flags.
  The companion audit also covers the 20-row legacy mouse registry, 20 chooser
  aliases, CB75-Mouse profile, and static feature families.
  These are snapshots of the browser app's observed registry, not every RK
  product; complete control-to-handler and hardware reachability remain open.
  See the [base audit](docs/rk-drive-web-app-audit.md),
  [feature-gate/mouse audit](docs/rk-drive-feature-gate-and-mouse-audit-2026-10-18.md),
  [RK68 HE lighting UI/protocol crosswalk](docs/rk-drive-rk68-he-lighting-ui-protocol-crosswalk-2026-10-18.md),
  and [keymap/macro/display crosswalk](docs/rk-drive-keymap-macro-display-crosswalk-2026-10-18.md),
  plus the [mouse registry](docs/rk-drive-mouse-registry.csv).
  The lighting crosswalk maps feature gates, UI service calls, effect
  read/apply/readback/rollback, custom-main records, and grouped per-key RGB
  serialization in the hash-pinned entry bundle. It does not establish
  hardware acceptance or model-wide support.
- A second live refresh at `2026-10-18T08:47:15Z` matched all seven saved
  bundle hashes and the derived catalog data. This confirms the dated snapshot
  against the public deployment at that time; it does not confirm hardware
  behavior. See the [live recheck record](docs/rk-drive-live-recheck-2026-10-18.md).

## Additional official 4.6 Windows Hub Driver snapshot

- A separately downloaded official 4.6 package was extracted statically, not
  installed or run. Its full 1,249-file path/size/SHA-256 inventory and
  provenance are in [`docs/rk-v4.6-package-snapshot.md`](docs/rk-v4.6-package-snapshot.md)
  and [`docs/rk-4.6-package-manifest.csv`](docs/rk-4.6-package-manifest.csv).
- A normalized path/hash comparison with the installed 4.06 tree records
  743 identical, 50 changed, 455 added, and 17 absent application paths; see
  [`docs/rk-package-file-delta-v4.06-v4.6.md`](docs/rk-package-file-delta-v4.06-v4.6.md)
  and its row-level CSV. The absent classification is package-payload
  comparison, not an installer-deletion claim.
- A new path-role inventory classifies all 1,249 files in the 4.6-labeled
  extracted tree into 17 groups and inventories resources for all 265 named
  profiles. It checks every path, size, and SHA-256 against the package
  manifest before generating the tables. The Side LED resource rows confirm
  that both `02B4` and `0258` set `ShowSideLED`, while only `02B4` has
  `sideled.png` and four SideLed locale dictionaries. See the
  [inventory report](docs/rk-v4.6-resource-inventory.md),
  [group CSV](docs/rk-resource-group-inventory-v4.6.csv),
  [per-profile asset CSV](docs/rk-model-resource-asset-inventory-v4.6.csv),
  and [generator/verifier](scripts/audit_rk46_resource_inventory.py).
- The extracted package contains 265 named profile files and 140 unique
  layouts. The generated catalog and comparison report are
  [`models-4.6.json`](models-4.6.json) and
  [`docs/rk-profile-catalog-v4.6-delta.md`](docs/rk-profile-catalog-v4.6-delta.md).
- A dated cross-catalog matrix compares those profile IDs with the RK Drive
  registry: 39 exact direct-ID overlaps in the 4.06 catalog and 93 in the
  4.6-labeled catalog. It separates shared wireless receiver IDs and details
  the S98 regional candidates; these are registry matches, not validation of
  physical model identity or compatibility. See
  [`docs/rk-package-drive-model-evidence-matrix-2026-10-18.md`](docs/rk-package-drive-model-evidence-matrix-2026-10-18.md).
- The 4.6 `DeviceDriver.exe` has a different SHA-256 from 4.06. Its import and
  binary changes are audited separately in
  [`docs/rk-v4.6-native-binary-delta-audit.md`](docs/rk-v4.6-native-binary-delta-audit.md).
  A follow-up checked all eight `0F 05`/`0F 34` byte candidates against
  instruction boundaries and adjacent indexed tables: none is a direct
  syscall/sysenter instruction in this PE. This static result does not cover
  calls made inside Windows or device-driver code. See
  [`docs/rk-v4.6-system-call-byte-audit.md`](docs/rk-v4.6-system-call-byte-audit.md)
  and its [candidate ledger](docs/rk-v4.6-syscall-byte-matches.csv).
  Separate static follow-ups now map the 4.6 profile selector and the Side LED
  configuration/UI/report-builder path, but this is still not a full
  function-level reanalysis. Side LED is enabled in profiles `02B4` and
  `0258`; only the first has side-light artwork/localization in this package.
  A ten-entry MFC message map and state-record path into the report builder are
  recovered; whether a given UI event schedules that builder remains open.
  The report builder reaches a generic HID feature writer, but event meanings,
  packet fields, model compatibility, and runtime behavior remain unresolved.
  See the [Side LED audit](docs/rk-v4.6-side-led-static-audit.md) and its
  [message-map follow-up](docs/rk-v4.6-side-led-message-map-follow-up.md).
  Other detailed native control-flow reports remain tied to the 4.06 binaries.
- A separate 4.6 screen/GIF trace maps the user-selected NewGIF path through
  shared frame-list fields, the 512-entry worker snapshot, the RGB565
  converter, G5 vtable methods for parameter/page transfer, and the
  `HidD_SetFeature` writer path. This closes the static selected-file-to-frame
  array gap for the multi-frame path. The one-item `New PNG` branch is mapped
  as a GDI+ save of the first listed image. The generic image picker is mapped
  through GDI+ local-image loading and preview geometry/invalidation. The
  candidate paint handler does not read those preview fields, and the separate
  list-processing routine shows no direct pointer link from the preview image
  to the frame list. Visible rendering and indirect/runtime commit behavior
  remain unresolved.
  Decoder details, visible control labels, runtime execution, and physical-
  model acceptance remain unverified. See
  [`docs/rk-v4.6-screen-gif-ui-transport-audit.md`](docs/rk-v4.6-screen-gif-ui-transport-audit.md).
- A hash-pinned 4.6 import/callsite pass records candidate direct, thunk,
  relative, and straight-line register-indirect transfers, including HID and
  local macro-file references. A follow-up maps the prior 16 unresolved
  imports to one IAT load each and 31 register-indirect call candidates; this
  is static transfer evidence, not CFG reachability or runtime proof. One
  branch-spanning SetupAPI route is documented outside the conservative CSV
  heuristic. See the [primary audit](docs/rk-v4.6-native-api-call-path-audit.md)
  and [indirect-reference follow-up](docs/rk-v4.6-unresolved-api-reference-audit.md).
- A new 4.6 API follow-up traces `SendInput` to a gated 50-record UTF-16 text
  lookup and Unicode key-event batches, the added GDI+ property calls to an
  animated-image timer/frame path, and `GetPrivateProfileStringA` to `OPT` /
  `TouchWeb` with an RK Drive URL fallback and selector-`0x12` internal
  action/command dispatch. The visible control origin, actual browser/device
  outcome, text-macro identity, asset ownership, and runtime reachability
  remain open;
  the `SendInput` path is host input synthesis, not keyboard HID output. See
  [`docs/rk-v4.6-native-api-feature-follow-up.md`](docs/rk-v4.6-native-api-feature-follow-up.md).
- A separate 4.6 hook pass maps four thread-scoped `SetWindowsHookExW`
  registrations (`WH_CBT`, `WH_MSGFILTER`, and two `WH_MOUSE` hooks), their
  forwarding sites, callback branches, and direct unhook calls. The direct
  registrations do not include `WH_KEYBOARD` or `WH_KEYBOARD_LL`, but the
  message-filter and key-state imports leave keyboard-related observation
  unresolved. Callback purposes, full reachability, and two CBT unhook pairings
  remain open. Addresses are specific to the 4.6 driver; see
  [`docs/rk-v4.6-windows-hook-callsite-audit.md`](docs/rk-v4.6-windows-hook-callsite-audit.md)
  and the separate [4.06 hook audit](docs/rk-406-windows-hook-callsite-audit.md).
- A focused loader-API follow-up maps all three direct 4.6 `LoadLibraryA`
  sites and four `GetModuleHandleA` sites to their module/export strings,
  pointer consumers, and closest 4.06 counterparts. The callsite roles match
  in this slice; branch execution and outside callers remain unresolved. See
  [`docs/rk-v4.6-dynamic-loader-api-audit.md`](docs/rk-v4.6-dynamic-loader-api-audit.md).
- A focused UI trace confirms the 4.6 driver constructs the added
  `tc_adv_str44`, `tc_screen22/23`, and `tc_knob1–4` items through three
  indexed localization loops. It also maps the eight knob profile rows into
  shared application state, the `CKeyDlg` message `0x477` handler, two posting
  functions, and a gated settings signal. The visible control-to-sender link
  and keyboard acceptance remain open. See
  [`docs/rk-v4.6-ui-knob-localization-path-audit.md`](docs/rk-v4.6-ui-knob-localization-path-audit.md).
- A focused 4.6 text-macro trace maps the `ShowTextMacro` profile gate,
  `textmacro.dct` local read/write helpers, and a 50-record fixed-size buffer
  (`0xC8C8` bytes). The exact path base, MFC event association, and relation to
  keyboard reports remain unresolved; this is host-file persistence evidence,
  not firmware storage. See
  [`docs/rk-v4.6-textmacro-path-audit.md`](docs/rk-v4.6-textmacro-path-audit.md)
  and its [evidence CSV](docs/rk-v4.6-textmacro-path-evidence.csv).
- In the same package, `Dev/01AF/Update.exe` and its `.upf` have hashes
  identical to the installed 4.06 updater and update package. The existing
  updater and firmware-readback findings therefore apply byte-for-byte to
  these two files; the `.upf` remains unvalidated and is not a device dump.
- A per-key XML comparison covers seven UI locales, generic and profile LED
  dictionaries, and profile side-light labels. It records added knob/screen
  strings and side-light resources, eight changed values, two malformed
  Japanese source files, and remaining runtime/UI reachability questions; see
  [`docs/rk-localization-delta-v4.06-v4.6.md`](docs/rk-localization-delta-v4.06-v4.6.md).
- A historical [4.06-rule projection of 4.6 profiles](docs/rk-profile-driver-family-map-v4.6-projected.csv)
  is retained for comparison only and is superseded for direct-profile routes
  by the verified RTTI map below. A static trace of the
  hash-pinned 4.6 driver recovered its own zero, general nonzero, and dedicated
  `Fw=3` selector/constructor branches for all 265 profile rows. The single
  `Fw=3` row is M20 `258A:0208`; the selector's physical-device and downstream
  protocol compatibility remain unvalidated. RTTI links that constructor to
  `CDev3632`; the audit maps its vtable and 20-byte read/write transport while
  leaving feature names and hardware compatibility unresolved. A follow-up
  maps frame offsets, additive request checksum construction, response-queue
  matching, and conservative callsite roles for eight selector values; it does
  not assign feature names or prove device acceptance. See
  [`docs/rk-v4.6-profile-selector-audit.md`](docs/rk-v4.6-profile-selector-audit.md)
  and its [row-level map](docs/rk-v4.6-profile-selector-map.csv), plus the
  [`CDev3632` vtable audit](docs/rk-v4.6-fw3-cdev3632-vtable-audit.md) and
  [frame/selector audit](docs/rk-v4.6-cdev3632-frame-and-selector-audit.md).
- A follow-up resolves all 265 direct-profile rows through the constructor's
  installed vtable and MSVC RTTI: 133 `CDevRKKB`, 131 `CDevG5KB`, and one
  `CDev3632` (M20). This corrects the earlier 4.06-rule projection, which put
  Fw-three M20 in G5. The row-level route is verified for the exact 4.6 PE,
  but no physical-model compatibility is validated; possible companion-device
  paths are outside this direct-profile matrix. A separate 29-slot G5 audit
  maps the verified vtable, the worker's `+0x44` ApplySetting dispatch, and
  command routes for key/layer, macro, LED, RGB-index, color-group, reset, and
  screen/GIF operations. A separate 26-slot RKKB audit now verifies its
  worker `+0x44` dispatch, `ApplySetting` mask branches, and shared 65-byte
  feature-report writer. Both class audits leave UI triggers, payload meanings,
  full model support, and hardware acceptance open; the complete G5 protocol
  map remains incomplete. A focused follow-up reclassifies G5 vtable `+0x20`
  as an inferred stored-path/handle availability probe: it delegates to a
  child object's matching slot or checks an object string with `CreateFileW`
  and an object handle with `HidD_GetAttributes`. The stored path meaning and
  runtime reachability remain unresolved; the method was not invoked. A
  targeted trace maps `+0x34` command `0x82` and `+0x70` command `0x88` to
  conditional response-copy code. A stack audit of all six `HidD_GetFeature`
  calls confirms each uses the same handle as its paired `HidD_SetFeature`;
  `+0x2DC` is a separate report byte. No hardware response was observed. No
  caller is attributable to G5 `+0x70`, and its firmware meaning/range remain
  unresolved. See
  [`docs/rk-v4.6-hid-getfeature-argument-audit.md`](docs/rk-v4.6-hid-getfeature-argument-audit.md).
  A focused caller audit screens signature-compatible `+0x70` sites against
  same-receiver larger-interface slots and point-output use; none is
  attributable to G5. Vtable aliases and other dispatch encodings remain
  unexcluded. See
  [`docs/rk-v4.6-cdevg5-realdata-caller-audit.md`](docs/rk-v4.6-cdevg5-realdata-caller-audit.md).
  See the
  [RTTI route audit](docs/rk-v4.6-profile-family-rtti-audit.md),
  [row-level map](docs/rk-v4.6-profile-family-rtti-map.csv), and
  [reproducer](scripts/audit_rk46_profile_family_rtti.py), plus the
  [G5 vtable/settings audit](docs/rk-v4.6-cdevg5-settings-and-vtable-audit.md),
  [29-slot map](docs/rk-v4.6-cdevg5-vtable-map.csv),
  [password-query trace](docs/rk-v4.6-cdevg5-password-query-audit.md), and
  [G5 verifier](scripts/audit_rk46_cdevg5_vtable.py), plus the
  [RKKB vtable/settings audit](docs/rk-v4.6-cdevrkbb-settings-and-vtable-audit.md),
  [26-slot map](docs/rk-v4.6-cdevrkbb-vtable-map.csv), and
  [RKKB verifier](scripts/audit_rk46_cdevrkbb_vtable.py). A follow-up verifies
  all 24 decoded callers of the deferred-settings signal helper, their
  argument pushes, a separate inline queue producer, and the semaphore handle
  split. A further trace maps the main-window `tc_restore`/`tc_apply` controls
  to one caller and resolves the shared gate to `[OPT] ApplyNow` (default 0;
  bundled `app/Cfg.ini` sets 1); most other signal callers still lack unique UI
  origins and concrete receiver classes. See the
  [caller ledger](docs/rk-v4.6-apply-signal-callers.csv),
  [signal verifier](scripts/audit_rk46_apply_signal_callers.py), and
  [UI/config trace](docs/rk-v4.6-ui-setting-signal-audit.md). Two further
  signal producers are now traced to profile-record mutations and an indexed
  dirty-row setter that calls `USER32!InvalidateRect`. Their UI origins remain
  unresolved; both also invoke a host-local `pro.dct` writer after the queue
  gate, as documented in the [UI/config trace](docs/rk-v4.6-ui-setting-signal-audit.md).
- This additional package is one Windows Hub Driver release. It does not
  cover the separate RK Web Driver, model-selected custom drivers/firmware,
  every historical utility, or every marketed hardware revision. The official
  download page itself distinguishes those driver paths; the dated
  [official distribution audit](docs/rk-official-driver-distribution-audit.md)
  documents their public support claims and limits.

## Covered in the installed 4.06 snapshot

- All 810 files in the examined installation are represented by path, byte
  size, and SHA-256 in `docs/rk-installed-package-manifest.csv`. On
  2026-10-18, the installed tree was rechecked: 810/810 paths, sizes, and
  hashes matched using `scripts/verify_installed_manifest.py`.
- All 188 named `DevName` profile rows and all 189 installed `KB.ini` files
  are inventoried. The extra `01C7` profile has no `DevName` record and stays
  explicitly unregistered.
- Profile options, key/Fn mapping tuples, section shapes, localization labels,
  resource groups, model-associated assets, and the static initial driver
  family selection are recorded in the JSON and linked CSV audits.
- The profile-family report distinguishes all 188 registered rows routed by
  the checked binary to RKKB or G5 from configuration-only `01C7`, seven
  conditional wireless candidates, and 15 screen-configured profiles. It
  does not promote those static categories into tested model support; see
  `docs/rk-profile-family-protocol-coverage.md`.
- All ordinary and delay imports from the five installed PE files, their
  scanned IAT/thunk references, dynamic API loader candidates, and raw
  system-call byte matches are inventoried.
- A second static pass mapped 51 call/callback routes and one imported-data
  reference among the 62 imports that lacked direct/thunk call references;
  10 import rows still have no recovered invocation path and are classified
  in the per-API audit. A full-image pointer-reference scan adds evidence for
  the two Update.exe ANSI loader imports and eight unins000.exe scrollbar
  fallback imports, but establishes no invocation and classifies none as
  unused. An instruction-level census maps the nine direct updater loader
  helper calls to wide descriptors and records zero exact pointer matches for
  the ANSI descriptors; indirect/computed selection remains unresolved. See
  `docs/rk-remaining-native-api-gap-deep-scan.md`,
  `docs/rk-update-ansi-loader-call-boundary-audit.md`, and
  `docs/rk-remaining-api-reference-scan.csv`.
  The `PostQuitMessage` wrapper path is tied to seven callers.
- All 128 dynamic-loader callsites in the five installed PE snapshots are
  inventoried and statically reviewed across the driver, installer helper,
  updater, and uninstaller. Other resolver callsites outside the focused
  follow-up still have caller-fed values, cached-pointer consumers, external
  callers, or runtime reachability gaps; see
  `docs/rk-dynamic-api-resolution-audit.md`.
- A hash-pinned V4.6 follow-up traces the indirect `RegEnumKeyExW` call into
  child-key name/open handling and a caller-path `RegDeleteKeyExW`/`RegDeleteKeyW`
  helper. This places it in a deletion-related path, but does not prove correct
  recursive traversal, the exact registry path, or runtime reachability; see
  `docs/rk-v4.6-registry-subtree-delete-audit.md`.
- A hash-pinned 4.06 follow-up resolves the main driver's `OLEACC.dll`
  delay-import descriptor, all three export names, and the shared
  `LoadLibraryA`/`GetProcAddress` helper's IAT patch and tail-dispatch path.
  This closes those argument/consumer gaps only; runtime reachability and
  other dynamic API questions remain open. See
  `docs/rk-main-delayload-api-audit.md`.
- A focused follow-up resolves fixed export strings and static cached-pointer
  consumers for the DeviceDriver UxTheme wrappers and Update common-control,
  common-dialog, and property-sheet helpers. The `DrawThemeParentBackground`
  wrapper still has no recovered in-image caller; no runtime branch is
  established. See `docs/rk-dynamic-api-consumer-gap-audit.md`.
- A new 4.06 G5 audit maps all 27 `CDevG5KB` vtable entries and follows the
  `+0x68` GetRealData wrapper into its request-write/response-read helper.
  Six nearby `+0x68` callsites are resolved to a local GDI adapter and
  `USER32!DrawTextW`, not to the G5 GetRealData slot. Their `0x8134`/`0x8135`
  values are Windows text-layout flags. A hash-pinned static checker verifies
  the adapter constructor, vtable slot, import, wrapper ABI, and callsites.
  A follow-up caller scan found no direct call to the G5 wrapper and no
  statically attributable virtual caller; the actual G5 command-`0x88` caller
  remains unresolved. The helper has no direct file sink. This does not
  establish a full read-only S98 firmware export. See
  [`docs/rk-406-cdevg5-vtable-audit.md`](docs/rk-406-cdevg5-vtable-audit.md)
  and its [slot ledger](docs/rk-406-cdevg5-vtable-map.csv),
  [call-resolution ledger](docs/rk-406-vtable-68-resolution.csv),
  and [static checker](scripts/audit_rk406_g5_vcall_resolution.py).
- The documented native paths include HID enumeration, selected
  device-family protocol routines, updater transfer/readback, local
  profile/macro/screen persistence, installer helpers, and uninstaller
  scripts.
- The host update follow-up maps optional `UpdateURL`/`NoUpdate` and `RGBKb`
  selection, manifest and later downloads into an AppData-rooted directory,
  and an optional `Other\<VID>_<PID>\start.exe` process launch. It also
  confirms that the installed snapshot lacks the original setup executable
  and source project. Server contents, update authenticity/installation, and
  the absent helper's behavior remain unresolved; see
  `docs/rk-host-update-install-path-audit.md`.
- The shared settings serializer's keymap, macro, lighting, RGB, and color
  group branches are mapped to G5/3632 commands. Separate RKKB writes for
  key/layer, macro-derived, LED, key-color, matrix, Fn, and music paths are
  also documented. The semaphore-backed Apply worker, the `tc_apply` and
  `tc_restore` main-window controls that signal it, and three device-family
  vtable entries are statically mapped. The control labels, queue flag, and
  worker dispatch are connected in the
  [V4.6 UI-to-worker trace](docs/rk-v4.6-ui-setting-signal-audit.md).
  Profile-row logic selects the RKKB or G5 class for the checked records, but
  the runtime receiver type and data arguments at the worker call remain
  unresolved. A targeted follow-up traces the selected-profile constructor into
  the active-root global; all eight installed S98 rows conditionally select
  G5 and its `+0x3C` Apply target. Other selected-root writes and runtime state
  keep this a conditional path. See
  [`docs/rk-406-active-profile-apply-dispatch-follow-up.md`](docs/rk-406-active-profile-apply-dispatch-follow-up.md)
  and its [hash-pinned verifier](scripts/audit_rk406_active_profile_apply.py).
  G5 screen/GIF/page serializers and their virtual entries are
  also mapped, while the screen worker's concrete target and several payload
  meanings remain open. See
  `docs/rk-settings-apply-worker-audit.md` and
  `docs/rk-setting-serializer-audit.md`.
- A dedicated lighting/RGB report separates command `4` settings, G5/3632
  RGB-table commands `10`/`9`, color-group commands `6`/`2`, and RKKB `02 29`
  and `03 7E` paths. A follow-up confirms dynamic `LedOpt%d` reads, tuple cell
  4's conditional effect on runtime-record `+0x08`, and tuple cells 2–6's UI
  state path. Full tuple semantics, label-to-effect mapping, channel meaning,
  and profile-to-color-group mapping remain unresolved; static packer
  structure is not physical-device validation. See
  `docs/rk-rgb-lighting-color-payload-audit.md` and
  `docs/rk-lighting-profile-record-path-audit.md`.
- A targeted profile trace maps `[OPT] DefBri`, `LightUI`, and `LightHW` into
  the runtime brightness selector, a UI value-display helper, and
  family-specific serializer bytes. All eight installed S98 profiles use
  `DefBri=5` and six-value UI/hardware lists; physical brightness units and
  the visible control's command handler remain unresolved. See the
  [brightness trace](docs/reverse-engineering.md#brightness-profile-ui-and-serializer-path)
  and the [UI-to-handler follow-up](docs/rk-lighting-brightness-ui-handler-audit.md).
- The static Win32 dialog-template parser inventories all dialog resources in
  the examined PEs and their declared controls; selected updater controls are
  cross-referenced to a statically recovered complete updater message map in
  `docs/rk-dialog-resource-audit.md`.
- The updater serial receive worker is traced through its queue, posted
  message `0x401`, and state-dispatch routine. The 3632 response reader's
  frame fields, status route, queue filters, timeout handling, and retry
  behavior are documented; its 20-byte `ReadFile` loop is linked by matching
  object queue offsets to the response consumer as a static producer
  candidate. Same-instance runtime reachability and status-record semantics
  remain unresolved. A UART follow-up corrects little-endian WORD fields to
  transmitted byte order and maps two closed chunk-state cycles, their
  conditional file sinks, and missing range/stream setup. It does not
  establish reachable or complete firmware readback. See
  `docs/rk-3632-response-semantics-audit.md` and
  `docs/rk-uart-firmware-path-semantics-audit.md`.
- The main UI's model-specific LED XML path and generic fallback path are
  statically cross-referenced. A separate label/control/handler crosswalk
  resolves selected paths such as the generated Apply control and language
  selector and the tray-menu Configuration/Exit command origins, while most
  feature widget/command bindings remain open; see
  `docs/rk-ui-control-command-crosswalk.md` and
  `docs/rk-tray-icon-menu-workflow-audit.md`.
- A general-settings follow-up separates profile values and the main Apply
  memory/event edge from host-local `lang.ini`, generic MFC INI/registry, and
  per-device `.dct` persistence. Reset/factory prompt strings are present, but
  no prompt-to-reset-handler edge is recovered. See
  `docs/rk-general-settings-ui-persistence-audit.md`.
- A reset/system-parameter follow-up maps the profile-gated reset virtual call,
  family `+0x38` targets, periodic timeout worker and its `+0x48` family paths.
  It also traces `0x6401` to the localized tray-menu Exit item; its event stops
  the worker and is not a keyboard reset. The separate localized reset prompts
  still have no recovered control-to-handler edge; worker payload semantics
  and runtime execution remain unresolved. See
  `docs/rk-reset-and-system-parameter-path-audit.md`.
- The installed mapping tuple corpus is exhaustively cataloged, with a
  confidence-ranked report separating visual rectangle coordinates from
  candidate action and keycode meanings. The `[KEY]` parser now maps tuple
  cells 1–10 into coordinate arrays and 16-byte action records, with cell 8
  feeding the RKKB 132-slot lookup byte. Four translated layers are also
  traced, but their construction from profile/Fn/UI state and the picker
  commit path remain unresolved. The fixed `04 00` plus `0x780` write is a
  macro-staging path in its recovered caller context, not a proven full
  keymap transfer. See `docs/rk-keymap-ui-path-audit.md` and
  `docs/rk-keymap-translation-audit.md`.
- The macro audit maps the 834-byte `.mck` record, reversible byte rotation,
  raw concatenated `mac.dct` persistence, import/export branches, and three
  family-specific serialization paths. The editor follow-up maps custom
  message handlers, dirty bits, and mouse-hook callsites but finds no proven
  physical-key capture producer or event-row constructor; see
  `docs/rk-macro-format-and-path-audit.md` and
  `docs/rk-macro-capture-path-audit.md`.
- The audio follow-up traces WASAPI loopback capture, 24 visualization bands,
  profile/audio configuration fields, and a distinct RKKB music-data writer.
  The capture-to-writer edge, UI controls, `audio.dct` schema, and equivalent
  G5/3632 output remain unresolved; see
  `docs/rk-audio-reactive-path-audit.md`.
- The screen audit maps G5 screen parameters, a five-byte GIF-parameter
  payload, and the frame/page transfer header, optional additive-complement
  byte, acknowledgements, retries, and cancellation path. The 4.06 screen
  audit's UI reachability and physical compatibility remain unresolved. For
  the separate hash-pinned 4.6 image/GIF path, NewGIF frames reach the static
  worker and G5 writer path, while the generic single-image preview has no
  recovered direct pointer path into that frame list. Screen-parameter schema
  and hardware acceptance remain open; see `docs/rk-screen-gif-payload-audit.md`,
  `docs/rk-screen-image-conversion-path-audit.md`, and
  `docs/rk-v4.6-screen-gif-ui-transport-audit.md`.
- Main-app HID enumeration and USB/HID interface notification filters are
  traced through register-indirect API calls and an RTTI-attributed
  `COemDrvDlg` `WM_DEVICECHANGE` message-map entry; runtime event delivery and
  device-to-profile selection remain unobserved.
- All 26 recovered MFC message-map arrays are decoded into 291 raw entry rows
  with message, signature, ID range, handler, and owner evidence. This is the
  recovered-array inventory, not a claim that every MFC map in the PE or every
  runtime dispatch path has been found; see
  `docs/rk-mfc-message-map-audit.md`.
- A dated snapshot of RK's public storefront navigation records 43 listed
  variants across 33 model tokens and compares them with the installed
  profile names. The resulting candidates are not treated as compatible
  devices; see `docs/rk-public-model-coverage-gaps.md`.

## Not established

- That the 4.06 package contains every RK keyboard model, regional variant,
  receiver, or firmware generation. Other package versions must be added and
  compared separately.
- A complete current or historical catalog of RK products, or an exact
  product-to-driver/software matrix. The storefront snapshot is a dated
  discovery input and does not prove which official driver, firmware family,
  or protocol a model uses.
- A unique one-to-one mapping between each profile code and every physical
  keyboard revision. Several families share identifiers or have conditional
  wireless/companion paths.
- Full call graphs for every native procedure, all indirect/COM/callback
  targets, or the runtime branch taken on a given PC.
  For the 4.06 uninstaller's eight USER32 scrollbar fallback imports, a focused
  recheck rejected the apparent indexed site at `0x0044B2C0` as a decode inside
  a call displacement; no in-image invocation site was recovered. The imports
  remain unresolved. See
  [`docs/rk-unins000-scrollbar-fallback-indexed-candidate.md`](docs/rk-unins000-scrollbar-fallback-indexed-candidate.md).
- Every MFC control label and action, every profile tuple's meaning, all
  packet fields, or the protocol meaning and runtime reachability of the UART
  command/response paths. The 15 updater dispatch slots are separately mapped.
  A focused trace now maps command `0x0419` through `.upf` parsing, mode
  selection, HID discovery, and update-worker dispatch; its downstream HID
  feature-write paths are statically visible. A progress follow-up maps all 14
  `PBM_SETPOS` sites (13 direct IAT calls and one register-indirect call) to
  resource control `0x0413` and traces three chunk-progress formulas; control
  `0x041B` remains without a direct position update. Timer origins, runtime
  selection, and indirect coupling to the UART state machine remain unresolved. See
  [`docs/rk-updater-command-0419-static-path-audit.md`](docs/rk-updater-command-0419-static-path-audit.md).
  See also the [progress-control audit](docs/rk-updater-progress-control-audit.md).
  A focused audit of the updater's `0x0422` “retain dongle pairing” checkbox
  verifies its `BM_GETCHECK` read and normalized store to a zero-initialized
  global, then finds no second direct reference to that flag in the exact PE.
  Its advertised transfer effect is therefore not demonstrated; computed
  aliases and runtime behavior remain unresolved. See
  [`docs/rk-updater-dongle-pairing-option-audit.md`](docs/rk-updater-dongle-pairing-option-audit.md)
  and its [hash-pinned verifier](scripts/audit_rk0422_dongle_pairing_flag.py).
  A conditional UART response-to-file sink is present in states 7 and 11, but
  its file gate is directly initialized to zero, no nonzero direct setter or
  stream-open path was found; the state-3/4/6/7 and state-10/11 subgraphs have
  no direct incoming transition from initialized state 0. Indirect/external
  activation remains unresolved. A full `.text` direct-reference pass also
  found no direct stream-pointer initializer or nonzero setter; both globals
  lie in the zero-filled `.data` tail. Computed aliases and external activation
  remain outside that proof. See
  [`docs/rk-uart-file-sink-reachability-audit.md`](docs/rk-uart-file-sink-reachability-audit.md).
  A separate whole-file reference scan found no encoded static pointer entries
  or UART stream initializer, and identified the only direct stdio opener as
  the updater package parser reading `.upf` input in mode `r`; see the
  [file-open crosswalk](docs/rk-uart-file-open-path-crosswalk.md).
  The updater also has two six-byte feature reads in a post-transfer helper;
  they do not constitute a complete firmware read.
- No complete read-only S98 firmware export is demonstrated across the
  installed 4.06 package and the separately extracted 4.6-labeled package.
  Their `Dev/01AF/Update.exe` and `.upf` files are byte-identical; the changed
  4.6 `DeviceDriver.exe` has separately traced G5 request/read paths that
  contain conditional copy code, and the six V4.6 `HidD_GetFeature` callsites
  use the same handle as their paired `HidD_SetFeature` calls. No hardware
  response was observed, and neither G5 path establishes a firmware file
  export. Whether an undiscovered indirect or model-specific path exists is
  unresolved; see `docs/rk-firmware-readback-audit.md`.

These gaps are intentional status labels, not claims that the missing work is
impossible. New package snapshots and independently supported findings should
extend the evidence without silently converting candidates into confirmed
hardware mappings.
