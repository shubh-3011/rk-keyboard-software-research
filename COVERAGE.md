# Coverage and open work

This file prevents the package snapshot from being mistaken for a universal RK
model or runtime map.

For current blockers and the recommended reverse-engineering order, see the
[full-suite gap matrix](docs/reverse-engineering-gap-matrix-2026-10-19.md).

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
  properties to match known VID/PID pairs to catalog entries. The app itself
  does not open a keyboard interface, read HID reports, or learn current RGB
  color/mode. Separately, the reverse-engineering report records a read-only
  HID inspection of the attached device; it did not write to the keyboard.
  Key and macro edits are local drafts, and lighting writes, hardware
  settings, screen transfer, updates, reset, and firmware operations remain
  unavailable. The native reconstruction is incomplete and is not a full RK
  clone. See the
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
  A focused static pass now hash-checks all six communication-worker modules,
  counts their 78 entry-bundle worker constructions, records the scheduler and
  retry logic, and inventories direct WebHID API call candidates with source
  offsets. This maps a shared browser-to-HID boundary; it does not close every
  model's UI-to-packet path or any browser/OS-native calls. See the
  [worker/WebHID audit](docs/rk-drive-communication-module-audit-2026-10-19.md).
  The lighting crosswalk maps feature gates, UI service calls, effect
  read/apply/readback/rollback, custom-main records, and grouped per-key RGB
  serialization in the hash-pinned entry bundle. It does not establish
  hardware acceptance or model-wide support.
- A second live refresh at `2026-10-18T08:47:15Z` matched all seven saved
  bundle hashes and the derived catalog data. This confirms the dated snapshot
  against the public deployment at that time; it does not confirm hardware
  behavior. See the [live recheck record](docs/rk-drive-live-recheck-2026-10-18.md).

## Official keyboard selector metadata snapshot

- A dated read-only capture of RK's public keyboard download selectors records
  11 product-specific driver results, 118 firmware results across 51 model
  choices, and 83 QMK results across 7 model choices. The S98 selector returns
  eight firmware rows, all Tri mode/RGB with language-specific PIDs. The
  456-row CSV expands platform-specific availability and preserves source API
  URLs and listed artifact URLs. The firmware-image inventory has bytes and
  SHA-256 records for 117/118 unique firmware URLs (the F99 `/0218` URL is a
  404) and maps 349/354 selector rows; four rows remain unassociated. All 38
  QMK JSON definitions and 38 ZIP overlays plus the separate seven HEX images
  have been acquired (83/83 QMK URLs). The HEX files pass Intel HEX structure
  and checksum validation and are compared by address overlap. All eight S98
  updater packages have also received a deeper static audit. This still does
  not close the other updater package call graphs or establish device behavior.
- The selector capture is metadata only, but follow-up package acquisition has
  now covered four Windows product-specific packages: F99 AI RK Setup 3.2.2, R99 RK Driver,
  an RK918-labeled archive whose member is named RK919, and S108 GamingForceZ.
  The F99 Mac DMG now has a static UDIF/APFS-block/Mach-O/ASAR carve pass. The
  carved ASAR is validated and compared member-by-member with Windows: 4,362
  raw hashes match, 185 additional matches are CRLF/LF-only, and one common
  `background.js` member remains different. A focused static comparison ties
  the changed Webpack factory 607 to the same HID wrapper and byte-identical
  worker source on both platforms, while 1,409 coarse changed spans remain
  semantically unattributed. APFS path attribution, app assets, and the
  user-visible behavior of that delta remain unresolved. See the
  [ASAR comparison](docs/rk-f99-asar-cross-platform-diff-2026-10-20.md),
  [member ledger](docs/rk-f99-macos-vs-windows-asar-members-2026-10-20.csv),
  [focused `background.js` comparison](docs/rk-f99-background-js-cross-platform-diff-2026-10-20.md),
  [module identity map](docs/rk-f99-background-js-content-identity-map-2026-10-20.csv),
  [changed-span ledger](docs/rk-f99-background-js-change-blocks-2026-10-20.csv),
  and [comparison scanner](scripts/compare_rk_f99_background_js.py),
  the [package audit](docs/rk-product-specific-software-package-audit-2026-10-19.md),
  and [hash catalog](docs/rk-product-specific-software-package-catalog-2026-10-19.csv).
  A further bounded F99 Windows trace follows two saved renderer actions: DPI
  selection through the HID report write path and firmware query/update through
  the OTA report writer. It records 95 literal renderer IPC calls across 91
  hash-pinned sidecar scripts, but the renderer files are not indexed in the
  pinned ASAR header; their co-shipping with this main bundle is unresolved.
  The trace found no literal renderer IPC channels for lighting or keymap, and
  its DPI/version endpoint evidence is mouse-oriented. See the
  [renderer-to-HID report](docs/rk-f99-windows-ui-ipc-to-hid-trace-2026-10-20.md)
  and [path ledger](docs/rk-f99-windows-ui-to-hid-path-ledger-2026-10-20.csv).
  The selector still does not enumerate retired, regional, or removed records.
  See the [API/catalog audit](docs/rk-official-selector-api-catalog-audit-2026-10-19.md),
  [dated CSV](docs/rk-official-download-selector-catalog-2026-10-19.csv), and
  [snapshot-preserving collector](scripts/capture_rk_public_selector_catalog.py).
  A route-by-route pass resolves all 19 platform rows from the 11 Driver
  records: five package downloads and two Web roots, with seven OS rows that
  have no URL. `drive2.rkgaming.com` is one shared web app for six models;
  `rk.hubx.pro` is a separate RK68 HE route. Their HTML/JS/CSS assets are
  hash-indexed, but UI call graphs and model-to-feature reachability remain
  open. The `drive2` certificate was expired during capture; the `hubx`
  snapshot bytes were initially fetched without TLS validation. See the
  [Driver route audit](docs/rk-product-driver-selector-route-audit-2026-10-20.md),
  its [row coverage](docs/rk-product-driver-selector-coverage-2026-10-20.csv),
  and [asset ledger](docs/rk-product-driver-route-web-asset-ledger-2026-10-20.csv).
  A hash-verified `drive2` call-path follow-up ties the connect button to the
  WebHID chooser/open/listener service and traces its 17 packet-builder calls
  before the page changes routes. The service sends 64-byte chunks through
  `sendReport(0, ...)`; this is static code evidence only, and no HID request
  or report was performed. Its reconnect path also persists hard-coded
  `keyboardInfo` VID/PID values that are not used in the subsequent collection
  match. Packet semantics, the 27 chooser PIDs' model mapping, and the main
  device page's feature graphs remain open. See the
  [connection audit](docs/rk-drive2-webhid-connection-path-audit-2026-10-20.md),
  [offset ledger](docs/rk-drive2-connection-path-evidence-2026-10-20.csv), and
  [scanner](scripts/audit_rk_drive2_connection_path.py).
- A hash-pinned static pass over the separate `rk.hubx.pro` app maps the
  `/setup` connect action through the picker and model gates, and traces one
  `/lighting` action through the V3 controller to `HIDDevice.sendReport`. A
  route-level follow-up also traces selected `/keyboard`, `/macro`,
  `/advanced`, `/performance`, `/features`, `/settings`, and `/devices` paths
  through stores/controllers to source-level report calls. It records two
  catalogued RK68 HE variants and bounded feature paths; rhythm receiver
  behavior, custom-layout device effects, several performance chains, runtime
  behavior, and full revision coverage remain open. See the [call-path report](docs/rk68-he-static-webhid-callpaths-2026-10-20.md),
  [55-row source-offset ledger](docs/rk68-he-static-webhid-callpath-evidence-2026-10-20.csv),
  [route-feature ledger](docs/rk68-he-route-feature-callpaths-2026-10-20.csv),
  and both [setup scanner](scripts/audit_rk68_he_webhid_callpaths.py) and
  [route scanner](scripts/audit_rk68_he_route_feature_callpaths.py).
- The QMK selector reports 83 rows and 83 distinct artifact URLs across seven
  model choices. Its 38 JSON definitions all match a `keyboard.json` embedded
  in the separately listed 38 ZIP source overlays; these are declarative
  layouts/build extensions, not a full QMK checkout or Windows configuration
  app. The 38 ZIPs and 38 JSON files are statically inventoried and hash-pinned;
  seven `.hex` images are separately acquired and structurally validated. See
  the [QMK source audit](docs/rk-qmk-selector-software-audit-2026-10-19.md),
  [HEX comparison](docs/rk-qmk-hex-static-comparison-2026-10-20.md), and
  [firmware selector inventory](docs/rk-firmware-selector-static-inventory-2026-10-19.md).
- A static PE-family pass covers all 117 acquired firmware-selector files and
  114 distinct whole-file hashes; 99 PE hashes reduce to 16 executable-section
  byte profiles. Two profiles match S98 updater code, spanning 80 PE hashes
  (74 and 6), but their model-specific payloads and PIDs differ. The pass also
  records 81 SINO overlays (72 selector-PID matches, five mismatches, and four
  rows without comparable selector PIDs), 4,377 representative API-import
  rows, 6,805 resource leaves, and 506 unvalidated x86 `cmp` candidates. This
  is package-family/metadata work, not per-family call-graph or firmware
  acceptance evidence. The [report](docs/rk-firmware-pe-family-static-audit-2026-10-20.md)
  and its [reproduction scanner](scripts/audit_rk_firmware_pe_families.py)
  distinguish exact findings from linear-sweep candidates.
- A follow-up selected one hash-pinned representative from each of six
  non-S98 native PE families and inventoried eight managed CLR images. Its
  static scans retain 27,082 linear import-call candidates, 1,810 import
  references reached by a bounded entrypoint walk, and 972 unresolved
  indirect transfers. Fourteen reached calls use generic file/device-I/O
  APIs; none is a reached HID, SetupAPI, WinUSB, or serial-specific call. A
  follow-up parses all eight CLR metadata images into 6,074 selected table
  rows, including 1,456 method-body headers, hashes six embedded resources per
  image, and records names and `#US` strings without treating them as live
  calls. A linear IL decoder now covers all 1,456 method bodies (30,774
  instructions), resolves 6,332 call-like references and 12,476 token
  operands, and records zero decode or branch-boundary issues. It identifies
  static extraction of the V0.0.5 helper and `libhidapi`/`libusb` resources to
  a temporary directory, a `Process.Start` path, and WMI USB discovery with
  VID/PID gates. A follow-up verified all 24 parent-to-resource links and
  parsed the three unique embedded payloads (the helper, HIDAPI, and libusb)
  in memory, recording sections, imports, exports, nested resources, and
  strings. The helper declares nine HIDAPI and 21 libusb imports; its
  instruction sweep yielded only unvalidated import-thunk candidates. No
  helper CFG or reachable HID/USB call path is established. These are bounds
  on the selected artifacts and static analysis,
  not proof of runtime behavior or absence from other package components. See
  the [native call-path report](docs/rk-firmware-pe-call-path-static-audit-2026-10-20.md),
  [CLR metadata report](docs/rk-firmware-clr-metadata-static-audit-2026-10-20.md),
  [CLR IL report](docs/rk-firmware-clr-il-static-audit-2026-10-20.md),
  [embedded payload report](docs/rk-embedded-payload-static-audit-2026-10-20.md),
  [six evidence ledgers](docs/rk-firmware-pe-entrypoint-import-reachability-2026-10-20.csv),
  and [hash-pinned scanner](scripts/audit_rk_firmware_pe_call_paths.py).

## Product-specific software package snapshots

- Static package inventories show three different product-specific families:
  the GamingForceZ NSIS application, the R99 Inno Setup `RK Driver`, and the
  F99 AI Electron application with a native `mi-hid` addon. These have
  different plugin/native boundaries and model data. The sample set is not a
  universal protocol map or a full call-graph reconstruction; no package was
  run. The [dated package catalog](docs/rk-product-specific-software-package-catalog-2026-10-19.csv)
  records exact hashes and analysis status.
- The R99 extracted tree's 215-file path/size/SHA-1 inventory is
  [`docs/rk-r99-package-manifest-2026-10-19.csv`](docs/rk-r99-package-manifest-2026-10-19.csv).
- A static PE API pass covers all seven R99 package PE files: 2,559 normal and
  delay import rows, 4,110 direct imported-call/tail-jump candidates, and no
  decoded `sysenter`/`int 0x2e` instructions in the scanned executable
  sections. `RK Driver.exe` imports CH375 helper and HID/SetupAPI APIs; 30
  `CH375DLL.DLL` calls use the same `0x223CDC` IOCTL value. Details and
  row-level ledgers are linked from the
  [R99 API boundary audit](docs/rk-r99-native-api-boundary-audit-2026-10-19.md).
- The F99 ASAR has 4,569 entries and was passed through REA's JavaScript
  application analyzer. Its local Evidence summary reports 3,814 relevant
  files, 2,971 parsed JavaScript files, 2,738,930 AST nodes, 12,483 findings,
  3 parser failures, 2,111 interrupted source analyses, and 75,336 `unknown_id`
  records. `background.js` is 2.84 MB and has `parse_status=partial`; the graph
  is incomplete. The full 298 MB Evidence remains outside the repository. This
  analysis does not establish absence of an Electron/native relationship from
  zero-count summary fields. The F99 macOS pass validates the carved ASAR and
  compares member hashes, but APFS paths and asset ownership remain open; see
  the separate [macOS findings](docs/rk-f99-macos-static-findings-2026-10-20.md)
  and [cross-platform ASAR comparison](docs/rk-f99-asar-cross-platform-diff-2026-10-20.md).
- Focused family traces now map representative paths without claiming full
  control-flow coverage: GamingForceZ lighting/profile resources through the
  shared plugin architecture to the Sonix feature-report wrapper; R99 app
  discovery and sample requests through CH375, plus the archived 2023 driver's
  IOCTL buffer and SetupAPI install paths; and F99's verified-device gate,
  model image selection, generic DPI route, and OTA dispatch. Exact lighting
  value mapping, R99 helper semantics/model gates, F99's remaining UI/native
  edges, and device behavior remain open. Details are in the
  [product-specific package audit](docs/rk-product-specific-software-package-audit-2026-10-19.md).
- A separate static audit covers all eight S98 Tri-mode RGB updater EXEs
  returned by the selector. It records each package hash/PID, compares their
  PE sections, imports, dialog resources, and code-scan candidates. Seven
  builds share section hashes; Thai is a distinct build. The appended `SINO`
  container and its four-byte trailer-key transform are mapped, but the
  post-transform firmware format, complete UI-to-transfer graph, report
  semantics, and device acceptance remain unresolved. The scanner found
  4,848 import rows, 14,291 direct IAT call/tail-jump candidates, 3,523
  register-indirect call/jump candidates, and no decoded direct-syscall
  instruction candidates in two unique code builds. These are bounded static
  scan results, not reachability or whole-suite coverage. See the
  [S98 updater audit](docs/rk-s98-firmware-updater-static-audit-2026-10-19.md)
  and its [reproduction script](scripts/audit_s98_firmware_packages.py).

## Additional official 4.6 Windows Hub Driver snapshot

- A separately downloaded official 4.6 package was extracted statically, not
  installed or run. Its full 1,249-file path/size/SHA-256 inventory and
  provenance are in [`docs/rk-v4.6-package-snapshot.md`](docs/rk-v4.6-package-snapshot.md)
  and [`docs/rk-4.6-package-manifest.csv`](docs/rk-4.6-package-manifest.csv).
- Static setup metadata identifies Inno Setup 5.3.3 Unicode and seven
  languages. A hash-pinned extraction and IFPS disassembly now recover six
  exported callback bodies and reconstruct the installer action descriptor:
  nine callback evidence rows and 1,271 action rows (including 1,249 file
  entries and two `AfterInstall` associations). These establish callback
  bodies and package metadata, not Inno dispatch order or runtime effects.
  The extracted payload still lacks the generated `unins000.exe`/`.dat`.
  See the [4.6 callback recovery](docs/rk-v4.6-inno-installer-callback-recovery-2026-10-20.md),
  [callback ledger](docs/rk-v4.6-installer-callback-evidence-2026-10-20.csv),
  [action ledger](docs/rk-v4.6-installer-action-evidence-2026-10-20.csv), and
  [hash-pinned scanner](scripts/audit_rk46_installer_callbacks.py). Earlier
  [script-recovery](docs/rk-v4.6-inno-script-recovery-audit.md) and
  [overlay recovery](docs/rk-v4.6-inno-overlay-static-recovery-followup.md)
  audits describe the extraction boundary; their failure to expose callbacks
  has been superseded by this focused compiled-bytecode recovery.
- A separate hash-pinned static pass inventories all 135 ordinary import rows
  and 281 decoded calls to the outer installer's IAT thunks. It finds one raw
  `0F 05` byte pair inside a `JMP` displacement and no recognized direct
  syscall instruction in the executable sections. This callsite pass does not
  prove branch reachability or API semantics; the setup callback bodies and
  reconstructed action descriptor are covered in the separate static
  recovery above. Neither pass establishes runtime side effects.
  See the [installer API boundary audit](docs/rk-v4.6-installer-native-api-boundary-audit.md),
  [callsite ledger](docs/rk-v4.6-installer-native-api-call-sites.csv), and
  [hash-pinned scanner](scripts/audit_rk46_installer_native_api.py).
- A package-membership crosscheck records the exact artifacts represented by
  the installed 4.06 tree, extracted 4.6 setup payload, and dated RK Drive
  snapshot, and compares all 17 baseline-only paths plus key profile/resource
  deltas. It confirms these are bounded snapshots, not the full RK release
  universe. See the [package/version boundary audit](docs/rk-package-membership-and-version-boundary-audit-2026-10-19.md).
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
- A static Win32 dialog-resource parse of the hash-verified 4.6 driver and
  bundled updater found 10 driver templates with seven declared controls and
  four updater templates with 34 controls; there were no parse errors. Their
  resource/control rows match the installed 4.06 driver and updater exactly.
  This compares embedded `RT_DIALOG` resources only; runtime-built MFC
  controls and changed handler maps remain outside this comparison. The two
  extra rows in the 4.06 full inventory come from its generated uninstaller,
  which is absent from the extracted 4.6 payload. See the
  [dialog-resource audit](docs/rk-v4.6-dialog-resource-audit.md) and
  [row ledger](docs/rk-v4.6-dialog-resource-controls.csv).
- The installed 4.06 `skins/` directory has a file-by-file metadata census of
  96 assets, including image dimensions, formats, and modes. The full installed
  manifest was rechecked with no mismatches; the recorded 4.6 delta adds two
  Side LED images. A static loader trace confirms GDI+ file-loading paths for
  named backgrounds and control groups, model-art fallback behavior. A profile-art caller checks `Dev\\%04X\\<name>` paths and selects `kbled.png` or attempts `keycfg.png` then falls back to `keyimg.png`. The installed profile directories contain 102 `kbled.png`, 102 `keyimg.png`, and no `keycfg.png`; runtime branch choice and displayed pixels remain unknown. The trace also finds three
  `power_*` paths absent from both package manifests. It found no direct
  `mak.skn` consumer. A package-wide scan of all five installed PEs and the
  520-byte blob found no identifiable format signature or direct consumer;
  indirect/runtime use remains possible. Exact control bindings and the
  format remain unresolved. See the [asset census](docs/rk-skin-asset-metadata-followup.md),
  [loader follow-up](docs/rk-skin-loader-static-followup.md), and
  [package-wide scan](docs/rk-mak-skn-package-scan-followup.md).
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
  A hash-pinned Capstone linear sweep of its `.text` section reports 570,401
  decoded boundaries, 102,205 direct call/branch sites, 18,517 indirect
  call/jump candidates, 10,970 return sites, and 313 undecoded bytes. Because
  linear sweep also decodes embedded data and does not resolve indirect calls,
  it is not a function map or complete CFG. See the
  [linear-sweep report](docs/rk-v4.6-driver-linear-sweep-inventory.md) and
  [reproduction script](scripts/audit_rk46_driver_linear_sweep.py).
  A follow-up checked all eight `0F 05`/`0F 34` byte candidates against
  instruction boundaries and adjacent indexed tables: none is a direct
  syscall/sysenter instruction in this PE. This static result does not cover
  calls made inside Windows or device-driver code. See
  [`docs/rk-v4.6-system-call-byte-audit.md`](docs/rk-v4.6-system-call-byte-audit.md)
  and its [candidate ledger](docs/rk-v4.6-syscall-byte-matches.csv).
  A separate instruction-boundary pass classifies all 18 raw syscall-byte
  candidates across the five installed 4.06 PEs: two are table data and the
  other 16 are parts of ordinary instruction encodings. See the
  [4.06 boundary audit](docs/rk-406-system-call-byte-audit.md).
  The 4.6 selector and RTTI maps now reconcile all 265 configured profile
  codes with no missing, extra, duplicate, or joined-field mismatch: 133 route
  to `CDevRKKB`, 131 to `CDevG5KB`, and M20/Fw=3 (`0208`) to `CDev3632`.
  Physical compatibility remains unvalidated for all 265 rows. The older
  projected map is historical and superseded for M20; see the
  [selector audit](docs/rk-v4.6-profile-selector-audit.md) and
  [RTTI-backed family audit](docs/rk-v4.6-profile-family-rtti-audit.md).
  Separate static follow-ups also map the Side LED
  configuration/UI/report-builder path, but this is still not a full
  function-level reanalysis. Side LED is enabled in profiles `02B4` and
  `0258`; only the first has side-light artwork/localization in this package.
  A ten-entry MFC message map and state-record path into the report builder are
  recovered. Four message-handler paths across five map entries also enqueue
  settings request `2` to the family apply worker, including one inline queue
  insertion. The exact active family and whether these callbacks schedule the
  specific Side LED report builder remain open. The report builder reaches a
  generic HID feature writer, but event meanings, packet fields, model
  compatibility, and runtime behavior remain unresolved.
  See the [Side LED audit](docs/rk-v4.6-side-led-static-audit.md) and its
  [message-map follow-up](docs/rk-v4.6-side-led-message-map-follow-up.md).
  A separate RTTI-backed `CLedDlg` map adds its 15 decoded entries, including
  a 4.6-only timer row, and connects private position-selection messages
  `0x0481`/`0x0482` to host-state mutations and conditional settings request
  `4`. Static family branches include the G5 flag-`0x04` command-6 path, the
  RKKB matrix-information path, and the nested 3632 selector-2 route; active
  family, runtime dispatch and hardware acceptance remain unknown. See the
  [map and selection-worker audit](docs/rk-v4.6-cleddlg-message-map-and-selection-worker-audit.md),
  [row ledger](docs/rk-v4.6-cleddlg-message-map.csv), and
  [decoder](scripts/audit_rk46_cleddlg_message_map.py).
  Other detailed native control-flow reports remain tied to the 4.06 binaries.
- The 4.6-labeled package's `Update.exe`, `InitSetup.dll`, and `uninstall.dll`
  are byte-identical to their installed 4.06 counterparts. The added
  per-import crosswalk verifies all 724 PE import rows against the 4.06 IAT
  ledger and carries forward 29 register-indirect callsites, three direct IAT
  tail jumps, the `_adjust_fdiv` data reference, and two unresolved ANSI loader
  imports. The helper syscall-like byte candidates also match 4.06 exactly;
  none decodes as a direct syscall/sysenter instruction. The generated 4.6
  uninstaller is absent from this extracted package, so its code is not
  covered. See the [helper audit](docs/rk-v4.6-helper-native-api-audit.md),
  [API/callsite ledger](docs/rk-v4.6-helper-api-callsite-crosswalk.csv), and
  [generator](scripts/audit_rk46_helper_api_crosswalk.py).
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
- A focused follow-up closes one screen-dialog child-event-to-worker edge:
  the `CScreenDlg` child HWND at object offset `+0x1408` passes the dialog's
  numeric `+0x114` state into the 512-entry frame snapshot and the already
  traced screen worker. The mapped `EN_CHANGE` control ID `0x107` updates the
  same state; editing alone is not shown to launch the worker. The event
  source's visible label/ID, exact notification, delay units, runtime family,
  and device acceptance remain unknown. See the
  [focused edge audit](docs/rk-v4.6-screen-dialog-worker-edge.md).
- A hash-pinned 4.6 import/callsite pass records candidate direct, thunk,
  relative, and straight-line register-indirect transfers, including HID and
  local macro-file references. A follow-up maps the prior 16 unresolved
  imports to one IAT load each and 31 register-indirect call candidates; the
  reconciled companion ledger adds those sites without changing the raw scan.
  This is static transfer evidence, not CFG reachability or runtime proof. One
  branch-spanning SetupAPI route is also documented outside the conservative
  scan. See the [primary audit](docs/rk-v4.6-native-api-call-path-audit.md),
  [indirect-reference follow-up](docs/rk-v4.6-unresolved-api-reference-audit.md),
  and [reconciled ledger](docs/rk-v4.6-native-api-call-sites-reconciled.csv).
  A focused follow-up traces the 4.6 `PlaySoundW` worker states to embedded
  aliases `MenuCommand` and `MenuPopup`, its stop branch, and five code-level
  state producers; their visible triggers and runtime playback remain
  unresolved.
- A supplemental all-import scan of the installed 4.06 main driver records
  866 same-region register-indirect call candidates across 130 imports; 833
  belong to import rows that already have a direct/thunk route. Each row keeps
  the IAT load and transfer addresses. Linear-sweep decoding and taint tracking
  still require CFG review, and `no_candidate_detected` does not imply unused.
  See the [audit](docs/rk-406-register-indirect-call-audit.md) and
  [candidate CSV](docs/rk-406-register-indirect-call-candidates.csv).
- A cross-version static trace follows HID class discovery through interface
  path retrieval, `CreateFileW`, preparsed-data/capability queries, metadata
  storage, and `CloseHandle` in the installed 4.06 and extracted 4.6 drivers.
  Both use an 80-row pool and a data-controlled access mask. Neither checks
  the `HidD_GetAttributes` return before `HidP_GetCaps`; each image has one
  direct `HidD_FreePreparsedData` call on the `HidP_GetCaps` failure edge,
  while the success path has a static release-gap candidate. Runtime ownership
  and the selector's nonzero case remain unresolved. See the
  [enumeration lifecycle audit](docs/rk-device-enumeration-handle-lifecycle-cross-version.md).
- A new 4.6 API follow-up traces `SendInput` to a gated 50-record UTF-16 text
  lookup and Unicode key-event batches, the added GDI+ property calls to an
  animated-image timer/frame path, and `GetPrivateProfileStringA` to `OPT` /
  `TouchWeb` with an RK Drive URL fallback and selector-`0x12` internal
  action/command dispatch. The reconciled main API report also traces the
  direct `WritePrivateProfileStringW` call at `0x00403643` from the selected
  locale index to a host `lang.ini` write at the intended %LOCALAPPDATA%\RKKB\ path if the package config is selected; runtime write remains unobserved.
  It also traces a shared temp-file
  factory through `GetTempPathW`, `GetTempFileNameW`, and delete-on-close
  `CreateFileW`; toolbar-property-page callers reach MFC serializer
  `0x004A49B9`. Archive mode zero stores state-dependent toolbar/menu data
  and flushes it through the CFile wrapper. The registry is RTTI-identified
  `CMenuHash`; a single-key release closes/removes a value, and a bulk loop
  closes cached handles on a traced application-loop termination branch.
  The registered global destructor only frees map storage. A selected
  replacement-failure path bypasses updating the cached value after closing
  its old handle; stale-value consequences remain conditional and unobserved.
  Exact serialized bytes and runtime cleanup outcomes remain unknown. See the
  [lifecycle report](docs/rk-v4.6-temp-registry-lifecycle.md) and its
  [verifier](scripts/audit_rk46_temp_registry_lifecycle.py). The visible control
  origin, actual browser/device outcome, active text-macro mapping selection, asset ownership,
  write success, and runtime reachability remain open;
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
- A COM/OLE pass resolves the six `CoCreateInstance`/`CoGetClassObject`
  callsites to host Startup-folder shortcut management, WASAPI loopback and
  master-volume paths, Windows file dialogs, and a generic unresolved class-
  factory helper. These are static callsite findings; the helper's concrete
  class and runtime arguments remain open. See
  [`docs/rk-v4.6-com-ole-activation-audit.md`](docs/rk-v4.6-com-ole-activation-audit.md).
- A 4.06 host-integration follow-up traces the AutoRun-associated check event
  to Startup-folder `.lnk` creation/deletion, including Shell Link COM calls,
  executable path, icon path, and `-s` argument. Flag polarity, filename
  resolution, and command-line meaning remain unresolved. See
  [`docs/rk-v406-startup-shortcut-integration-audit.md`](docs/rk-v406-startup-shortcut-integration-audit.md).
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
  A follow-up confirms the conditional `CKeyDlg` message-`0x477` handler can
  queue setting `2`, which reaches the G5 flag-2 command-4 serializer and
  `HidD_SetFeature` path for the mapped G5 profiles. A separate popup trace
  links `0x00435A23` to localized knob-option arrays, but that sender uses
  `lParam=0`, not the command-4 branch's required `2`. The exact `lParam=2`
  sender and visible control remain unresolved. See the
  [knob-to-command-4 audit](docs/rk-v4.6-knob-signal-to-g5-command04-follow-up.md)
  and [popup-origin trace](docs/rk-v4.6-knob-popup-origin-partial-audit.md).
  A follow-up checks the known popup creators and confirms that none of the
  statically traced senders establishes delivery to `CKeyDlg` with `lParam=2`;
  the exact sender and visible control remain unresolved. See the
  [`0x0477` argument-origin audit](docs/rk-v4.6-0x477-lparam2-origin-audit.md).
- A focused 4.6 text-macro trace maps the `ShowTextMacro` profile gate,
  `textmacro.dct` local read/write helpers, and a 50-record fixed-size buffer
  (`0xC8C8` bytes). If startup selects `app/Cfg.ini`, the intended path shape is
  `%LOCALAPPDATA%\RKKB\<four-hex-value>\textmacro.dct`. A follow-up maps the
  `CKeyFunPickDlg` virtual `WM_COMMAND` path, embedded `CPngBtn` sender, state
  `5`, text read/copy, and local save. Its caption descriptor joins `tc_apply`
  (English `Apply`). `CWelcomDlg` selection among ten child HWNDs forwards an
  identifier into conditional old-partition save/new-partition load. Absolute
  `cfg.ini` selection, notification delivery, state-option label, COM text
  getter, other setup callers, and runtime I/O remain unresolved. See
  [`docs/rk-v4.6-textmacro-path-audit.md`](docs/rk-v4.6-textmacro-path-audit.md)
  and its [evidence CSV](docs/rk-v4.6-textmacro-path-evidence.csv), plus the
  [command bridge](docs/rk-v4.6-textmacro-command-bridge.md) and
  [verifier](scripts/audit_rk46_textmacro_command_bridge.py). A new static
  device-trigger trace follows the `CDev3632` and `CDevG5KB` read-worker
  decoders through private message `0x07EB`, the `COemDrvDlg` mapping-cell
  tag `0x0A00005B`, a non-allocating macro lookup, and host `SendInput`. It
  identifies the code path, not the physical key gesture, active profile,
  runtime message delivery, or API success. See the [trigger report](docs/rk-v4.6-textmacro-device-trigger.md), [evidence ledger](docs/rk-v4.6-textmacro-device-trigger.csv), and [verifier](scripts/audit_rk46_textmacro_device_trigger.py). A cleanup helper scans four groups of 132 mapping cells per linked-list node for the same tag/key pair, then clears unmatched records across the full `0x404`-byte span. Three direct-call candidates are found by the executable-section byte-linear sweep; runtime list identity and whether any call actually reclaims a record remain unknown. See the [reclamation report](docs/rk-v4.6-textmacro-record-reclamation.md) and [verifier](scripts/audit_rk46_textmacro_reclamation.py).
- In the same package, `Dev/01AF/Update.exe` and its `.upf` have hashes
  identical to the installed 4.06 updater and update package. The existing
  updater and firmware-readback findings therefore apply byte-for-byte to
  these two files; the `.upf` remains unvalidated and is not a device dump.
  Focused updater follow-ups map the conditional mode-3 HID preflight and
  fallback, including fixed `0603:1021` and `0603:1020` selectors, and trace
  the successful `1021` status response through a secondary worker to a
  conditional `1020` section-transfer path. The `.upf` has a malformed
  declared A-section length; a new static parser trace also finds a signed
  allocation/loop boundary anomaly for A and a one-byte overrun in B's
  four-byte transform loop if that sample reaches it. Runtime branch
  predicates, allocator behavior, and device responses remain unknown. A
  potential six-byte buffer versus advertised feature-length
  mismatch is recorded as static risk only. See the
  [preflight audit](docs/rk-v4.6-update-mode3-hid-preflight-audit.md) and
  [status-to-transfer follow-up](docs/rk-v4.6-mode3-status-to-transfer-worker-followup.md),
  plus the [section-transform and length-boundary audit](docs/rk-upf-section-transform-and-length-boundary-audit.md).
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
  map remains incomplete. A focused command-5 trace proves that the 200-byte
  write source is the same output buffer passed to the G5 key/macro builder,
  while leaving the output structure and payload meaning unresolved; see the
  [command-5 source audit](docs/rk-v4.6-cdevg5-command05-payload-source-audit.md).
  A focused follow-up reclassifies G5 vtable `+0x20`
  as an inferred stored-path/handle availability probe: it delegates to a
  child object's matching slot or checks an object string with `CreateFileW`
  and an object handle with `HidD_GetAttributes`. The stored path meaning and
  runtime reachability remain unresolved; the method was not invoked. A
  targeted trace maps `+0x34` command `0x82` and `+0x70` command `0x88` to
  conditional response-copy code. A stack audit of all six `HidD_GetFeature`
  calls confirms each uses the same handle as its paired `HidD_SetFeature`;
  `+0x2DC` is a separate report byte. No response was observed from those G5
  methods. No caller is attributable to G5 `+0x70`, and its firmware
  meaning/range remain unresolved. See
  [`docs/rk-v4.6-hid-getfeature-argument-audit.md`](docs/rk-v4.6-hid-getfeature-argument-audit.md).
  A focused caller audit screens signature-compatible `+0x70` sites against
  same-receiver larger-interface slots and point-output use; none is
  attributable to G5. Vtable aliases and other dispatch encodings remain
  unexcluded. An expanded reference scan adds three generic `+0x70` tail-call
  relays; none is tied to a G5 object, and caller length, downstream consumer,
  firmware range, and persistence remain unknown. See the
  [`+0x70` caller audit](docs/rk-v4.6-cdevg5-realdata-caller-audit.md) and
  [command-`0x88` callsite completeness follow-up](docs/rk-v4.6-g5-command88-callsite-completeness-follow-up.md).
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
  2026-10-19, `scripts/verify_installed_manifest.py` confirmed 810/810 paths,
  sizes, and hashes, with no missing/extra paths, mismatches, or unsafe
  manifest rows. An independent file classification also matched all 14
  resource-group counts and byte totals.
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
- Follow-up revalidations reconcile the no-direct-call import rows for the
  DeviceDriver, Update, InitSetup, and uninstall binaries. The DeviceDriver
  total is 80 register-indirect import calls plus two IAT tail-jump wrappers;
  three missed call instructions are listed with the hash-pinned 32-row
  evidence table. The installer helper's five rows resolve to four
  register-indirect APIs and one imported-data read. The updater's 12 rows
  resolve to seven register-indirect APIs, three tail-jump wrappers, and two
  unresolved ANSI loader imports. Runtime execution remains unobserved. See
  `docs/rk-406-native-api-gap-revalidation-follow-up.md`,
  `docs/rk-installer-helper-no-direct-call-import-followup.md`, and
  `docs/rk-updater-native-import-gap-reconciliation.md`.
- A hash-pinned 4.06 uninstaller follow-up resolves `CreateNamedPipeW`,
  `SetNamedPipeHandleState`, and `TransactNamedPipe` to a message-framed
  `InnoSetup64BitHelper` subprocess channel. It hash-identifies the embedded
  AMD64 and IA-64 helper PE resources and maps the AMD64 ACL and type-library
  handlers from their static code. Runtime execution remains unverified; the
  parent/helper operation-2 reply-field mismatch is documented. See
  [`docs/rk-unins000-named-pipe-helper-audit.md`](docs/rk-unins000-named-pipe-helper-audit.md).
- A second static pass mapped 51 call/callback routes and one imported-data
  reference among the 62 imports that lacked direct/thunk call references;
  10 import rows still have no recovered invocation path and are classified
  in the per-API audit. A full-image pointer-reference scan adds evidence for
  the two Update.exe ANSI loader imports and eight unins000.exe scrollbar
  fallback imports, but establishes no invocation and classifies none as
  unused. An instruction-level census maps the nine direct updater loader
  helper calls to wide descriptors and records zero exact pointer matches for
  the ANSI descriptors; indirect/computed selection remains unresolved. A
  follow-up also checks relative calls/jumps and RVA encodings across all ten
  rows, finding no new consumer; each remains unresolved dynamic/runtime. See
  `docs/rk-remaining-native-api-gap-deep-scan.md`,
  `docs/rk-update-ansi-loader-call-boundary-audit.md`, and
  `docs/rk-unins000-scrollbar-fallback-import-thunk-audit.md`,
  `docs/rk-unresolved-native-api-relative-reference-followup.md`, and
  `docs/rk-remaining-api-reference-scan.csv`.
  Independent audits rechecked the installed ANSI-loader and uninstaller
  images: all nine updater resolver calls still pass wide descriptors, and
  each of the eight uninstaller fallback globals appears only in two resolver
  stores, with no consumer recovered.
  The `PostQuitMessage` wrapper path is tied to seven callers.
  A focused follow-up traces the five indirect `GetProfileIntW` sites in the
  4.06 driver to exact `windows` drag/scroll keys, defaults, global stores,
  rectangle/tick consumers, and recovered vtable targets. This deepens the
  already-mapped API path; it does not reduce the ten unresolved import rows
  or establish runtime profile values/UI effects. See
  [`docs/rk-device-driver-getprofileintw-callpath.md`](docs/rk-device-driver-getprofileintw-callpath.md).
- All 128 dynamic-loader callsites in the five installed PE snapshots are
  inventoried and statically reviewed across the driver, installer helper,
  updater, and uninstaller. Other resolver callsites outside the focused
  follow-up still have caller-fed values, cached-pointer consumers, external
  callers, or runtime reachability gaps; see
  `docs/rk-dynamic-api-resolution-audit.md`.
- A hash-pinned V4.6 follow-up traces the indirect `RegEnumKeyExW` call into
  child-key name/open handling and a caller-path `RegDeleteKeyExW`/`RegDeleteKeyW`
  helper. A later exact-image decode corrects the earlier non-recursion
  conclusion: `0x004ACEF8` calls itself at `0x004ACF7A`, recursively processes
  enumerated children, then deletes the parent. The concrete registry root/path,
  UI route, and runtime reachability remain unresolved; see the
  [original audit](docs/rk-v4.6-registry-subtree-delete-audit.md),
  [correction](docs/rk-v4.6-registry-recursive-delete-followup-2026-10-20.md),
  and [40-edge ledger](docs/rk-v4.6-registry-recursive-delete-edge-ledger-2026-10-20.csv).
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
- A 4.06 language-loader follow-up traces `LoadLibraryW` into generated
  locale-satellite DLL names, user/system UI-language candidates, the
  `ntdll` resource-language fallback, and a special `LOC` candidate. The
  higher-level dispatcher, chosen locale, and successful module load remain
  unresolved. See
  [`docs/rk-v406-language-satellite-loader-api-followup.md`](docs/rk-v406-language-satellite-loader-api-followup.md).
- A new 4.06 G5 audit maps all 27 `CDevG5KB` vtable entries and follows the
  `+0x68` GetRealData wrapper into its request-write/response-read helper.
  Six nearby `+0x68` callsites are resolved to a local GDI adapter and
  `USER32!DrawTextW`, not to the G5 GetRealData slot. Their `0x8134`/`0x8135`
  values are Windows text-layout flags. A hash-pinned static checker verifies
  the adapter constructor, vtable slot, import, wrapper ABI, and callsites.
  A follow-up caller scan found no direct call to the G5 wrapper and no
  statically attributable virtual caller; the actual G5 command-`0x88` caller
  remains unresolved. A new holder trace shows one concrete G5 object reaching
  global `0x0062B380`; the decoded calls through that holder use `+0x14` and
  `+0x28`, not `+0x68`. This narrows one alias path but does not exclude other
  aliases, callbacks, or dispatch forms. Five additional superficially
  compatible `+0x68` calls are traced through rectangle producers and geometry
  consumers; they support layout-helper interpretations, while the child
  receiver's concrete type remains unknown. Seventy-eight register-mediated
  calls resolve through constructor-established local vptrs and slots to
  `USER32!DrawTextW`; five more resolve on listed caller/paint-handler paths.
  Together with seven earlier resolutions, this classifies all 90 rows of the
  bounded pattern census. Alternate callers/runtime receivers of those five
  forwarded sites remain unproved. The 2026-10-22 correction retracts the prior
  overwritten-receiver and opaque-GDI+ claims: normalizing argument pushes and
  cleanup shows six additional calls use the local text adapter. The expanded
  54-site checker now replays ESP changes in each call setup. These slices do
  not exhaust all `+0x68` calls. The helper has no direct file sink. This does not
  establish a full read-only S98 firmware export. See
  [`docs/rk-406-cdevg5-vtable-audit.md`](docs/rk-406-cdevg5-vtable-audit.md)
  and its [slot ledger](docs/rk-406-cdevg5-vtable-map.csv),
  [call-resolution ledger](docs/rk-406-vtable-68-resolution.csv),
  [candidate census](docs/rk-406-vcall-candidate-census.csv),
  [static checker](scripts/audit_rk406_g5_vcall_resolution.py), and
  [census scanner](scripts/audit_rk406_vcall_candidate_census.py),
  [stack-alias correction](docs/rk-406-stack-alias-corrections.md),
  [forwarded-receiver report](docs/rk-406-forwarded-text-receivers.md),
  [caller-path checker](scripts/audit_rk406_forwarded_text_receivers.py), and
  [active-object caller-scope follow-up](docs/rk-406-cdevg5-active-object-caller-scope.md).
- A separate 4.6 G5 command-`0x88` trace proves a request write followed by a
  conditional feature read and chunk copies into caller-owned memory. The
  77-site virtual-call scan and three generic tail relays do not attribute a
  caller or consumer; no full image range or file sink is established, and
  the response meaning remains unknown. See
  [the command-`0x88` response/sink audit](docs/rk-v4.6-g5-command-0x88-response-sink-audit.md).
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
  state path. Cells 2, 3, 5, and 6 also gate specific child-object offsets
  through `CWnd::ShowWindow`; control IDs and labels remain unresolved. Full
  tuple semantics, label-to-effect mapping, channel meaning,
  and profile-to-color-group mapping remain unresolved; static packer
  structure is not physical-device validation. See
  `docs/rk-rgb-lighting-color-payload-audit.md` and
  `docs/rk-lighting-profile-record-path-audit.md`.
- A targeted profile trace maps `[OPT] DefBri`, `LightUI`, and `LightHW` into
  the runtime brightness selector, a UI value-display helper, and
  family-specific serializer bytes. All eight installed S98 profiles use
  `DefBri=5` and six-value UI/hardware lists. A focused callsite trace resolves
  the `tc_adv_str1` draw call to `USER32!DrawTextW` and `0x8134` as its layout
  flags. A recovered RTTI-backed `CLedDlg` message map identifies that
  paint handler and its `0x0800`/`0x0801` handlers. Four and five literal
  `PostMessageW` sender sites are recovered for those messages, respectively.
  One LightUI-based construction path stores selector `0x95` in the `+0x9E0`
  field of `CLedDlg+0x1A6C`, constructed as RTTI-identified `CPngSliderBar`.
  Its recovered MFC map binds `0x0800`/`0x0801` to the matching sender pair,
  and the parent `CLedDlg` map has corresponding handlers. Runtime dispatch,
  visible label/meaning, and widget-to-writer association remain unresolved.
  A full-code reference census
  finds `LightUI` writes only in the profile loader. A separate record census
  traces `DefBri` into runtime `+0x04` during initialization; the selected-row
  helper and five direct callers do not write that field. The `0x0800` parent
  handler can conditionally signal worker mask `0x02` and save eligible
  `0x3E74`-byte objects to `pro.dct`, including current brightness bytes; its
  observed save-loop mutation is selected-row `+0x213C`, not brightness
  `+0x04`. Recovered family serializers can conditionally consume the existing
  value through `LightHW`, but the runtime receiver and UI-to-value-writer edge
  remain unresolved. Physical brightness
  units and the widget-to-writer path remain unresolved. See the
  [brightness trace](docs/reverse-engineering.md#brightness-profile-ui-and-serializer-path)
  and the [UI-to-handler follow-up](docs/rk-lighting-brightness-ui-handler-audit.md),
  [field-boundary follow-up](docs/rk-406-brightness-handler-field-boundary.md),
  and [selector-message sender trace](docs/rk-led-selector-message-sender-followup.md).
- A new 4.06 LED-selection follow-up maps a candidate `WM_LBUTTONDOWN`
  producer posting private message `0x0594` to a `CLedDlg` selection handler,
  selected-row state, and the Apply worker. A follow-up confirms the handler
  ignores posted `wParam`/`lParam`, queries the dynamically created
  `CTreeCtrlExRk` child (control ID `0x0105`), matches the selected `HTREEITEM`,
  and stores its generated-list ordinal. The localized choices are rows in one
  tree control, so the posted ID is not a per-label control ID. The route
  conditionally reaches the G5 command-`4` serializer for mapped S98 profile
  rows. The selected ordinal indexes profile `LedOpt` data, but its
  option-to-device-effect meaning, runtime delivery, active object, and
  hardware effect remain unresolved; see
  [`docs/rk-406-led-selection-ui-to-worker-followup.md`](docs/rk-406-led-selection-ui-to-worker-followup.md) and
  [`docs/rk-406-led-0594-parameter-and-generated-row-audit.md`](docs/rk-406-led-0594-parameter-and-generated-row-audit.md) and the
  [source-control/tree-row follow-up](docs/rk-406-led-0594-tree-control-row-token-followup.md).
- A separate 4.6 trace closes the G5 profile-default and serializer path:
  `LightUI` display values, 24 `LedOpt` profile rows, `DefBri` defaults, and
  `LightHW` output translation feed active per-mode state and dialog rendering.
  A 4.6 private-message `0x0800` handler now traces selected-row updates into
  the brightness-index byte consumed by the G5 packer, conditionally queues
  Apply mask `0x02`, and persists state. Profile `020F` demonstrates distinct
  UI values and output bytes. The visible child control that sends the message,
  active live-device target, and firmware acceptance remain unresolved. See
  [`docs/rk-v4.6-brightness-profile-to-writer-follow-up.md`](docs/rk-v4.6-brightness-profile-to-writer-follow-up.md).
- A focused `CLedDlg` follow-up resolves private messages `0x0481` and
  `0x0482` to two posted selection notifications, their per-position mapping
  record effects, and Apply signal mode `4`. A follow-up traces 132 position
  values into the active profile color-group table and its conditional RKKB,
  G5, or 3632 serializer paths. The child control identity, visible value
  semantics, active runtime receiver, and device effect remain unresolved.
  See the [key-position message trace](docs/rk-led-key-position-message-followup.md)
  and [serializer follow-up](docs/rk-key-position-to-color-serializer-followup.md).
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
- After explicit authorization, the live `258A:0150` HID collections were
  opened with read-only handles for descriptor inspection. A follow-up parses
  input/output/feature button and value capability arrays, documenting report
  IDs, usage ranges, and field widths without reading an input report or
  issuing an output or feature write. The complete inventory covers ten paths
  (seven opened, three access-denied). The 19-field `FF02:0002` descriptor and
  three feature layouts still do not identify protocol commands, current
  settings, or the physical keyboard model. See
  `docs/rk-firmware-readback-audit.md` and
  `scripts/probe_rk_hid_capabilities.ps1`.
- The main UI's model-specific LED XML path and generic fallback path are
  statically cross-referenced. For the pinned 4.06 driver, the 24-label
  builder selects `tc_eft*` when `Fw` is nonzero, otherwise `tc_led_mode*`
  when `RGBKb` is nonzero, otherwise `tc_led*`; `ShowSleepTime` is a separate
  option. `LedMask` defaults to zero and set bits skip the candidate-control
  construction path. Each locale's generated 4,536-row candidate crosswalk
  covers all 189 installed profiles and distinguishes mask-filtered
  candidates from labels absent in the selected dictionary. It does not
  establish widget visibility, event handling, or a command mapping. A static
  join covers 22,680 locale/profile/slot rows across the five installed
  dictionaries (`en`, `Japanese`, `Korean`, `sc`, `tw`): 18,825 carry
  same-numbered six-cell `LedOptN` tuples and 3,855 lack that key. Tuple-cell
  and firmware-effect meanings remain unresolved. See
  `docs/rk-led-control-candidates-4.06.md` and
  `docs/rk-led-control-candidates-4.06-en.csv`, plus the
  [label/profile tuple report](docs/rk-406-led-label-profile-tuple-crosswalk.md)
  and [all-locales generated crosswalk](docs/rk-406-led-label-profile-tuple-crosswalk-4.06-all-locales.csv).
  A separate
  label/control/handler crosswalk
  resolves selected paths such as the generated Apply control and language
  selector and the tray-menu Configuration/Exit command origins. The tray
  language menu's `0x6A00`–`0x6A06` IDs are statically traced to Win32
  `WM_COMMAND` delivery to the `COemDrvDlg` owner, but no overlapping range or
  language handler appears in the recovered MFC maps and no edge to the locale
  loader/persistence path was found. Most feature widget/command bindings
  remain open; see
  `docs/rk-ui-control-command-crosswalk.md` and
  `docs/rk-tray-icon-menu-workflow-audit.md` and
  `docs/rk-tray-language-menu-static-audit.md`.
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
  candidate action and keycode meanings. The `[KEY]` parser maps tuple cells
  1–10 into coordinate arrays and 16-byte action records; cell 8 feeds the
  RKKB 132-slot lookup byte. The profile-loaded `Fw` option selects the
  special `FUN_0041D7E0` updater: narrow type-2 `FA`/`FB` cases can restore
  profile `[KEY]`/`[FN1]`/`[FN2]` rows or propagate an incoming record across
  layers 0-2, while setting the dirty-layer mask. The ordinary updater and
  picker modal result commit to the selected map layer, and the worker passes
  that map to the RKKB four-layer translator. A layer-switch helper
  conditionally fills unmatched macro-tagged
  rows from the corresponding `[KEY]`, `[FN1]`, `[FN2]`, or `[TAP]` profile
  row. Full default initialization of all layers and complete tap behavior
  remain unresolved. The fixed `04 00` plus `0x780` write is macro staging in its
  recovered caller context, not a proven full keymap transfer. See
  `docs/rk-keymap-ui-path-audit.md` and
  `docs/rk-keymap-translation-audit.md`.
- The macro audit maps the 834-byte `.mck` record, reversible byte rotation,
  raw concatenated `mac.dct` persistence, import/export branches, and three
  family-specific serialization paths. The editor follow-up ties four custom
  messages to tree-control mouse/Delete interactions and proves that the row
  builder reconstructs rows from editor tree/list state. A physical-input to
  recorder path remains unproven; see
  `docs/rk-macro-format-and-path-audit.md` and
  `docs/rk-macro-capture-path-audit.md`.
- The audio follow-up traces WASAPI loopback capture, 24 visualization bands,
  profile/audio configuration fields, a separate `Music_Theard` device worker,
  its record layout, and `+0x40` dispatches to RKKB, G5, and nested 3632 output
  methods. Static evidence still does not connect loopback samples to those
  worker buffers. The UI follow-up maps 20 audio labels and the inferred `0x1E`
  page-state copy into capture-worker globals, then traces page entry/exit and
  default-endpoint-change restart paths. Exact control bindings, `audio.dct`
  schema, and G5/3632 payload meanings remain unresolved. See
  `docs/rk-audio-reactive-path-audit.md` and
  `docs/rk-audio-ui-control-followup.md`.
- The screen audit maps G5 screen parameters, a five-byte GIF-parameter
  payload, and the frame/page transfer header, optional additive-complement
  byte, acknowledgements, retries, and cancellation path. The hash-pinned 4.06
  UI trace identifies NewPNG/NewGIF as save-as dialogs (`bOpenFileDialog=0`),
  not input-file pickers: NewPNG requests index zero through a helper passed
  `CScreenDlg+0xE0`, which reads the same list head at `+0xF4` that NewGIF
  traverses directly. The list wrapper is based at `+0xE4` (count/head/tail at
  `+0xEC/+0xF4/+0xF8`); cache regeneration conditionally rebuilds this same
  list when its count is `0x11`. A focused follow-up maps `CScreenDlg` message
  `0x0477` to two branches: value zero creates a GDI+ bitmap object and value
  one opens an image picker; both insert into the same list and call the
  count-gated rebuild helper, then invalidate child views. A follow-up closes the `CScreenDlg` sender path: the
  screen's two-row menu stores values `0` and `1`, and its
  `WM_MOUSEMOVE`/`WM_LBUTTONUP` handlers select and submit a row. The English
  labels resolve through locale keys `tc_screen14` (“New”) and
  `tc_screen15` (“Import”). The value-zero bitmap dimensions load from the
  profile's `[OPT] siScreen` pair; the 4.06 catalog contains 15 such values
  across four dimension pairs, with S98 entries using `320,172`. Runtime
  dimensions were not observed. Both `0x0477` menu branches insert into the
  same list later snapshotted by transfer, but successful conversion of the
  bitmap/path objects remains unresolved; the profile cache trigger and
  source-file enumeration remain unresolved. The transfer control `tc_screen12` is now bound to its
  generated child and click handler; Chinese, Russian, and Korean labels
  clarify that it saves to the keyboard. The handler applies an unresolved
  global/device-vtable gate, then copies up to 512 F4 items to a modal object;
  its `WM_INITDIALOG` starts the frame worker, whose `+0x4C` and `+0x50` calls
  resolve to G5 page and GIF writers when the active object uses the recovered
  G5 vtable. The false gate branch shows the localized USB-only warning. The
  gate's meaning, runtime device selection, and physical acceptance remain
  unknown. For the separate hash-pinned 4.6 image/GIF
  path, NewGIF frames reach the static worker and G5 writer path, while the
  generic single-image preview has no recovered direct pointer path into that
  frame list. Screen-parameter schema and hardware acceptance remain open; see
  `docs/rk-screen-gif-payload-audit.md`,
  `docs/rk-screen-image-conversion-path-audit.md`,
  `docs/rk-406-screen-ui-to-worker-modal-follow-up.md`, and
  `docs/rk-v4.6-screen-gif-ui-transport-audit.md`.
- Main-app HID enumeration and USB/HID interface notification filters are
  traced through register-indirect API calls and an RTTI-attributed
  `COemDrvDlg` `WM_DEVICECHANGE` message-map entry; runtime event delivery and
  device-to-profile selection remain unobserved.
- All 27 recovered MFC message-map arrays are decoded into 305 raw entry rows
  with message, signature, ID range, handler, and owner evidence. This is the
  recovered-array inventory, not a claim that every MFC map in the PE or every
  runtime dispatch path has been found; see
  `docs/rk-mfc-message-map-audit.md`.
- The hash-pinned 4.6 `DeviceDriver.exe` scan identifies 145 structurally
  validated accessor/table candidates and 1,214 entry rows; 144 candidates
  have RTTI/vtable association evidence and one candidate's owner is
  unresolved. The inventory includes statically linked MFC framework maps and
  does not prove runtime dispatch or complete map coverage; see
  `docs/rk-v4.6-mfc-message-map-inventory.md`.
- A hash-pinned root-seeded CFG pass for that 4.6 image starts from its PE
  entrypoint, 1,033 unique MFC handlers, and proven entries from three device
  family vtables (`CDevG5KB`, `CDevRKKB`, and RTTI-identified `CDev3632`). The
  77 vtable rows reduce to 52 unique executable targets. The current pass
  records 3,450 root candidates, 31,639 basic blocks, 13,677 unique direct-call
  edges, 3,030 unique exact IAT call sites, and 73 IAT tail-jump sites. A
  follow-up resolves all four indirect calls in the `WM_DEVICECHANGE` handler:
  two dispatch to a conditionally selected logger and two call `SetTimer`,
  linking HID arrival/removal notifications to a delayed rescan. A manual
  branch-aware review also resolves the two register-indirect
  `SetupDiGetDeviceInterfaceDetailW` calls, including their arguments and
  detail-buffer handoff to `CreateFileW`. The raw graph ledger records 3,568
  indirect-call contexts (3,564 distinct sites); six reviewed transfers leave
  3,562 contexts (3,558 sites) unresolved. The generated CSV conservatively
  retains those two SetupAPI calls as unresolved because its register analysis
  does not propagate the branch-spanning definition.
  The graph also leaves 123 indirect jumps, 147 possible tail transfers, and
  66.20% of raw `.text` outside the selected paths. It visits 582,534 decoded
  instruction bytes (33.80% of raw `.text`); the full function/CFG gap remains
  open. See
  `docs/rk-v4.6-rooted-cfg-callgraph-audit.md`.
- A focused 4.6 API trace follows the timer/device-change rescan into
  `SetupDiGetClassDevsW`, interface enumeration, conditional `CreateFileW`,
  HID attribute/capability queries, object construction, and cleanup. This
  statically establishes an enumeration path but does not identify a physical
  S98; the queried attributes are not visibly used as a VID/PID filter in this
  helper. Follow-ups trace the populated 80-row table into two immediate
  consumers that compare profile-row VID/PID and HID usage/report-length fields
  before opening an eligible row, then link those arguments to the selector
  table and family routes (`Fw=0` → `CDevRKKB`, `Fw=3` → `CDev3632`, other
  nonzero values → `CDevG5KB`). The software profile-to-driver bridge is
  resolved for this package; physical model/revision compatibility remains
  unverified. See
  [`docs/rk-v4.6-hid-interface-enumeration-rescan-audit.md`](docs/rk-v4.6-hid-interface-enumeration-rescan-audit.md) and
  [`docs/rk-v4.6-hid-record-to-interface-eligibility-audit.md`](docs/rk-v4.6-hid-record-to-interface-eligibility-audit.md) and
  [`docs/rk-v4.6-hid-profile-caller-bridge-audit.md`](docs/rk-v4.6-hid-profile-caller-bridge-audit.md).
- A separate V4.6 trace follows literal private message `0x0477` from both
  shared popup click handlers into the RTTI-attributed page maps; the screen
  dialog map's `CScreenDlg` owner is now confirmed statically. The page-level
  action for every selection remains incomplete; see
  `docs/rk-v4.6-private-message-0477-popup-fanout.md`.
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
  command/response paths. All 15 updater dispatch slots are mapped; state 0
  and values above 15 take the handler epilogue instead of a table slot. See
  the [UART state map](docs/rk-updater-uart-state-machine.md).
  A focused trace now maps command `0x0419` through `.upf` parsing, mode
  selection, HID discovery, and update-worker dispatch; its downstream HID
  feature-write paths are statically visible. A progress follow-up maps all 14
  `PBM_SETPOS` sites (13 direct IAT calls and one register-indirect call) to
  resource control `0x0413` and traces three chunk-progress formulas; control
  `0x041B` remains without a direct position update. A follow-up finds no
  direct `WM_TIMER` producer for updater IDs 2, 3, or 4 in the inspected posting
  and timer callsites; dynamic window-procedure forwarding and callback virtual
  targets remain unresolved. Runtime selection and indirect coupling to the UART
  state machine also remain unresolved. See the
  [timer producer follow-up](docs/rk-updater-low-timer-producer-followup.md) and
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
  [file-open crosswalk](docs/rk-uart-file-open-path-crosswalk.md). A full
  direct-call census adds all parser cleanup sites and separates the generic
  `CreateFileW` delete-on-close path from the UART response sink; computed
  callers and file-gate activation remain unresolved. See the
  [call-graph reconciliation](docs/rk-uart-file-api-callgraph-reconciliation.md).
  The updater also has two six-byte feature reads in a post-transfer helper;
  they do not constitute a complete firmware read.
- No complete read-only S98 firmware export is demonstrated across the
  installed 4.06 package and the separately extracted 4.6-labeled package.
  Their `Dev/01AF/Update.exe` and `.upf` files are byte-identical; the changed
  4.6 `DeviceDriver.exe` has separately traced G5 request/read paths that
  contain conditional copy code, and the six V4.6 `HidD_GetFeature` callsites
  use the same handle as their paired `HidD_SetFeature` calls. The expanded
  static caller scan found no attributable G5 `+0x70` callsite or complete
  output-buffer-to-file path; generic tail-call relays remain unresolved.
  Neither report establishes a firmware file export. A live HID open mapped
  seven collections on the attached
  `258A:0150` device; the shared VID/PID appears on 46 registry profiles, so
  this still does not identify the device as an S98. Its accessible
  `FF02:0002` collection with 20-byte input/output reports matches the
  descriptor half of the extracted 4.6 `Fw=3` selector, but the sole direct
  `Fw=3` M20 row is `258A:0208`; no runtime profile selection is established.
  The live consumer collection also satisfies the generic consumer descriptor
  branch in the installed 4.06 selector, but PID `0150` has no direct profile
  row. The special wireless route statically loads profile `OPT/Psd` bytes and
  compares them with a six-byte device-helper response. The query helper
  submits a 20-byte packet with `WriteFile` and reads a 20-byte response with
  `ReadFile`; this active transaction was not executed, so the attached
  device's runtime profile match remains unresolved. See
  `docs/rk-wireless-profile-psd-static-dataflow-audit.md` and
  `docs/rk-live-hid-selector-crosscheck-2026-10-19.md`. Three direct
  `HidD_GetFeature` requests returned two short reports (6 and 8 bytes); the
  descriptor-declared 1032-byte feature read failed twice with Win32 error 31.
  Across all recorded calls, the same short bytes were returned ten times per
  report ID, with the first returned byte `06` for requested IDs `05` and
  `0A`; response semantics remain unresolved. No output report or `HidD_SetFeature`
  payload was sent. A cached BLE follow-up found
  three disconnected `RK-S98RGB` nodes
  in separate PnP containers from the USB device; HID characteristic access
  was denied, and no GATT values were read or written. See
  `docs/rk-firmware-readback-audit.md`. The updater's temporary
  `AFX`/delete-on-close serializer also has no direct
  UART/HID receive caller. Whether an
  undiscovered indirect or model-specific firmware export exists is
  unresolved; see `docs/rk-firmware-readback-audit.md`. A separate static
  audit enumerates the identified 4.06/4.6 `HidD_GetFeature` calls and their
  preceding feature-request flows, including updater indirect calls, then
  checks traced response buffers for firmware-file sinks. It finds no
  complete export in those paths but leaves unresolved callers and indirect
  consumers open; see
  [`docs/rk-hid-read-request-and-firmware-sink-audit.md`](docs/rk-hid-read-request-and-firmware-sink-audit.md).

These gaps are intentional status labels, not claims that the missing work is
impossible. New package snapshots and independently supported findings should
extend the evidence without silently converting candidates into confirmed
hardware mappings.
