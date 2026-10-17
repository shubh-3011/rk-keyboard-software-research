# Coverage and open work

This file prevents the package snapshot from being mistaken for a universal RK
model or runtime map.

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
- All ordinary and delay imports from the five installed PE files, their
  scanned IAT/thunk references, dynamic API loader candidates, and raw
  system-call byte matches are inventoried.
- A second static pass mapped 51 call/callback routes and one imported-data
  reference among the 62 imports that lacked direct/thunk call references;
  10 import rows still have no recovered invocation path and are classified
  in the per-API audit. The `PostQuitMessage` wrapper path is tied to seven
  callers.
- All 128 dynamic-loader callsites in the five installed PE snapshots are
  inventoried and statically reviewed across the driver, installer helper,
  updater, and uninstaller. Some caller-fed module/export values, cached
  pointer consumers, external callers, and runtime execution remain open; see
  `docs/rk-dynamic-api-resolution-audit.md`.
- The documented native paths include HID enumeration, selected
  device-family protocol routines, updater transfer/readback, local
  profile/macro/screen persistence, installer helpers, and uninstaller
  scripts.
- The shared settings serializer's keymap, macro, lighting, RGB, and color
  group branches are mapped to G5/3632 commands. Separate RKKB writes for
  key/layer, macro-derived, LED, key-color, matrix, Fn, and music paths are
  also documented. The semaphore-backed Apply worker, one UI event that
  signals it, and three device-family vtable entries are statically mapped.
  Profile-row logic selects the RKKB or G5 class for the checked records, but
  the concrete receiver type and data arguments at the worker call remain
  unresolved. G5 screen/GIF/page serializers and their virtual entries are
  also mapped, while the screen worker's concrete target and several payload
  meanings remain open. See
  `docs/rk-settings-apply-worker-audit.md` and
  `docs/rk-setting-serializer-audit.md`.
- The static Win32 dialog-template parser inventories all dialog resources in
  the examined PEs and their declared controls; selected updater controls are
  cross-referenced to a statically recovered complete updater message map in
  `docs/rk-dialog-resource-audit.md`.
- The updater serial receive worker is traced through its queue, posted
  message `0x401`, and state-dispatch routine. The 3632 response reader's
  status tests, queue timeout, and retry behavior are also documented.
- The main UI's model-specific LED XML path and generic fallback path are
  statically cross-referenced, while widget/command binding remains open.
- The installed mapping tuple corpus is exhaustively cataloged, with a
  confidence-ranked report separating visual rectangle coordinates from
  candidate action, keycode, and matrix-index meanings; end-to-end profile to
  device translation remains unresolved.
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
- Every MFC control label and action, every profile tuple's meaning, all
  packet fields, or the protocol meaning and runtime reachability of the UART
  command/response paths. The 15 updater dispatch slots are separately mapped.
  A conditional UART response-to-file sink is present in states 7 and 11, but
  its file gate is directly initialized to zero, no nonzero direct setter or
  stream-open path was found; states 10/11 also form a closed direct cycle
  with no incoming transition from initialized state 0. Indirect/external
  activation remains unresolved.
- A read-only command that can safely and completely copy firmware from an
  attached keyboard. The conditional UART sink is not a demonstrated,
  complete firmware backup method.

These gaps are intentional status labels, not claims that the missing work is
impossible. New package snapshots and independently supported findings should
extend the evidence without silently converting candidates into confirmed
hardware mappings.
