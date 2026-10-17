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
  in the per-API audit. A follow-up traces the two Update.exe ANSI loader
  imports and eight unins000.exe scrollbar fallback imports but does not
  establish their invocation; see `docs/rk-remaining-native-api-path-audit.md`.
  The `PostQuitMessage` wrapper path is tied to seven callers.
- All 128 dynamic-loader callsites in the five installed PE snapshots are
  inventoried and statically reviewed across the driver, installer helper,
  updater, and uninstaller. Other resolver callsites outside the focused
  follow-up still have caller-fed values, cached-pointer consumers, external
  callers, or runtime reachability gaps; see
  `docs/rk-dynamic-api-resolution-audit.md`.
- A focused follow-up resolves fixed export strings and static cached-pointer
  consumers for the DeviceDriver UxTheme wrappers and Update common-control,
  common-dialog, and property-sheet helpers. The `DrawThemeParentBackground`
  wrapper still has no recovered in-image caller; no runtime branch is
  established. See `docs/rk-dynamic-api-consumer-gap-audit.md`.
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
  also documented. The semaphore-backed Apply worker, one UI event that
  signals it, and three device-family vtable entries are statically mapped.
  Profile-row logic selects the RKKB or G5 class for the checked records, but
  the concrete receiver type and data arguments at the worker call remain
  unresolved. G5 screen/GIF/page serializers and their virtual entries are
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
  [brightness trace](docs/reverse-engineering.md#brightness-profile-ui-and-serializer-path).
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
  selector, while most feature widget/command bindings remain open; see
  `docs/rk-ui-control-command-crosswalk.md`.
- A general-settings follow-up separates profile values and the main Apply
  memory/event edge from host-local `lang.ini`, generic MFC INI/registry, and
  per-device `.dct` persistence. Reset/factory prompt strings are present, but
  no prompt-to-reset-handler edge is recovered. See
  `docs/rk-general-settings-ui-persistence-audit.md`.
- A reset/system-parameter follow-up maps the profile-gated reset virtual call,
  family `+0x38` targets, periodic timeout worker and its `+0x48` family paths,
  and the `0x6401` event that stops that worker. The localized reset prompts
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
  byte, acknowledgements, retries, and cancellation path. Image conversion,
  UI reachability, screen-parameter schema, and physical compatibility remain
  unresolved. A follow-up maps the GIF-to-PNG cache routine, GDI+ callsites,
  and frame-conversion worker, but does not establish a file-import or
  conversion-to-device-writer path; see `docs/rk-screen-gif-payload-audit.md`
  and `docs/rk-screen-image-conversion-path-audit.md`.
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
  stream-open path was found; the state-3/4/6/7 and state-10/11 subgraphs have
  no direct incoming transition from initialized state 0. Indirect/external
  activation remains unresolved. The updater also has two six-byte feature
  reads in a post-transfer helper; they do not constitute a complete firmware
  read.
- A read-only command that can safely and completely copy firmware from an
  attached keyboard. The conditional UART sink is not a demonstrated,
  complete firmware backup method.

These gaps are intentional status labels, not claims that the missing work is
impossible. New package snapshots and independently supported findings should
extend the evidence without silently converting candidates into confirmed
hardware mappings.
