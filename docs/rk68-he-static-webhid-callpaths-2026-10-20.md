# RK68 HE Web application: bounded static WebHID call paths

**Snapshot:** selector-listed route `https://rk.hubx.pro/`
**Analysis date:** 2026-10-20
**Scope:** static source and bundle evidence from the 91 HTML, JavaScript, and CSS assets recorded for this host in [`rk-product-driver-route-web-asset-ledger-2026-10-20.csv`](rk-product-driver-route-web-asset-ledger-2026-10-20.csv).

This report reconstructs source-level paths that can be followed without executing the application. It covers one selector-listed web application, not the complete Royal Kludge Windows driver suite or every RK model. The primary bundle is `app-BqfTKFxh.js` (SHA-256 `b6144986513c0e91b17f340c9fbd126911d9596132ef466e7b25e760d6586ef8`). The HTML entry is `index.html` (SHA-256 `4482b2dc450123151f8e43a7313c4430b77d3c8dec87fe45ba8caab2b6efd10a`).

## Findings

### Entry and UI routes

The HTML shell loads the main bundle. Its static router declares these paths and lazy main-component imports:

- `/` → `chunk-CXTZWNyo.js`
- `/keyboard` → `chunk-CsbVz4lP.js`
- `/lighting` → `chunk-DDGIK9S6.js`
- `/rhythm` → `chunk-BAldE2tb.js`
- `/macro` → `chunk-DhL8p3_z.js`
- `/features` → `chunk-3hJ9KbLQ.js`
- `/performance` → `chunk-CP73SzDP.js`
- `/advanced` → `chunk-C1buM9JT.js`
- `/custom_keys_layout` → `chunk-2Gyz-vL_.js`
- `/empty` → `chunk-F0efLOcG.js`
- `/setup` → `chunk-D9wJ8Lfy.js`
- `/settings` → `chunk-oIAA2p6Q.js`
- `/devices` → `chunk-BrDqzObC.js`

These are direct router and lazy-import declarations in the bundle, not runtime visits. Component names recorded in the evidence CSV come from each chunk's minified `__name` metadata and are descriptive labels. The router also lazy-loads shared layout chunks; this inventory records the main component import only.

### Device selection and model gates

The `/setup` component's connect action calls a local imported binding. The component imports export `c`; the main bundle export table maps `c` to `$6t`. `$6t` checks for `navigator.hid`, constructs picker filters from the static `i1` product table, then calls `navigator.hid.requestDevice({filters:e})`.

After selection, `H6t` walks candidate profiles through exact VID/PID matching, report-channel collection checks, TX and RX report-ID checks, protocol/controller dispatch, and—for the `kb_by_v3_wired` branch—UUID comparison. A separate existing-permission path uses `navigator.hid.getDevices()` to recover an already authorized device. Connect/disconnect listeners and the `model_common_device` store track online/offline/current-device state.

This bundle contains two RK68 HE catalog entries:

- VID/PID `14126/4287`, TX/RX/I/O report IDs `9/9/9`, payload length `63`, protocol `kb_by_v3_wired`, keyboard/report/wired, UUID `18691697672194`, icon `RK_68_HE`.
- VID/PID `14126/4288`, TX/RX/I/O report IDs `9/9/9`, payload length `63`, protocol `kb_by_v3_wired`, keyboard/report/wired, UUID `18691697672252`, icon `RK_68_HE_UK`.

Those are catalog profiles in this specific bundle. They do not establish the physical revision connected to a computer, enumerate wireless variants, or prove that every RK68 HE revision is supported.

### A source-proven lighting path

The following static call chain is present in the bundle sources:

1. The router maps `/lighting` to `chunk-DDGIK9S6.js`.
2. Its `sync_light_params` handler obtains the shared store and calls `sync_light_mode()` after setting the requested light parameters.
3. The page imports the main bundle's export `r` under local name `he`. The main bundle exports `Li` as `r`; `Li` is the `model_kb_by_v3_basic` store.
4. The store's `sync_light_mode()` action calls `(await Yt().controller).sync_light_mode(this)`. The controller store's `controller` getter routes through its `connect()` action.
5. The V3 controller's `sync_light_mode(t)` builds a payload and calls `this.sendReport(this.payload)` in the same method body.
6. The V3 `sendReport` implementation calls `this.device.sendReport(this.report_id_tx, new Uint8Array(t))`, the browser `HIDDevice.sendReport` boundary.

The model-gated `kb_by_v3_wired` branch constructs the V3 controller and checks the configured UUID. The static sources therefore expose a path from the lighting UI action through the service/controller layers to the browser report method. This is a code-path reconstruction, not a claim that the device accepted a packet or that a particular physical keyboard has that profile.

### Other protocol surface found

Within the bounded V3 controller class, static declarations include lighting, rapid-trigger (`sync_rt`), advanced-key, polling-level, macro-transfer, battery, and firmware-version operations. The evidence CSV records exact declarations for representative operations. It also records method-local `sync_rt` and `sync_polling_level` → `sendReport` edges. The route inventory shows corresponding feature pages, but this report does not close every page-handler → store action → controller-method chain. In particular, the presence of a method name or a route does not by itself prove that the RK68 HE page exposes that operation or that its protocol branch succeeds.

### Route-level feature call paths

The companion [`rk68-he-route-feature-callpaths-2026-10-20.csv`](rk68-he-route-feature-callpaths-2026-10-20.csv) adds a bounded handler → store → controller trace for selected routes. Each row carries the source filename, SHA-256, zero-based half-open UTF-8 byte range, excerpt, and a status distinguishing direct source edges from unresolved property calls. The important closed paths are:

- **Key mapping (`/keyboard`):** the editor chooses its V3 wrapper when the current device's protocol is `kb_by_v3_wired`. Its drop handler calls the V3 key store's `set_key` and awaits `sync_keys`; that persisted store delegates through the controller store to V3 `sync_keys`, `_sync_keys`, and `sendReport`.
- **Macros (`/macro` and `/keyboard`):** saving a macro records event data and macro type/count in the persisted `model_macro.macro_config` store. The keyboard editor reads that store for assignments. When a macro-typed key is synchronized, V3 `sync_keys` checks and serializes macro data, then `_send_macro_to_device` chunks the transfer and calls `sendReport`. This separates local editor save from the source-proven device-upload path.
- **Advanced keys / DKS (`/advanced`):** the save handler recognizes DKS, TGL, MT, MPT, and END categories and calls the key store's `sync_advanced_keys`. The V3 dispatcher chooses `_sync_advanced_keys_dks` when the saved type is DKS; that encoder packs fields from the stored structure and calls `sendReport`. The report does not assign undocumented semantic meaning to individual packed bytes.
- **Performance / rapid trigger (`/performance`):** per-key apply dispatches key type, travel distance, RT, and safe-area store actions. The global handler separately dispatches `sync_rt`; the key store delegates to the V3 controller's `sync_rt`, whose method packs RT values and calls `sendReport`.
- **Feature report rate (`/features`):** the component gates its V3 panel on `kb_by_v3_wired`. Its report-rate handler updates the shared basic-feature store and awaits `sync_polling_level`; the store delegates to the controller, and V3 `sync_polling_level` calls `sendReport`.
- **Settings and device selection:** the settings handler schedules a controller connection followed by `reset_factory`; the V3 method calls `sendReport`. The devices page uses the shared picker, enumerates already-authorized devices with `navigator.hid.getDevices()`, stores the selected device, and navigates to `/keyboard`. These are source call paths, not operations exercised in this analysis.

Some router-listed areas remain only partially understood. `/rhythm` calls `changeCurrentRhythm` and `messageSender.sendChangeMessage`, but the acquired module set has no implementation for those receiver properties; their behavior and any lower-level transport remain open. `/custom_keys_layout` source proves drag/resize mutations of `keys_local` and JSON logging, but does not establish a device-write path. The performance page also exposes several non-RT store calls whose full controller paths are not traced in this pass.

## Evidence and reproduction

[`rk68-he-static-webhid-callpath-evidence-2026-10-20.csv`](rk68-he-static-webhid-callpath-evidence-2026-10-20.csv) records the original setup, model-gate, lifecycle, and lighting-path evidence. [`rk68-he-route-feature-callpaths-2026-10-20.csv`](rk68-he-route-feature-callpaths-2026-10-20.csv) records the route-scoped evidence described above. Every row records a source asset SHA-256 and a zero-based, half-open UTF-8 byte range with an excerpt. The generators check source assets against the existing asset ledger before producing rows; byte offsets are stable only for the pinned SHA-256 version.

Regenerate the ledger from the already acquired snapshot:

```powershell
python scripts/audit_rk68_he_webhid_callpaths.py
python scripts/audit_rk68_he_route_feature_callpaths.py
```

The script reads only the ledger-selected local snapshot, checks each asset hash, and scans source text. It does not import/evaluate vendor JavaScript or interact with a HID device. The REA static graph was also generated against this curated, hash-pinned input; it is retained in ignored `.research` data and is not a replacement for the byte-addressable source excerpts in the CSV.

## Open paths and limits

- The route ledger is a bounded static reconstruction, not a complete call graph. Rhythm receiver implementations, custom-layout persistence/device effects, and several non-RT performance controller chains are unresolved. Other feature routes and controller methods still need method-by-method tracing.
- The catalog is this web application's eight-entry static table, not a complete RK product database. Other sites, desktop binaries, firmware, protocol variants, and device revisions remain outside this snapshot.
- Static source cannot establish permission prompts, actual browser/device descriptors, whether the controller branch is selected at runtime, report acceptance, state persistence, or successful physical effects.
- No vendor code was executed, no keyboard/HID interface was opened, and no HID report was sent during this analysis.
- Asset acquisition provenance is described in the route asset ledger. The evidence here supports what is in the acquired bytes; it does not establish vendor ownership or validate the download site's TLS chain.
