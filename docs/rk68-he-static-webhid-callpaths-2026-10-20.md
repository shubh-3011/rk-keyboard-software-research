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

## Evidence and reproduction

[`rk68-he-static-webhid-callpath-evidence-2026-10-20.csv`](rk68-he-static-webhid-callpath-evidence-2026-10-20.csv) is the evidence ledger. Every row records the source asset SHA-256 and a zero-based, half-open UTF-8 byte range with an excerpt. Each cited file is checked against the existing asset ledger before rows are generated. The primary-bundle byte offsets are therefore stable only for the listed SHA-256 version.

Regenerate the ledger from the already acquired snapshot:

```powershell
python scripts/audit_rk68_he_webhid_callpaths.py
```

The script reads only the ledger-selected local snapshot, checks each asset hash, and scans source text. It does not import/evaluate vendor JavaScript or interact with a HID device. The REA static graph was also generated against this curated, hash-pinned input; it is retained in ignored `.research` data and is not a replacement for the byte-addressable source excerpts in the CSV.

## Open paths and limits

- UI → controller edges still need method-by-method reconstruction for keyboard mapping, macros, rhythm, advanced keys, performance, features, custom layout, and settings. This report does not treat route names or string matches as proof of execution.
- The catalog is this web application's eight-entry static table, not a complete RK product database. Other sites, desktop binaries, firmware, protocol variants, and device revisions remain outside this snapshot.
- Static source cannot establish permission prompts, actual browser/device descriptors, whether the controller branch is selected at runtime, report acceptance, state persistence, or successful physical effects.
- No vendor code was executed, no keyboard/HID interface was opened, and no HID report was sent during this analysis.
- Asset acquisition provenance is described in the route asset ledger. The evidence here supports what is in the acquired bytes; it does not establish vendor ownership or validate the download site's TLS chain.
