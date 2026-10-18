# RK Drive feature gates and mouse registry audit — 2026-10-18

## Scope and method

This follow-up statically inspected the public RK Drive Web App bundle served on
2026-10-18. It fetched the seven JavaScript bundles into memory and retained only
hashes and source-free metadata. The entry bundle is
`index-DSCGl9KV.js`, 20,417,509 bytes, SHA-256
`ec50777e49f34f24f4564c8624d5c39b52447980199fad43e24734826e6531ee`, matching
the snapshot already recorded in [`rk-drive-js-manifest.csv`](rk-drive-js-manifest.csv).
No vendor JavaScript or product image was copied into this repository.

This was static analysis only. The app was not run, no WebHID chooser or browser
permission was opened, and no device interface, report, update, or firmware path
was accessed. A source-free mouse registry is in
[`rk-drive-mouse-registry.csv`](rk-drive-mouse-registry.csv).

## Device routing and identification

**Proven — route structure.** The bundled router has one route: `/`, named
`home`. The connected-device view branches on connection state plus the selected
descriptor's `deviceType` and `protocolType`; it is not a separate URL per
feature. Static predicates were found for these family/view combinations:

- Keyboard: BeiYing, SparkLink, JuPeng, QiWang, Gcome, HangSheng, RongYuan,
  Bytech, and QMK.
- Mouse: BeiYing and QiWang.
- The TLW mouse path is constructed from a separate model profile and produces
  descriptors dynamically; it does not appear among the 20 legacy mouse
  protocol descriptors.

**Proven — match inputs.** The browser chooser builds filters from VID/PID. QMK
filters also include usage page and usage. The subsequent general descriptor
match compares VID and PID and checks that the device exposes the declared HID
usage-page/usage collection. Gcome adds an exact normalized product-name check.
The newer RK68 HE path first reads a device UUID, resolves it to a profile, and
checks the profile's VID/PID before initialization. These rules are stronger
than a displayed product label, but still do not prove that every physical
revision has a unique identifier.

**Inferred — ambiguity.** The mouse catalog has shared candidate IDs: for
example, VID/PID `0x258A:0x0138` is declared for RK-M30, MO1, and MO3 receivers,
and `0x372E:0x103F` is declared for RK-K3 and RK-MG5 receivers. Those rows also
share their usage page/usage. The bundle's static descriptor set therefore
cannot distinguish those model names by the listed HID identity alone. A live
device name, additional report data, or an explicit user choice may be involved;
which one is used remains unresolved.

## Mouse registry findings

**Proven — two registry layers.** The entry bundle contains 20 full legacy
`deviceType: Mouse` descriptors and 20 simpler, lower-case chooser aliases.
The profile records resolve to six BeiYing product labels (RK-M3, RK-M30,
RK-K3, RK-MG5, MO1, MO3) and two QiWang product labels (RK MG6 Pro and RK-MG6).
It also includes two QiWang boot-placeholder descriptors with `0xFFFF` VID/PID;
these are static boot-mode entries, not evidence of two retail mouse models.
Each full legacy descriptor points at a protocol family and a model-specific
layout/factory symbol. The CSV links each profile row to its matching chooser
alias when its VID/PID, usage fields, connection type, and protocol family
agree.

The legacy list covers USB and 2.4 GHz receiver variants. It declares the
following product/connection pairings (hex IDs are also in the CSV):

- BeiYing: RK-M3 (`0x372E`, USB `0x102A`, receiver `0x1019`); RK-M30
  (`0x258A`, `0x0136` / `0x0138`); RK-K3 (`0x372E`, `0x1045` / `0x103F`);
  RK-MG5 (`0x372E`, `0x1073` / `0x103F`); MO1 (`0x258A`, `0x0284` / `0x0138`);
  and MO3 (`0x258A`, `0x0283` / `0x0138`).
- QiWang: RK MG6 Pro (`0x2E3C`, `0x00A5` / `0x00A6`, plus a second pair
  `0x00E5` / `0x00E6`) and RK-MG6 (`0x0F62`, `0x1013` / `0x1014`).

**Proven — separate CB75-Mouse profile.** A model-specific profile named
`CB75-Mouse` is declared with VID `0x320F`, HID usage page `0xFF1C`, usage
`0x0092`, report ID 4, and two connections: wired PID `0x22F2` (declared
56-byte data size) and wireless PID `0x22F3` (24-byte data size). It declares
`features.lighting = true`, separate profile/macro storage keys, and a
button-layout object. Its official image reference is
[`cb75-mouse-Ch095Wok.png`](https://drive.rkgaming.com/assets/cb75-mouse-Ch095Wok.png);
the image itself was not downloaded or mirrored.

This CB75 record is compiled into two TLW mouse descriptors by a registry
builder. That builder checks model IDs, duplicate HID identities, and storage
keys before adding the connections. The TLW mouse protocol implementation
contains a guard that rejects lighting calls when `features.lighting` is false.
That is direct evidence that feature flags can gate a protocol method; it does
not establish that every other mouse control is implemented for CB75.

## User-visible feature families and gates

**Proven — labels and page families in the bundle.** The English localization
and UI code contain these candidate surfaces:

| Family | Static user-visible controls or labels | Model-gate evidence and limit |
| --- | --- | --- |
| Keyboard mapping | Key settings, key functions, layers, Windows/macOS tables, advanced keys | Per-descriptor layers, tables, layouts, and protocol family exist. Per-control runtime gates are not fully recovered. |
| Macros | Macro manager, recording/editing, delay, import/export messages | UI and family-specific code exist; this audit did not map each mouse or keyboard model to a supported macro path. |
| Lighting | Effects, brightness, speed, direction, per-key color and light zones | Keyboard rows declare different effect lists. RK68 HE dynamically reads device feature bits for effect direction and key RGB; its profile declares no side light. CB75 declares only `lighting: true`. |
| TFT/screen | Image loading, layers, frame list, playback, time format, resolutions, up to 100 frames | Labels are present; no per-model transfer support is inferred from the labels. Existing screen transport audit remains the relevant protocol evidence. |
| Mouse mapping | Mouse buttons, wheel, X/Y axes, DPI functions, DPI levels, report-rate functions | Generic mouse UI strings and mouse protocol classes are present. They do not show that each mouse descriptor exposes every control. |
| Mouse performance | DPI, report rate, LOD height, ripple control, line correction, motion sync, glass mode, sensor mode, sleep time, debounce, work/high-performance/game modes | Static localization and settings labels only. The exact model-to-control gates and packet paths remain unresolved. |
| Magnetic switch performance | RK68 HE text for actuation travel, Rapid Trigger, global/single-key scope, press/release sensitivity, dead zone, calibration, real-time travel tests | The bundle has a dedicated RK68 HE profile and Bytech initialization path. Labels strongly indicate an HE performance surface, but the exact UI-to-feature-bit mapping for each item is not established here. |
| Settings / firmware | Keyboard/device information, firmware version, wired-mode update prompts, factory/reset and boot-mode text | Candidate UI and updater code are present. This audit did not invoke these paths or infer a safe device operation. |

**Proven — RK68 HE model gate.** The bundle includes two profiles named
`RK68 HE` and `RK68 HE ES`, with product IDs `0x10BF` and `0x10C0`, distinct
UUIDs, vendor ID `0x372E`, USB-only connection metadata, and protocol family
Bytech. Their common profile fields include minimum firmware version 0,
`hasSideLight: false`, and a hidden-keycode list. On connection, static code
reads UUID and device information/features. The lighting UI checks the
`lightingEffectDirection` and `keyIdRGB` values from the returned feature set;
side-light configuration also requires the model profile's `hasSideLight` flag.
This is a genuine per-model/firmware capability path, though it is not a
complete map of the page.

## Proven, inferred, and unresolved

- **Proven:** Seven public bundles are referenced by the current page and the
  entry hash matches the existing snapshot. There is one root UI route, several
  explicit device-family branches, a 20-row full legacy mouse registry, a
  20-row chooser-alias layer, a CB75-Mouse TLW profile with two connection
  records, and two RK68 HE locale/model profiles. The listed feature labels,
  matching gates, and static capability checks are in the bundle.
- **Inferred:** The model/protocol predicates choose family-specific pages, and
  the RK68 HE magnetic-switch strings are intended for its specialized feature
  surface. Shared mouse IDs make model name resolution ambiguous if only the
  listed identity fields are available.
- **Unresolved:** Full crosswalk from every menu control to a capability bit,
  event handler, and packet for every model; physical revision identification;
  whether mouse aliases are selected or deduplicated at runtime; completeness of
  the public model/photo registry; and actual device behavior. The public
  registry is an app snapshot, not a census of every RK product.

## Reproducible metadata and limits

The source-free CSV is an additional inventory, not executable support data.
The image URL is a reference to RK-hosted content and not a redistributable
copy. The JavaScript minification and static-only method mean that property
strings, UI labels, and dead or gated code must not be treated as proof of
reachable behavior. No firmware, boot mode, or write operation was attempted.
