# RK Drive keymap, macro, and display static crosswalk

## Scope

This follow-up traces selected keymap, macro, and display paths in the public RK
Drive entry bundle `index-DSCGl9KV.js`, fetched in memory on 2026-10-18. Its
size is 20,417,509 bytes and SHA-256 is
`ec50777e49f34f24f4564c8624d5c39b52447980199fad43e24734826e6531ee`, matching
the [bundle manifest](rk-drive-js-manifest.csv). The source-free rows and
anchors are in
[`rk-drive-keymap-macro-display-crosswalk-2026-10-18.csv`](rk-drive-keymap-macro-display-crosswalk-2026-10-18.csv).
No vendor JavaScript or artwork was saved, and no page was executed.

## Keymap: RK68 HE UI and shared SDK service

The bundle registers `IKeymapService` to class `LEr`; the SDK's `remapping`
getter resolves that service. Its batch write builds operation 3 with the
encoded layer/system value and one six-byte record per key: a two-byte key ID
and four-byte keycode. Batch read builds operation 131, includes requested
two-byte IDs and aligned six-byte response sizing, then decodes six-byte
records into `{id,keycode}`. The layer/system bit packing is not decoded here.

The RK68 HE mapping UI loads all key IDs through
`remapping.getKeymaps` and also requests per-key travel data. It rejects an
incomplete mapping. An assignment is blocked when the selected key is already
used by an advanced-key feature; otherwise it validates a nonnegative
keycode, calls `setKeymap`, immediately reads `getKeymap`, and compares the
saved ID/keycode. Restoring a layer first removes its advanced-key entries,
then calls `resetKeymaps` and reloads the layer.

This proves the UI-to-SDK service-method path in the bundle. Although `LEr` is
registered as the shared `remapping` service, this trace does not establish
that the RK68 HE runtime resolves the concrete `LEr` serializer for its
physical device. The opcodes and record layout are therefore service-level
static evidence, not confirmed RK68 HE wire traffic.

## Macros: RK68 HE UI and service

The SDK registers `IMacroService` to class `FEr` and exposes it as `macro`.
The `macro-page` component loads the storage capacity and macro headers,
requires positive available capacity, and ensures a `Default Macro` slot. A
save validates the current macro list, writes it, reads it back, and compares
the result; if verification fails, it attempts to restore the prior list and
verifies that rollback.

The service-level static operations include:

- Operation 130, selector 0: read the available macro storage size as a
  four-byte value.
- Operation 133, selector 0: read the macro slot/header table. Each table
  entry is four bytes: little-endian offset followed by little-endian length.
- Operation 5, selector 0: write the slot table and concatenated macro data.
  The service's size calculation is `5 + UTF8(name).length + 4 * actionCount`.
  Each macro body begins with a one-byte UTF-8 name length and the name, then
  four-byte action records. Names over 255 UTF-8 bytes are rejected.

The parsed action object is `{type, code, delay, device}`. The serializer packs
these values into four bytes, but this audit leaves the packed bit meanings
unlabeled except where the UI validates key-down/key-up pairing and delay
bounds. The UI enforces a 256-slot ceiling and available storage. Its JSON
import/export envelope is `{version:1, device:"RK68 HE", macros:[...]}`. This
path is specific to the observed RK68 HE UI/service flow; broader model support
is unresolved.

## TFT page and newer display SDK are separate paths

The bundle contains a legacy `tft` page and an `IDisplayService` SDK service.
The legacy page's store binds the active `u.protocol`; the M87-branded page
lists four M87 locale variants and declares a 240 by 135 crop. The inspected
page imports image/GIF frames, converts each frame canvas to RGB565 pixel
buffers, limits the list to 100 frames, then calls
`protocol.setTftPic(buffers, delay)`. It subtracts 25 ms from frame delay when
the configured delay is at least 25 ms. Progress is reported through
`OnTftSetEvent`; the UI closes a pending operation after 15 seconds and calls
`stopTFTPicDownload`. Several duplicated `tft` implementations have different
dimensions, so the M87 page dimensions must not be generalized to all models.

Some legacy protocol classes contain active RGB565 packet-transfer methods;
others provide no-op stubs. The presence of the method or page does not prove a
model-specific profile reaches an active implementation.

Separately, the SDK registers `IDisplayService` to `QEr` and exposes a
`display` getter. That service includes display capability checks, profile
reads/writes, image-format conversion, and static/dynamic image transfer
helpers. The inspected bundle has no recovered UI call through the SDK's
`display` getter, and this trace did not connect the legacy page's
`u.protocol.setTftPic` calls to `QEr`. Keep these as distinct code paths; a
general display feature or per-model bridge is not established.

## Evidence and limits

- **Proven statically:** the hashed bundle, service registrations and SDK
  getters, method/opcode sequences, RK68 HE keymap/macro UI calls, readback and
  rollback structure, legacy TFT page calls, and the existence of the separate
  display service.
- **Inferred:** those UI components are intended for compatible devices with
  the relevant services/protocol methods available.
- **Unresolved:** physical-model/profile resolution for the keymap serializer;
  model coverage of macro storage; legacy TFT protocol-family selection and
  active transfer support per profile; the UI bridge to `IDisplayService`;
  firmware semantics and device acceptance.

The bundle was read as bytes for static inspection only. No WebHID chooser,
device interface, keyboard report, command, firmware, or bootloader path was
used. Re-run the
[hash-pinned anchor verifier](../scripts/audit_rk_drive_keymap_macro_display.py)
to validate bundle identity and the recorded byte anchors.
