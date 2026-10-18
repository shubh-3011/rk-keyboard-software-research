# RK Drive RK68 HE lighting UI-to-service crosswalk

## Scope and provenance

This follow-up connects a narrow set of the public RK Drive Web App's lighting
controls to its minified SDK service implementation. It is tied to the entry
bundle `index-DSCGl9KV.js`, fetched from
`https://drive.rkgaming.com/assets/index-DSCGl9KV.js` on 2026-10-18. The
in-memory bundle was 20,417,509 bytes with SHA-256
`ec50777e49f34f24f4564c8624d5c39b52447980199fad43e24734826e6531ee`, matching
the existing [bundle manifest](rk-drive-js-manifest.csv). Vendor JavaScript
was not retained in the repository; the row-level, source-free crosswalk is
[`rk-drive-rk68-he-lighting-ui-protocol-crosswalk-2026-10-18.csv`](rk-drive-rk68-he-lighting-ui-protocol-crosswalk-2026-10-18.csv).

The two RK68 HE profile records (`RK68 HE`, PID `0x10BF`; and `RK68 HE ES`,
PID `0x10C0`) are Bytech profiles in the existing
[specialized profile catalog](rk-drive-specialized-keyboard-profiles.csv).
The SDK factory registers a service token named `ILightingLegacyService` to
class `jEr`, and the SDK facade's `lighting` getter resolves that token. The
service name is shared/legacy-named; the class is not shown to be exclusive to
the RK68 HE. This crosswalk documents the RK68 HE capability-gated path and
does not generalize its availability to every profile.

## Static path summary

The `lighting-page` loads the main effect with `sdk.lighting.getEffect(Main)`.
Selecting or applying an effect calls `setEffect(area, value)`, reads the
effect back, compares the returned fields, and attempts to restore the
previous effect if verification fails. For the main area, the page adds and
checks `direction` only when `lightingEffectDirection` is available.

Custom main lighting uses a separate path: the editor selects `CustomMode`,
then calls `setCustomMainLight` with key IDs and RGB values. Per-key paint uses
`updateRGB` only when `keyIdRGB` is true and there are records to update. That
method groups keys by color and serializes each group as
`[r, g, b, idCount, ...keyIDs]`. The same service has distinct full-key
uniform-color and LED-bead methods on selectors 2 and 3; they are not the
per-key paint method. The service's static serializers include operation/type values 132 for effect
read, 4 for effect set, 134 for custom-main read, 6 for custom-main set, and
8 with selector 1 for per-key RGB updates. The `Lqe` area mapping used by the
effect methods returns Main/Side/Logo selectors 1/6/11. These are values in
the Web App's packet builder, not proof of firmware semantics.

## Evidence labels and limits

- **Proven statically:** the exact bundle hash, decoder-table token mapping,
  service registration/getter, UI-to-service calls, capability gates,
  read-back verification/rollback structure, and serializer field layouts.
- **Inferred:** the lighting page and common service are intended to expose
  these controls for profiles whose runtime SDK feature state enables them.
  The RK68 HE rows are Bytech profiles, but this analysis does not prove a
  particular hardware revision reaches or accepts each operation.
- **Unresolved:** actual browser event reachability, device response, exact
  protocol meanings, firmware/revision compatibility, failure handling inside
  the transport, and the UI-to-handler paths for other models and feature
  families.

The bundle was fetched and searched in memory only. No page script was run by
this audit, no WebHID chooser or device permission was opened, and no report,
command, firmware, or bootloader operation was accessed. Re-run the
[hash-pinned verifier](../scripts/audit_rk_drive_rk68_he_lighting.py) to check
the byte anchors and decoded service-token mapping without saving the bundle.
