# RK `drive2` lighting selector to WebHID: bounded static path

**Analysis date:** 2026-10-25
**Snapshot:** selector-listed `drive2.rkgaming.com` route assets captured in the 2026-10-20 asset ledger
**Scope:** one main-light mode-selector handler through packet construction to the browser WebHID send call. This adds a feature-specific trace to the existing [connection and initialization audit](rk-drive2-webhid-connection-path-audit-2026-10-20.md); it is not a complete `drive2` UI/protocol reconstruction.

## Conclusion

The pinned source statically connects the `/device` route's **light setting** menu to a main-light selector. Changing that selector invokes `changeLightBigMode`; its handler adjusts the lighting store, constructs `PRGBPack` with apply argument `1`, and awaits the page's imported `WebHIDService.writeData`. The service divides the packet into chunks no larger than 64 bytes and calls `HIDDevice.sendReport(0, chunk)`.

This is source-level reachability evidence only. No app code was executed, no chooser or keyboard interface was opened, and no report was sent. The code does not establish that the connected keyboard is an S98, that any particular hardware revision supports command `0x18`, or that firmware accepts the packet.

## Pinned inputs and verification

The [asset ledger](rk-product-driver-route-web-asset-ledger-2026-10-20.csv) identifies the two source files and their hashes:

| Asset | Bytes | SHA-256 |
| --- | ---: | --- |
| `index-Cq0ERv1u.js` | 513,749 | `26eb7d4cbc70e3d5784ba77e41024d0c6f8b46ee8d022727d619a41217a0e011` |
| `DeviceSettingPage-D_XFuI9e.js` | 1,934,623 | `7b20036f4f4390b3559b777f72b3381e513e661929fb097df4378d07e1e6ecfb` |

The [15-row evidence ledger](rk-drive2-lighting-apply-path-evidence-2026-10-25.csv) records unique byte anchors, exact source hashes, offsets, evidence classifications, and limits. Re-run from the repository root:

```powershell
python scripts/audit_rk_drive2_lighting_apply_path.py
```

The verifier reads only the existing `.research` snapshot and its dated asset ledger. It fails if either digest changes, if any anchor is absent or ambiguous, or if the page's import alias no longer maps to the entry module's `WebHIDService` singleton. It does not execute JavaScript or access WebHID.

## Reconstructed path

1. **Route entry — proven in pinned source.** The entry router declares `/device` with the lazy component mapped to `DeviceSettingPage`.
2. **Lighting page selection — proven in pinned source.** The device-page menu's first item has text key `lightSetting`. Its click callback writes the selected array index into `driveCurrentPage` and resets the nested page index to zero. The device page renders the `L0e` component when `driveCurrentPage === 0`; that wrapper places `A0e` in the `lightTabPage-1` tab.
3. **Control binding — proven in pinned source.** `A0e` calls the lighting composable `Lce`. The mode selector binds its model value to the composable's `LightBigMode` state and includes `changeLightBigMode` in the model-update handler. This identifies the UI-to-handler edge; it does not prove which menu item a person selected at runtime.
4. **State update and packet call — proven in pinned source.** `Lce`'s `changeLightBigMode` handler updates the on/off and dynamic mode state according to the selected value. It then awaits `mt.writeData(re.PRGBPack(1, ...))`, passing the current seven-color list, switch, direction, super-response flag, luminance, light mode, speed, sleep delay, and static-color mode. If the selected mode is the custom mode, the function continues into a separate per-key color path; this report does not trace that branch.
5. **Service identity — proven across the pinned module boundary.** The page imports the entry module as `./index-Cq0ERv1u.js` and imports entry export `aS` under local name `mt`. The entry export table maps `aS` to `_x`; `_x` is registered as the dependency named `WebHIDService`. This ties the handler's `mt.writeData` call to the service described by the entry source.
6. **Packet construction — proven as host-side serialization.** The entry's command table assigns `KB2_CMD_PRGB` value 24 (`0x18`). `PRGBPack` allocates a 64-byte array, sets header byte 0 from `head` (`92`, `0x5C`), places the command at byte 2, writes the apply argument at byte 4, serializes seven color entries as three parsed color bytes followed by `255`, calls `getLightBitmap` with the switch/direction/super-response arguments, appends the remaining light settings, writes the payload length in byte 1, and calls `ComputeCheckSum` for byte 3. The byte order of the three color bytes follows the literal serializer operations; this report does not claim a firmware-side color interpretation.
7. **WebHID boundary — proven as source.** `writeData` slices data into chunks of at most 64 bytes and calls `this.device.sendReport(0, n)` for each chunk. Since this serializer allocates exactly 64 bytes, its ordinary output is one 64-byte call at report ID zero. Source evidence does not prove that the device was connected, the method ran, the operating system transmitted the packet, or the device accepted it.

## Evidence distinctions

### Proven from these exact bytes

- The route, menu text key, index selection, conditional render, component composition, and mode-selector event binding listed above.
- The mode handler's call to the `PRGBPack` builder with leading argument `1`, then to the imported service's `writeData` method.
- The builder's 64-byte output allocation, command-table value, visible field write order, and checksum-helper call.
- The service's chunking and direct `sendReport(0, chunk)` call.

### Inferred from host code, not hardware validation

- Argument `1` is treated here as an apply/write selector because the same app's initialization sequence calls `PRGBPack(0, ...)` while its log labels that operation as retrieving lighting settings. This inference is based on caller context and is not a decoded firmware specification.
- The mode selector is intended to affect the seven-color lighting settings represented by the store and serializer. Host state names and UI wiring do not establish how every controller or firmware revision interprets each field.

### Unresolved

- Device/revision support for `PRGB` and its response semantics, packet checksum acceptance, persistence, and physical lighting effects.
- Whether a particular S98/other model is selected for this route or passes its chooser and model gates.
- The full palette/color-picker-to-store chain, all lighting controls and capability gates, the custom per-key `KRGBPack` branch, receiver response dispatch into the state decoder, and each model family's equivalent lighting path.
- The OS/browser implementation below the WebHID API boundary.

## Provenance and boundaries

This is a new feature-specific path against the `drive2` asset hashes already acquired and recorded in this repository. It is distinct from the broad `drive.rkgaming.com` worker audit and from the RK68 HE `rk.hubx.pro` lighting trace: those reports analyze different bundles and do not establish this `drive2` call path.

Static source can identify a software route and report API callsite, but it cannot establish successful live communication or physical model compatibility. No source bundle or image was copied into the repository for this report.
