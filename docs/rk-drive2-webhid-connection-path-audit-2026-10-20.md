# RK `drive2` WebHID connection and initialization path — static audit

## Scope and evidence

This is a static follow-up to the [selector-listed Driver route audit](rk-product-driver-selector-route-audit-2026-10-20.md).
It traces the acquired `drive2.rkgaming.com` route from its route table and
connect-page handler to the shared WebHID service and 64-byte packet builder.
The three source files are SHA-256 pinned in the
[route asset ledger](rk-product-driver-route-web-asset-ledger-2026-10-20.csv).
The [65-row evidence ledger](rk-drive2-connection-path-evidence-2026-10-20.csv)
contains their byte offsets and the [scanner](../scripts/audit_rk_drive2_connection_path.py)
rechecks those hashes before emitting the rows.

No vendor JavaScript was executed. No browser chooser was opened, no HID
interface was opened or enumerated, and no report was received or sent. The
report describes code paths, not observed device behavior.

## Route and service path

The entry bundle `index-Cq0ERv1u.js` (513,749 bytes;
SHA-256 `26eb7d4cbc70e3d5784ba77e41024d0c6f8b46ee8d022727d619a41217a0e011`)
maps `/connect` to a lazy `ConnectDrivePage` module and `/device` to a lazy
`DeviceSettingPage` module. The component injects `WebHIDService`; its connect
button is bound to a handler which calls, in order:

1. `requestDevice()`;
2. `openDevice()`;
3. `startEventListen()`;
4. a sync packet followed by the app-mode initialization sequence below;
5. navigation to `/device` after the sequence and an 800 ms delay.

The chooser code uses the production filter list `fx`: vendor ID 7330
(`0x1CA2`), product IDs 5633–5659 (`0x1601`–`0x161B`), usage page 65440
(`0xFFA0`), usage 1. It then rejects seven product-name strings in the returned
device. This list is not a complete RK model/revision mapping and does not
prove those numeric IDs are supported keyboards.

The open path records the selected device's VID, PID, and usage page in reactive
state, but writes a hard-coded `{VID:7247, PID:61064, usagePage:65440, usage:1}`
object to `localStorage` as `keyboardInfo`. The reconnect routine reads and
logs that stored object, then calls `navigator.hid.getDevices()` and selects a
device by collection usage page/usage; the stored VID/PID are not used by that
selection loop. The reason for the hard-coded object and its runtime effects
are unresolved.

The service registers `oninputreport`, `onconnect`, and `ondisconnect` handlers.
Its input handler concatenates received `DataView` bytes into a buffer. If byte
2 is `0x92`, it changes byte 1 to `0xC0`; once the declared length condition is
met, it calls `ProcessingReceivedData()` and clears the buffer. The parser has
branches keyed by command-response values from the packet enum, but this pass
does not map every response branch to its producer, state consumer, or feature
UI.

## Connection-time request sequence

The `ConnectDrivePage` bundle is 5,523 bytes with SHA-256
`04ca4462e79af641d0150ecf83cbc55fb1dd8e29490ad128c9b78c0e6ed3698d`. Its
button handler calls `writeData()` for the following sequence. The page's log
strings label the requests as shown; for `PRGBPack`, `LOGORGBPack`, `DBPack`,
and `DEFKEYPack`, those labels and builder names are not enough to confirm the
device-side meaning.

| Order | Packet builder call | Page label or context |
| ---: | --- | --- |
| 1 | `SYNCPack()` | sync, then wait 200 ms |
| 2 | `CMDPack(1, null)` | protocol version |
| 3 | `CMDPack(38, null)` | keyboard name |
| 4 | `CMDPack(37, null)` | precision and travel bounds |
| 5 | `CMDPack(112, 4)` | configuration ID |
| 6 | `CMDPack(118, null)` | supported axis IDs |
| 7 | `CMDPack(80, 7)` | report rate |
| 8 | `CMDPack(33, null)` | Windows mode |
| 9 | `CMDPack(34, null)` | macOS mode |
| 10 | `CMDPack(52, 2)` | top dead-zone switch status |
| 11 | `DBPack(0, 0, 0, 0)` | overall travel/dead-zone context |
| 12 | `CMDArrayPack(68, [255, 255, 255])` | lighting offset |
| 13 | `PRGBPack(0, staticLightColors, false, false, false, 0, 0, 0, 0)` | lighting state context |
| 14 | `LOGORGBPack(0, logoStaticLightColors, false, false, false, 0, 0, 0, 0, 0)` | logo/ambient-light context |
| 15–17 | `DEFKEYPack(0,1)`, `(2,3)`, `(4,5)` | HID matrix context |

If `KeyboardRunMode` equals 255 after sync, the handler takes its boot-mode
branch and skips the remaining app-mode sequence. Otherwise it sends the
requests above and navigates to `/device`. This is a static branch description;
it does not establish what a physical device returns for any command.

The entry bundle defines `ProtocolCMD` values including `KB2_CMD=0`,
`KB2_CMD_SYNC=1`, `KB2_CMD_KEY=35`, `KB2_CMD_DB=41`, `KB2_CMD_DEFKEY=43`,
`KB2_CMD_PRGB=24`, and `KB2_CMD_LOGORGB=25`. `CMDOrder` labels include query
IDs 1, 33, 34, 37, 38, 52, 68, 80, 112, and 118. The `CMDPack` and `SYNCPack`
builders each allocate 64 bytes, set a leading byte to decimal 92 (`0x5C`),
populate command data and `0xFF` terminators, then call `ComputeCheckSum`.
That helper's byte arithmetic is recoverable statically, but checksum
correctness and the application-specific framing remain unverified on a
keyboard.

`writeData()` divides its input into chunks of at most 64 bytes and invokes
`HIDDevice.sendReport(0, chunk)`. For the 64-byte packet builders this is a
single report with report ID 0. The API call and buffer path are proven from
the hashed bundle; no report was sent in this audit. The selector-wide scan
found no literal `sendFeatureReport` or `receiveFeatureReport` in the four
acquired `drive2` JavaScript files; that bounded lexical result does not rule
out indirect or aliased calls.

## Limits and next work

- The 27 filtered product IDs are not joined to a reliable product/revision
  catalog; the selector routes six named models to this shared app, but the
  code-to-model compatibility path is not closed.
- The inbound parser and many `/device` page handlers, profile gates, serializers,
  persistence paths, firmware paths, and UI-to-command edges remain unmapped.
- Packet labels, enum names, and static builders do not establish command
  semantics, successful reads/writes, firmware compatibility, or physical
  acceptance.
- This 2026 `drive2` bundle is a distinct hash from the larger 2026-10-18
  `drive.rkgaming.com` bundle. Existing reports for that other build cannot be
  treated as its call graph.
- The raw assets remain in ignored `.research/`; no vendor application code
  or web asset was copied into this repository.\n