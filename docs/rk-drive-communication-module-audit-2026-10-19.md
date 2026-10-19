# RK Drive communication workers and WebHID callsites — 2026-10-19

## Scope and method

This pass hash-checked the seven JavaScript bundles recorded in the
[2026-10-18 bundle manifest](rk-drive-js-manifest.csv). The entry bundle was
20,417,509 bytes with SHA-256
`ec50777e49f34f24f4564c8624d5c39b52447980199fad43e24734826e6531ee`. Its six
small communication-worker assets were 538–1,103 bytes each. The scripts were
fetched into memory; no vendor JavaScript was saved or executed.

The pass inventories worker scheduling and direct WebHID API name/callsite
candidates. It does not open a browser chooser, request permission, open HID,
send/receive a report, exercise the app, or establish that a particular model
reaches a candidate path. All offsets are zero-based offsets into the exact
hash-pinned minified entry bundle.

## Worker inventory

The entry bundle constructs 78 workers using the six named assets below. The
counts are textual constructor occurrences; they do not equal physical models
or successful runtime worker creation.

| Worker asset | SHA-256 | Constructors in entry | Static scheduler behavior |
|---|---|---:|---|
| `communication-DV8bKwpo.js` | `9b77ecd0960c3e27a09f0c3dd122e8644c03140da18caf74291d5623c920adcc` | 38 | 20 ms queue loop; at most one queued item is posted per eligible tick. A heartbeat is posted after 1 s idle. Incoming `report` clears the response gate. |
| `dongleCommunication-CCLAqb0M.js` | `34a77cb93ae974ca7a412a4acbd4d124d0752d881440112f470844b06a7bfb6f` | 30 | 10 ms loop and 15 ms send/retry gate. It keeps an outstanding item, reposts it while waiting for `finish`/`report`, and posts `timeout` after 3 s. |
| `mouseCommunication-CkhFGE6m.js` | `52bf0ce7a90cc9efe57d58505b92117c9a9f46a91952d73cbebb82b94086991d` | 6 | 100 ms loop. `getReport` enables polling; `stopGet` or 2 s without activity disables it. While active, the worker asks for a report on a 20 ms gate. |
| `qiwangCommunication-CFWn-kHU.js` | `444fbf0dbcf57a79c9291357ce87ab8e18938d17eea589ffa94769214c057121` | 1 | 20 ms loop; after sending, waits 2 s for `report`, retries the retained item up to three times, and disables the retry gate. Idle heartbeat threshold is 1 s. |
| `qiwangCommunicationAdaptive-CZXbJVQO.js` | `9f44e3fbf24a9011c50902fd3429b1d2ef4fdd56f534f8d6a7e8e524a94a8052` | 2 | Separate priority and ordinary queues; wired mode uses a 20 ms send gap and 1 s response timeout; dongle mode uses 30 ms and 2 s. It retries once. Messages configure transport, enqueue packets, and clear the outstanding packet on `report`. |
| `rongyuanCommunication-DZX36okp.js` | `1d9e6b399ac8464638723917db38c591254f0e9ea83e0ca9fec4c51d2317a648` | 1 | 20 ms loop. `wait`/`run` pause and resume its idle behavior; it emits heartbeat after the 2 s idle threshold, and releases the wait after 5 s. |

These are static descriptions of the worker code's timer and queue state. They
do not establish the meaning of report bytes, transport reliability, actual
timing, or device acceptance. The large entry bundle also contains additional
inline transport and packet classes; these six files are the worker assets,
not the complete protocol implementation.

## Browser HID API boundary

The entry bundle contains direct WebHID API call candidates for
`HIDDevice.receiveFeatureReport`, `sendFeatureReport`, `sendReport`, `open`,
`close`, and `forget`, plus `HID` discovery through `requestDevice` and
`getDevices`. It installs `inputreport` and `disconnect` listeners. The raw
occurrence counts are repeated/minified source callsites, not counts of unique
operations or live sessions:

| API token | Occurrences in entry bundle |
|---|---:|
| `navigator.hid` | 6 |
| `HID.requestDevice` | 1 |
| `HID.getDevices` | 3 |
| `HIDDevice.receiveFeatureReport` | 63 |
| `HIDDevice.sendFeatureReport` | 63 |
| `HIDDevice.sendReport` | 59 |
| `HIDDevice.open` | 12 |
| `HIDDevice.close` | 158 |
| `HIDDevice.forget` | 9 |
| `inputreport` add/remove listeners | 63 / 88 |
| `disconnect` listeners | 3 |

The callsite ledger stores each byte offset and the entry-bundle digest. One
base wrapper class installs its `inputreport` listener near `0x15E155` and has
direct calls to `receiveFeatureReport` at `0x15E1FC`, `sendFeatureReport` at
`0x15E2BB`, and `sendReport` at `0x15E33E`; it converts received report data to
a view and dispatches it to a report handler. These are static wrapper calls,
not proof of runtime use. The direct APIs bridge browser JavaScript to the
browser's WebHID implementation. The browser, USB/HID class driver, and
OS-native call chains are separate components and were not inspected in this
pass. No OS syscall conclusion follows from this JavaScript-only inventory.

## Reproduction and limits

Run from the repository root with network access:

```powershell
python scripts/audit_rk_drive_communication_modules.py --overwrite
```

The script fails if any of the seven bundle sizes or hashes differ from the
dated manifest. It writes no vendor source. Its outputs are:

- [Worker asset hashes and constructor counts](rk-drive-communication-module-audit-2026-10-19.csv)
- [WebHID callsite candidates](rk-drive-webhid-api-callsite-candidates-2026-10-19.csv)
- [Hash-checking scanner](../scripts/audit_rk_drive_communication_modules.py)

The broader unresolved scope remains the entry bundle's complete UI-to-worker
and packet-serializer graph for all 177 listed keyboard descriptors, runtime
model selection, unsupported or retired models, and every OS/browser behavior
below WebHID. This audit does not turn static presence into supported-device
claims.
