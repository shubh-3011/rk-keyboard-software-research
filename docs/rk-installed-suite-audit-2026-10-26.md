# Installed RK suite: verified baseline and reconstruction handoff

## Outcome and boundary

On **2026-10-26**, a fresh offline pass verified **all 810 installed files
(78,070,176 bytes)** against the saved installed-package manifest. It independently
recounted all **14 file groups**, checked all **22 localization XML files**, joined
**188 named profiles / 189 KB.ini files** to the catalog, and freshly parsed
**1,918 ordinary/delay import identities** from all **five installed PE files**.
REA 6.7.0 inspected all five resource trees: **206 resource payloads** were
individually checked against their original file ranges and SHA-256 hashes.

This is **complete membership/inventory coverage of that finite installation**,
not complete code recovery, UI parity, device support, or a runtime trace.
No vendor executable was launched; no HID/serial interface, updater, bootloader,
or firmware writer was used in this pass. The reported lag has **not** been
measured or attributed to a specific cause.

The installed baseline is identified by `Cfg.ini Ver=0x406` and byte hashes,
not solely by the Windows uninstall display version. The separately extracted
4.6-labeled installer is a different snapshot. Its **265** named profiles must
not be silently substituted for the installed **188**.

## New reproducible deliverables

- [Machine-readable verification summary](installed-suite-audit-2026-10-26/summary.json):
  input-ledger hashes, counts, locale parse status, binary identities, REA
  Evidence IDs, coverage and limitations.
- [Every installed file and its group](installed-suite-audit-2026-10-26/files.csv):
  810 exact relative paths, sizes and hashes; no vendor file contents.
- [Every installed static native import](installed-suite-audit-2026-10-26/imports.csv):
  1,918 rows, binary hash, ordinary/delay kind, DLL, symbol, IAT RVA and prior
  static-reference lists. Import identities are freshly parsed; instruction
  callsite lists are **reused from the hash-recorded prior ledger**, not a new
  disassembly or observed call count.
- [Complete REA resource Evidence](installed-suite-audit-2026-10-26/rea/): five
  original JSON records, keyed by subject hash. These contain structural
  metadata, locations and hashes, **not extracted proprietary payloads**.
  `.gitattributes` disables line-ending conversion for these records so their
  recorded byte-level hashes survive Git checkout.
- [Verifier](../scripts/audit_installed_suite.py) and
  [synthetic regression tests](../tests/test_installed_suite_audit.py).

The verifier fails on changed/missing/extra files, duplicate ledger identities,
unclassified paths, unexpected XML defects, catalog membership differences,
import-identity differences, incomplete REA resource results, and invalid
resource ranges or digests. Raw installed files are never edited. It checks
profile identity/membership, not the meaning of every profile tuple.

## Every installed file group

Fresh counts and byte totals match the existing
[14-group resource ledger](rk-resource-group-inventory.csv) exactly:

- Root app/config/installer files: **7 files, 4,275,764 bytes**.
- Fonts: **4 files, 883,684 bytes**.
- Skins/UI chrome: **96 files, 2,225,168 bytes**.
- Main UI localization: **7 files, 150,532 bytes**.
- Global ET patterns: **74 files, 22,956 bytes**.
- Per-profile configurations: **189 files, 1,013,544 bytes**.
- Keyboard artwork: **204 files, 64,042,805 bytes**.
- Screen GIF samples: **2 files, 3,050,220 bytes**.
- Firmware package: **1 file, 193,652 bytes**.
- Profile-local updater: **1 file, 2,109,952 bytes**.
- Generic LED dictionaries: **5 files, 21,110 bytes**.
- Profile-local LED dictionaries: **10 files, 8,558 bytes**.
- Per-profile ET/Cartoon data: **198 files, 68,360 bytes**.
- Global Cartoon data: **12 files, 3,871 bytes**.

Artwork and animations account for substantial package bytes, but byte size
does not establish the cause of lag. Asset loading/fallback paths are mapped
in the [skin loader report](rk-skin-loader-static-followup.md). `mak.skn`
still has no identified direct consumer or decoded format; see its
[bounded package scan](rk-mak-skn-package-scan-followup.md).

## Localization, model profiles and UI workflows

### Locales and profile data

All seven UI locales (`en`, `Japanese`, `Korean`, `Russian`, `sc`, `Turkish`,
`tw`) contain **247 intended leaf keys** each. Japanese `text.xml` remains
malformed: `/tc_screen1>` is missing `<`. Counts for that file use only the
documented in-memory normalization; the installed bytes remain unchanged.
Five generic LED dictionaries and ten profile-local LED dictionaries complete
the 22-file XML inventory. See the [key matrix](rk-localization-key-matrix.csv)
and [localization audit](rk-resource-localization-audit.md).

All named profile codes and names are rejoined to `Cfg.ini`; `01C7` is the
one unregistered `KB.ini`. The installed static family ledger has **125 RKKB**
and **63 G5** direct-profile routes. The companion/wireless 3632 route is not
represented by those direct-profile totals. Profile source tuples, including
extra/empty cells and nondrawable rows, remain in [models.json](../models.json).
See the [schema](rk-profile-schema-audit.md),
[tuple semantics](rk-profile-tuple-semantics.md),
[family rows](rk-profile-driver-family-map.csv), and
[wireless signature dataflow](rk-wireless-profile-psd-static-dataflow-audit.md).
Neither duplicate layouts nor VID/PID aliases prove physical compatibility.

### Workflow checklist and remaining parity gates

Each item below links to identifiable static paths, rather than treating a
translated caption as a working control:

1. **Startup, discovery and hotplug:** SetupAPI/HID interface discovery,
   attributes/caps and rescan timers are mapped in the
   [discovery audit](rk-device-enumeration-notification-audit.md). Successful
   physical identification and exact revision gates remain unvalidated.
2. **Main Apply and key picker Apply:** distinct controls share `tc_apply`.
   One updates state/signals a worker; the picker ends a modal interaction and
   commits mapping data. See the [control crosswalk](rk-ui-control-command-crosswalk.md)
   and [active-profile dispatch](rk-406-active-profile-apply-dispatch-follow-up.md).
   Full rendered-key → selected action → accepted hardware write is incomplete.
3. **Key/Fn/layer mappings:** parser and selected serializer relations are in
   the [UI/serializer path](rk-keymap-ui-path-audit.md) and
   [translation audit](rk-keymap-translation-audit.md). Full action enums,
   matrix meaning, physical revisions and every picker route remain open.
4. **Lighting/effects:** locale/profile candidate generation and masks are in
   the [LED candidate audit](rk-led-control-candidates-4.06.md),
   [tree-selection follow-up](rk-406-led-0594-tree-control-row-token-followup.md),
   and [RGB payload audit](rk-rgb-lighting-color-payload-audit.md).
   Candidate rows are not independently numbered child controls. Complete
   label/value → payload → physical-effect mappings are not established.
5. **Brightness/speed/color:** profile records and serializers are partially
   linked; the UI-to-brightness-record writer remains unresolved. See the
   [brightness boundary](rk-406-brightness-handler-field-boundary.md).
6. **Macro create/import/export/edit/record:** the
   [format audit](rk-macro-format-and-path-audit.md) documents `0x342`-byte
   records and the two-bit rotation used for `.mck` persistence. The
   [capture audit](rk-macro-capture-path-audit.md) and
   [localized numeric-edit audit](rk-ui-localized-action-audit.md) retain gaps
   in recording, label bindings, event semantics and playback.
7. **Audio-reactive effects:** WASAPI capture, processing and conditional
   output paths are in the [audio path audit](rk-audio-reactive-path-audit.md)
   and [UI lifecycle follow-up](rk-audio-ui-control-followup.md). All control
   bindings, effect parameters and physical outputs are not recovered.
8. **Screen/GIF import/preview/save/transfer:** New/Import/Apply and selected
   list/worker paths are mapped in the
   [screen UI trace](rk-406-screen-ui-to-worker-modal-follow-up.md),
   [image conversion](rk-screen-image-conversion-path-audit.md), and
   [payload audit](rk-screen-gif-payload-audit.md). Full decoding/preview/worker
   linkage and hardware acceptance remain incomplete in this installed build.
9. **Language and general preferences:** locale reload/host persistence,
   startup and settings paths are in the
   [general settings audit](rk-general-settings-ui-persistence-audit.md).
   Label-to-child bindings and actual runtime config selection remain partial.
10. **Tray/configuration/exit:** `0x6400`/`0x6401` and tray double-click are
    mapped in the [tray audit](rk-tray-icon-menu-workflow-audit.md). The
    language popup command route remains unresolved; menu construction alone
    is not proof that locale switching executes.
11. **Reset, periodic system state and shutdown:** see the
    [reset/system-worker audit](rk-reset-and-system-parameter-path-audit.md).
    Worker exit, pending-write ordering and model effects need verification.
12. **Software update, firmware update, installation/uninstallation:** these
    are separate workflows, detailed below; none is enabled in the rebuild.

Newer 4.6-only knob, Side LED, text macro and screen paths are separately
indexed in [COVERAGE.md](../COVERAGE.md). They cannot be treated as installed
4.06 features solely because the two packages share a product name.

## Static native API boundaries and identifiable call paths

The fresh import identities exactly match the saved IAT ledger:

- `DeviceDriver.exe`: **672 ordinary + 3 delay imports**, **61 resources**.
- `Dev/01AF/Update.exe`: **618 ordinary imports**, **60 resources**.
- `InitSetup.dll`: **76 ordinary imports**, **2 resources**.
- `uninstall.dll`: **30 ordinary imports**, **11 resources**.
- `unins000.exe`: **519 ordinary imports**, **72 resources**.

The new summary contains every binary's full SHA-256 and REA Evidence ID.
For example, the main driver's resource evidence is
`ev_4ec8eb22b33b06bfb3596bae7c656d07df096cc97125cdf6beaac60a69835009`.
REA's **complete** flag applies to resource-tree inventory only. Non-icon
payloads remain opaque; this is not decompilation or proof of actual rendering.

The exhaustive import ledger is distinct from a call graph. Start with the
[system API crosswalk](rk-system-api-crosswalk.md), then follow:

- Device enumeration/notifications → SetupAPI, `CreateFileW`, HID metadata:
  [enumeration audit](rk-device-enumeration-notification-audit.md).
- UI events/dirty flags → semaphore worker → family virtual dispatch:
  [UI event paths](rk-ui-event-worker-path-audit.md) and
  [Apply worker](rk-settings-apply-worker-audit.md).
- Family state → key/macro/lighting/color serializers → HID/file transport:
  [settings serializers](rk-setting-serializer-audit.md).
- Loader APIs → statically identifiable module/export strings and consumers:
  [dynamic resolution](rk-dynamic-api-resolution-audit.md) and
  [remaining consumer gaps](rk-dynamic-api-consumer-gap-audit.md).
- Indirect imports/data reads → selected invocation paths:
  [indirect audit](rk-native-api-indirect-call-audit.md),
  [main-driver revalidation](rk-406-native-api-gap-revalidation-follow-up.md),
  [helper reconciliation](rk-installer-helper-no-direct-call-import-followup.md),
  [updater reconciliation](rk-updater-native-import-gap-reconciliation.md).
- Raw syscall-like bytes → instruction/data boundary classification:
  [4.06 byte audit](rk-406-system-call-byte-audit.md). Byte matches are not
  syscalls; imported Win32 calls are not kernel syscall traces.

Unresolved indirect calls, callbacks, dynamically chosen APIs and runtime
arguments remain explicit gaps. These references do not establish every call
that Windows, a device driver, or the vendor process could make.

## Device-family protocol reconstruction boundary

These framing facts come from existing hash-pinned static analyses, not from
sending reports during this pass:

- **RKKB:** `FUN_00413220` emits a 65-byte feature report, report ID `10`,
  with up to 62 payload bytes per chunk. Separate Apply paths use LED prefix
  `02 29`, per-key-color `03 7E`, matrix `01 F8` and macro staging `04 00`.
  See [serializer audit](rk-setting-serializer-audit.md). This is not a
  complete field schema or authorization to replay those commands.
- **G5:** `FUN_0040F700` uses a 520-byte feature report with up to 512 payload
  bytes. Identified routes include key/layers (`3`), macro (`5`), LED (`4`),
  color groups (`6`) and RGB-index (`10`). Query-style routes can send
  `HidD_SetFeature` before `HidD_GetFeature`; they are not passive reads.
- **3632:** `FUN_0040D7E0` constructs a 20-byte frame: marker `0x13`, command,
  total chunk count, packet index, option/length nibble field, up to 14 data
  bytes, and low-byte additive request checksum. The receiver does not
  establish an equivalent checksum verification. Ordinary responses are
  queued separately from byte-1 `0x0A` status records. See the
  [framing/response audit](rk-3632-response-semantics-audit.md).

Full field-level schemas, valid ranges, revision-specific model gates, retry
semantics, nonmutating identification and hardware acceptance are incomplete.
The [firmware readback report](rk-firmware-readback-audit.md) does **not**
establish a complete safe keyboard-firmware export path.

## Network, software updater, firmware updater and installer

The installed main app's software-update worker reads optional `OPT/UpdateURL`
and `NoUpdate`. Static fallbacks are the HTTP `www.rkgaming.com/Work/Update-RGB/`
and `Update-Single/` bases plus `update_version.xml?timestamp=%x`.
Cache deletion and `URLDownloadToFileW` paths are mapped; manifest-driven
payload URLs depend on runtime data. The optional helper path
`Other/<VID>_<PID>/start.exe` is not an included helper implementation.
See [host update/install paths](rk-host-update-install-path-audit.md).
No update URL was fetched in this pass. These literals do not prove the
current server contents, an exhaustive network API surface, or absence of
other runtime traffic. There is no new live traffic capture.

The separate `Dev/01AF/Update.exe` contains mapped resource-ID-to-handler
routes, including command `0x0419` (one-click update), browse, BLE version,
pairing checkbox and VID/PID edit enablement. See the
[control crosswalk](rk-ui-control-command-crosswalk.md),
[one-click path](rk-updater-command-0419-static-path-audit.md),
[UART state machine](rk-updater-uart-state-machine.md), and
[UART file-sink boundary](rk-uart-file-sink-reachability-audit.md).
The mode-3 HID route has further static
[preflight](rk-v4.6-update-mode3-hid-preflight-audit.md) and
[transfer-worker](rk-v4.6-mode3-status-to-transfer-worker-followup.md) findings
that apply to the byte-identical updater shared with the other package.
The bundled `.upf` is not a validated device backup and has documented
[section-length/transform anomalies](rk-upf-section-transform-and-length-boundary-audit.md).
No updater or firmware routine should be enabled from these facts alone.

`InitSetup.dll`, `uninstall.dll`, `unins000.exe` and `unins000.dat` remain part
of the installed inventory. Their import identities do not establish installer
call arguments or actual uninstall effects. See the
[installer/uninstaller audit](rk-installer-uninstaller-script-audit.md).
The later separately acquired installer's
[compiled callback recovery](rk-v4.6-inno-installer-callback-recovery-2026-10-20.md)
must retain its own package provenance.

## Open-source reconstruction: what exists and what is next

The native [WPF rebuild](../rebuild/windows/README.md) and companion
[Keydeck project](https://github.com/shubh-3011/keydeck-rk-studio) are already
source-available under their repository licenses. They are local draft tools,
not full RK replacements. The native app uses PnP metadata, catalogs, local
key-label/macro drafts, tray and opt-in startup. Keydeck has richer local
keymap, lighting, macro, advanced and screen drafts. **Neither applies those
settings to a keyboard.** This audit changes neither app's hardware behavior.

Vendor code/artwork/firmware cannot simply be relicensed by this project.
Independent code and factual interoperability metadata can be maintained
separately; preserve [provenance](../DATA-PROVENANCE.md) and local-only vendor
asset loading. Exact distributable UI parity needs project-owned assets or
appropriate rights, plus verified layout/event behavior.

Next parity work should close one bounded end-to-end workflow at a time:

1. Resolve the installed brightness UI → runtime value-write edge and the
   active-family serializer, without conflating label drawing with device I/O.
2. Produce pure offline per-family codecs with fixtures and strict bounds;
   identify unknown fields instead of inserting guessed defaults.
3. Port structured local macro editing to the native app with round-trip
   tests; do not label local drafts as keyboard-applied settings.
4. Only after explicit runtime/device-test authorization, verify exact
   model/revision/descriptor gates and one reversible operation with readback.
   Firmware/update/reset work remains separately gated.
5. Establish a repeatable latency/rendering baseline before claiming improved
   performance or matching the vendor UI pixel-for-pixel.

The [full-suite gap matrix](reverse-engineering-gap-matrix-2026-10-19.md) and
[rebuild roadmap](../REBUILD-ROADMAP.md) remain the broader task checklist.
This pass closes fresh finite-inventory verification, **not** their open
behavioral, protocol or runtime questions.

## Reproduce safely

Install the already-declared audit dependencies in your chosen environment.
For each of the five PE paths above, capture REA resource Evidence into a
dedicated local directory, for example:

```powershell
npx -y rea-agents@6.7.0 inspect-pe-resources `
  "C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe" --format json |
  Out-File -Encoding utf8 ".research\my-rea-resources\driver.json"
```

Repeat with the updater, setup helper, uninstall helper and uninstaller. Then
write the verification outputs to a **new** output directory:

```powershell
python scripts/audit_installed_suite.py `
  --rk-root "C:\Program Files (x86)\RK Keyboard Software" `
  --rea-evidence ".research\my-rea-resources" `
  --output ".research\my-suite-audit"
python -m unittest discover -s tests -v
```

For rechecking this exact snapshot, the committed `installed-suite-audit-2026-10-26/rea`
directory can also be supplied as `--rea-evidence`. REA MCP registration is
not required for this CLI route. Resource parsing needs no native decompiler;
native CFG/decompilation work needs its separate provider prerequisites.
