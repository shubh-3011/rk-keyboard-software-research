# RK firmware selector PE families: static audit — 2026-10-20

## Scope and method

This pass deepens the dated firmware-selector inventory for the 117 vendor
artifacts with locally acquired bytes. The reproducible scanner is
[`audit_rk_firmware_pe_families.py`](../scripts/audit_rk_firmware_pe_families.py).
It verifies each local SHA-256 against the earlier inventory, clusters exact
package duplicates, parses PE imports and resource leaves, scans selected
resource and section strings, fingerprints executable sections, and reads the
first fields of appended overlays. The scanner compares executable-section
hashes with the eight S98 package hashes already covered in
[`rk-s98-firmware-updater-static-audit-2026-10-19.md`](rk-s98-firmware-updater-static-audit-2026-10-19.md).

All inspection is static. The script did not launch any package, unpack an
archive, decode or extract an updater payload, open HID, contact a keyboard, or
write firmware. String hits and linear-sweep comparison instructions are
candidates, not proof of execution or reachability.

## Exact package families

All 117 acquired files resolve locally and match their inventory SHA-256.
They represent 114 distinct whole-file hashes. Three duplicate groups are
byte-identical despite different selector records:

| Selector records | SHA-256 |
| --- | --- |
| C84 USB and C96 USB `.bin` | `8255ecd13ff22e6aff540cfb6bcc9bd7c5afac6f42657aeb0b8b72b93c50b3b9` |
| C60 USB and C61 USB `.bin` | `fd51d8591e729ae81190bdda2012fd5f409be6322fa8a776ebd6671e6d5ad72d` |
| R98 PRO Tri mode and RK98 Pro Tri mode `.exe` | `730bdbd29e15563554541f3039ec17f70689f3a17efe6eb7a98d9b36aa1a1e65` |

These duplicate hashes establish identical bytes, not cross-model compatibility.

Of the 114 whole-file families, 99 are PE packages. Their executable-section
bytes form 16 distinct fingerprints. Two fingerprints exactly match S98's
already-audited executable sections. One of those profiles covers 74 PE file
hashes across many selector models; the second covers six. The packages in
these two clusters also share their import and resource fingerprints within
each cluster. The 74-package profile has 606 imported API rows and the same
executable-section bytes as the common S98 build. This is strong evidence of
reused updater code across many listed model/PID packages. It does not establish
that all models accept the same firmware image: their appended payloads and
header PIDs differ.

The other 19 PE hashes do not match either S98 executable-section profile.
They include separate updater families with 606–661 imports, one RK68 package
with 607 imports and a SINO overlay, two RK68 HE packages with 25 imports and
multi-megabyte opaque overlays, and eight PE files carrying a CLR header and a
single `mscoree.dll` import. These are different static package shapes; their
full behavior and payload handling remain open.

## Appended SINO overlay and selector PID evidence

Eighty-one of the 99 PE hashes have an appended `5A A5 SINO` marker and a
header that agrees with the recorded length: 80 contain a declared 61,440-byte
payload followed by four bytes, and one contains a declared 47,104-byte payload
followed by four bytes. The ledger records SHA-256 digests of the complete
overlay and payload region without including the bytes.

The overlay VID field is `0x258A` in all 81 cases. After parsing only valid
four-digit hexadecimal selector PIDs, 72 overlay PIDs match the selector row,
five do not, and four have no comparable selector PID in the inventory. The
five mismatches are:

| File | Selector PID | Overlay PID |
| --- | --- | --- |
| `20260701124952_3749.exe` / `20260701125829_7813.exe` (R98 PRO / RK98 Pro records; same file hash) | `01FF`, `0212` | `0210` |
| `20260701132000_5719.exe` (RK61) | `00EC` | `0065` |
| `20260701123102_8953.exe` (N99) | `01BB` | `01B8` |
| `20260701132032_1329.exe` (RK61) | `0065` | `00EC` |
| `20260701115119_9538.exe` (M70) | `0203` | `029A` |

The four incomparable records are L75 (`01ES`, not valid hexadecimal), two S70
records with blank selector PID, and F99 with a blank selector PID. This is a
metadata-to-overlay discrepancy ledger, not proof which side is authoritative.
The 18 PE hashes without a decodable SINO header include packages with no
appended bytes and packages with large opaque overlays; those formats were not
unpacked.

The model-gate CSV also records 506 x86 linear-sweep `cmp` immediate candidates
across native PE section profiles. Function boundaries, data/code separation,
and reachability were not established, so these values are search leads rather
than verified PID checks. The eight CLR images are explicitly marked as not
subjected to the native x86 scan.

## Imports, resources, and UI strings

The import ledger contains 4,377 normal/delay import rows, one representative
per executable-section fingerprint. The dominant updater profile imports
`HID.DLL` and `SETUPAPI.dll` alongside the Windows UI/runtime libraries; the
complete per-family symbol rows are in the import ledger. Import presence alone
does not reveal the call graph, read/write sequence, or device behavior.

The resource ledger contains 6,805 resource leaves across the 99 PE hashes,
including 99 version resources, 91 manifests, 487 dialogs, and 1,278 string
table leaves. The semantic string-candidate CSV records source section or
resource, source SHA-256, encoding, text, and lexical tags. Captions and messages
include `Update Tool V2.0`, `Firmware Path:`, `Code Version:`, and `Serial
number`. Some packages also contain strings such as `Failed to write to hid
device`, `App device jump to bootloader mode`, and `Read firmware from device
into <file>`. Static strings identify intended UI/error vocabulary; they do not
prove that a branch is reachable or that the message is shown at runtime.

## Reproducible ledgers

- [Whole-file duplicate-hash families](rk-firmware-package-hash-families-2026-10-20.csv)
- [PE package identity, imports/resources fingerprints, and overlay fields](rk-firmware-pe-package-detail-2026-10-20.csv)
- [Executable-section byte families and S98 comparison](rk-firmware-pe-code-families-2026-10-20.csv)
- [Normal and delayed imported API rows by executable-section family](rk-firmware-pe-import-family-api-ledger-2026-10-20.csv)
- [Resource leaf names, languages, sizes, and SHA-256](rk-firmware-pe-resource-ledger-2026-10-20.csv)
- [Lexically selected semantic string candidates](rk-firmware-pe-semantic-string-candidates-2026-10-20.csv)
- [Unvalidated model/PID comparison candidates](rk-firmware-pe-model-gate-candidates-2026-10-20.csv)
- [Regeneration script](../scripts/audit_rk_firmware_pe_families.py)

## Remaining limits

This pass does not close per-family entrypoint-to-HID call graphs, managed CLR
methods, the several non-SINO payload containers, RK68 HE overlay contents, or
the five selector/overlay PID discrepancies. The S98 transform analysis cannot
automatically be generalized to packages with different executable-section
hashes, overlays, or archive wrappers. The 117-file set is the acquired portion
of one dated public firmware selector, not a census of every RK model, retired
release, regional download, or RK companion application. This is package-family
analysis only; it is not a complete reverse engineering of the whole RK
software suite and does not yet implement a clone.
