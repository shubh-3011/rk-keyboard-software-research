# RK S98 Tri-mode RGB updater: static audit — 2026-10-19

## Scope and method

This audit covers all eight firmware EXEs currently listed by the public RK
selector for S98 / Tri mode / RGB. The packages were downloaded to the local
research directory, SHA-256 pinned, and inspected as PE resources and x86 code.
No updater was launched and no HID interface was opened. The packages and
firmware bytes are not redistributed here.

[`audit_s98_firmware_packages.py`](../scripts/audit_s98_firmware_packages.py)
regenerates the package, section, import, callsite, syscall-candidate, and
dialog-resource CSVs from the downloaded EXEs and the dated selector snapshot.
It scans executable sections linearly. Its imported-call and syscall rows are
candidates, not validated control-flow edges; many rows fall inside statically
linked framework code and require function-boundary/reachability work. The
import ledger records the PE imports exactly. The per-package manifest records
hashes, PE metadata, overlay layout, and selector linkage without including the
vendor binaries.

## Package variants and identity

All eight packages are unsigned PE32 x86 files, 2,140,176 bytes each, with
fixed file/product version 1.0.0.1 and a `requireAdministrator` manifest. They
contain 606 normal/delay import rows each. Seven packages share the same
executable section hashes; the Thai PID `0x0223` is a distinct build with
different section hashes. Its marker parser and transform routines are still
present at shifted addresses and follow the same field order and block
transform in the sampled disassembly.

The selector-to-package mapping is:

| Selector language | Header VID | Header PID | Package SHA-256 |
| --- | --- | --- | --- |
| English-US | `0x258A` | `0x01AF` | `c64c781f3a020254f53f663d776d4100bb010b26529d9e908cc2426529ac4adf` |
| English-UK | `0x258A` | `0x01BF` | `475e8d7b97adfbd861c3b7b16721ad598df04095b81228e381319b6be23129e6` |
| Thai | `0x258A` | `0x0223` | `399020b7b66fda67cc6c69ae81336d67024204cbc9e15ffabde26a2cccd072ca` |
| German | `0x258A` | `0x0224` | `a37213fa936351aa66246de65db6b4b08050273411973f3c8dfe895347ab5b9f` |
| Spanish | `0x258A` | `0x022B` | `29b1ee9a8bcc74912149537babdbeb7ab384ad813aceec7305f051e2f52c4c28` |
| Japanese | `0x258A` | `0x022F` | `aec09f3cd68dc858104cc8837c6f6299d131e5037b079ff94a7e63aa056d152d` |
| Russian | `0x258A` | `0x0230` | `128c6463a4c575d31656becb918de7be4c3ede3f9241d07684bd0ae386864607` |
| Traditional Chinese | `0x258A` | `0x023F` | `8e2e74621d9effd916856d96ff75e752702be355c4ba40bcccf978339f3a3298` |

Each file has a 61,456-byte overlay beginning at file offset `0x1FB800`.
All eight header PIDs agree with the selector's language-specific PID. The
complete hashes, URLs, timestamps, resource counts, section hashes, and
per-file overlay digests are in the linked ledgers below.

## Firmware container and transform

The program obtains a module path, opens a stream for that file, and scans it
byte-by-byte for the eight-byte marker `5A A5 53 49 4E 4F` (`5A A5 SINO`). In
the 01BF build, the marker parser begins near VA `0x00406CC0`; the Thai build's
corresponding scan begins near `0x00406B10`. The parser reads the following
fields as big-endian integers:

| Overlay-relative offset | Size | Meaning supported by code |
| --- | --- | --- |
| `0x00` | 2 | Prefix `5A A5` |
| `0x02` | 4 | Literal `SINO` |
| `0x06` | 2 | USB VID; stored as `0x258A` |
| `0x08` | 2 | USB PID; varies by language |
| `0x0A` | 2 | Ciphertext byte count; `0xF000` (61,440) in these packages |
| `0x0C` | 61,440 | Transformed firmware payload bytes |
| `0xF00C` | 4 | Trailer key bytes consumed after the payload |

The offset-12 bytes are payload data; a preliminary interpretation of them as a
header key was wrong. The parser reads the key from the final four bytes. The
overlay length agrees exactly with `12 + 0xF000 + 4`.

The code at VA `0x00403B30` in the common build (approximately `0x00403970`
in the Thai build) converts the payload into 8-byte blocks, applies a 32-round
XTEA-style subtractive transform using the four trailer bytes, then writes the
result back into the buffer. Its round constants and byte ordering are
recovered from the instructions. This is a static transform description, not
proof that the resulting bytes are a complete, directly usable MCU image. An
exploratory offline transform did not produce a recognizable image signature;
the payload's post-transform format and any additional packing remain open.
No decoded image is stored in this repository.

## Device matching and report paths

The device enumerator uses SetupAPI and HID descriptor/capability calls. In
the 01BF build, a candidate is opened with read/write access using `CreateFileW`
near VA `0x004087C0`; nearby code queries `HidD_GetAttributes`, preparsed data,
and `HidP_GetCaps`. The header VID/PID values are copied to the updater state
and compared against enumerated HID attributes. This statically establishes
the package's target descriptor pair, not successful discovery or device
compatibility at runtime.

The 01BF build imports HID and SetupAPI functions including
`HidD_GetAttributes`, `HidD_GetPreparsedData`, `HidP_GetCaps`,
`HidD_GetHidGuid`, `HidD_SetFeature`, and `HidD_GetFeature`. The inspected
report path includes:

- Feature writes that construct report prefixes `05 52`, `05 57`, `05 75`,
  and `05 72`, with some request fields copied from caller parameters.
- A feature read of `0x802` bytes and loops over `0x800`-byte payload blocks;
  code compares read data with the in-memory package payload.
- A separate transfer routine constructs 2,050-byte HID feature reports
  containing a two-byte report prefix and up to `0x800` bytes of data.
- A feature query at VA `0x0040923F` starts with prefix `05 72`. A nearby
  branch checks response byte `+2 == 0x61` and maps response byte `+5` into
  updater state. The field names and protocol meanings are unresolved.

These are static call paths and buffer shapes. The complete UI command-to-worker
graph, device response semantics, retries, progress behavior, accepted
firmware state, and exact flash-write lifecycle are not closed. Import-call
candidate totals must not be mistaken for executed API calls.

## UI resources

PE dialog resources show an MFC-style `Update Tool V2.0`. The main dialog
resource has 40 controls: an all-start and exit button, settings/info and
language/statistics buttons, refresh, firmware-path and code-version labels,
and 16 numbered slots. The settings resource has 65 controls, including VID,
PID, serial-number, sensor, firmware selection, and `Win1` through `Win16`
labels. A separate About dialog identifies version 2.0 and a 2020 copyright
line. Captions in the resource CSV are preserved as stored; they do not prove
which runtime branch each control reaches.

## Reproducible ledgers

- [Package hashes, selector mapping, and appended-container metadata](rk-s98-firmware-package-manifest-2026-10-19.csv)
- [PE section hashes for all eight files](rk-s98-firmware-section-hashes-2026-10-19.csv)
- [All imported APIs across the eight exact packages](rk-s98-firmware-native-api-imports-2026-10-19.csv)
- [Linear-sweep imported API call/tail-jump candidates for the two code builds](rk-s98-firmware-native-api-callsite-candidates-2026-10-19.csv)
- [Decoded `sysenter` / `int 0x2e` instruction candidates](rk-s98-firmware-native-syscall-candidates-2026-10-19.csv)
- [Dialog templates and resource controls](rk-s98-firmware-dialog-resources-2026-10-19.csv)
- [Regeneration script](../scripts/audit_s98_firmware_packages.py)

The scanner found no decoded `sysenter` or `int 0x2e` candidates in the two
distinct executable-section builds. This says nothing about Windows kernel,
HID-class-driver, or other operating-system behavior.

## Remaining gaps

- Resolve function boundaries and the MFC message map to link every visible
  button to its worker, API calls, and state updates.
- Explain the post-transform firmware format and validate the transform against
  independent known-good package/output evidence.
- Resolve every HID request/response field, all model and revision gates, and
  the complete transfer/retry/cancel/error state machine.
- Acquire and analyze the other public firmware packages, QMK downloads, and
  product-specific app families before making any whole-suite claim.
- Keep reconstruction work separate until the package/version inventory and
  protocol gaps have been reduced; this audit does not certify a firmware
  writer or a complete RK clone.
