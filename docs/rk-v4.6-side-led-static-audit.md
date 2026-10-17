# RK DeviceDriver 4.6 Side LED static audit

## Scope and method

This note follows the Side LED profile, UI, and report-writing references in
the 4.6 `DeviceDriver.exe` only. Evidence comes from offline `objdump`
disassembly of the package binary (SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`), the
existing extracted profile snapshot represented by `models-4.6.json`, and
files in the local 4.6 package extraction. The executable was not launched;
no keyboard, HID, serial, or other device interface was opened. Proprietary
image files are not reproduced here; their paths, sizes, and hashes are given
only as evidence identifiers.

Addresses below are preferred-base VAs (`ImageBase = 0x00400000`). “Proven”
means directly visible from static bytes or extracted package contents; it
does not imply runtime execution or firmware acceptance.

## Proven

### Profile configuration and model records

At `0x00455D38`, the binary passes the UTF-16 key `ShowSideLED` to its
profile-string helper and stores the returned byte at `0x0062A2C8`. A false
value branches past the remaining Side LED reads. The enabled path reads
`DefSideLedIndex` at `0x00455D5A`, `SideBri` at `0x00455D73`, and `SideSpeed`
at `0x00455D96`. The loop formats `SideLedOpt%d` at `0x00455DF7`, reads each
value using the same profile section, and passes the resulting string to the
parser at `0x00450740`; the parsed six-byte option data is placed in a
repeating in-memory record. The code directly establishes the keys, gating,
and data flow. The meanings of the six fields are not named in the binary.

The 4.6 model snapshot contains 265 profiles. Two have `ShowSideLED=1`:

| Profile code | Catalog name | Default index | Side option records |
| --- | --- | ---: | ---: |
| `02B4` | K71R Pro | 1 | 5 |
| `0258` | RK K99 | 3 | 10 |

The extracted `Dev/02B4/KB.ini` and `Dev/0258/KB.ini` agree with these
catalog values. This identifies two feature-enabled profiles in this package
snapshot; it does not prove that these are the only compatible physical
keyboards or that the feature is available in every connection mode.

### UI construction and local resources

The executable contains the `CSideLedDlg` class and its RTTI name. In the
parent UI construction path, `0x0045A2AF` tests `ShowSideLED`; the enabled
branch allocates `0x1DD8` bytes, calls constructor `0x0045D150`, and invokes
the new object's virtual slot at `+0x13C`, passing `0x67` and the parent
window. The class accessor at `0x0045D4C0` returns a message-map descriptor
address. Its initialization-like method at `0x0045D4D0` calls a base method,
then `0x0045E640`, and returns true. Those addresses establish a gated
Side-LED dialog object and an initialization path; exact MFC event semantics
are discussed under unresolved evidence.

`0x0045E020` formats `tc_side_led%d` using a one-based counter, walks a
pointer table beginning at `0x00647780`, and creates UI text/control objects.
The packaged `Dev/02B4/SideLed/en/led.xml` supplies the title “Side light
effect” and five labels: “Turn off”, “Streaming light”, “Neon”, “Breath”,
and “Always on”. Japanese, simplified Chinese, and traditional Chinese
folders are also present under `Dev/02B4/SideLed`. These labels align by
number with `SideLedOpt1` through `SideLedOpt5`; the exact binding between
each displayed label and each option record has not been proven beyond that
numbered correspondence.

At `0x0045E0B3`, the Side LED UI path passes a format string beginning at
`0x005E1140` to the path-building helper. The full string is
`%sDev\\%04X\\SideLed\\%s\\led.xml`; it selects a model-specific,
locale-specific XML path. This is a direct code reference missed by the
earlier raw-address scan described in
[`rk-v4.6-native-api-call-path-audit.md`](rk-v4.6-native-api-call-path-audit.md).
The string begins two bytes earlier at `0x005E113E` with a UTF-16 `^`
prefix, which explains the offset difference.

At `0x0045E6BD`, a separate format string builds
`%sDev\\%04X\\sideled.png`. The `Dev/02B4/sideled.png` package file is 91,852
bytes (SHA-256 `dc8b58f2a84217b386c42fb6f6fa0bf7f24accc6ce13bb079a47727064a86320`).
The binary also references global skin files `sideled_nr.png` and
`sideled_ov.png` from `0x0045BBD3` and `0x0045C3B1`/`0x0045C3C8`. They are
991 bytes (SHA-256
`046e82127dedd3baf9863d6c9b4a49f10cc7d4527479e2901f25a2838ef5b4f0`) and
997 bytes (SHA-256
`861fe9de0f189f99853db687c186614812507df39fd36928afc3893d366cdb5f`),
respectively. These references establish resource lookup and skin usage, not
the complete rendered layout.

The `0258` profile directory has no `SideLed` localization folder or
`sideled.png` in this extracted package, despite its enabled profile keys.
Whether it uses a fallback, a shared resource, or an incomplete package is
unresolved.

### Configuration-to-report-to-HID writer path

The report builder at `0x00412060` is called at `0x00412D0D` with a report
buffer. Within it, `0x004122D7` checks the parsed `ShowSideLED` flag. For flag
value 1, it selects the profile's current side-option record and copies four
bytes into report-buffer offsets `+0x28` through `+0x2B` (`0x00412300` to
`0x00412329`). This proves that the side-option selection affects a
serialized in-memory record; the field names and byte semantics remain
unknown. A second internal value branch also writes Side LED-related bytes
into another record shape at offsets including `+0x28` and `+0x49`.

After `0x00412D0D` returns, the caller iterates its selected report records
and calls `0x00410290` at `0x00412D54`, passing the record buffer pointer and
index. The helper reaches `0x0040FFD0` at `0x0041030B`. That routine builds a
`0x208`-byte feature packet and calls the `HidD_SetFeature` thunk at
`0x00590A08` from `0x0041014F`; the import is at IAT VA `0x005A61E0`. Thus
static control flow links the report builder that contains the Side LED
fields to a generic HID feature-report writer. It does not identify a
Side-LED-specific report ID, prove the exact on-wire byte layout, or prove
that any physical keyboard accepts the packet.

## Inferred

- `0x0045D4D0` is likely the Side LED dialog's initialization override: it
  calls a base routine, invokes a feature-specific initializer, and returns a
  success-like value.
- The `tc_side_led%d` loop, localized `led.xml`, model image path, and global
  normal/hover skin references likely populate the visible Side LED selector
  and its illustration.
- `SideBri` and `SideSpeed` are configuration values associated with
  brightness and speed by their names, but this audit does not establish
  whether they are numeric limits, report values, or control identifiers.
- The report builder likely emits a selected Side LED setting when the
  profile enables the feature. The static call chain supports this inference;
  the exact command encoding and device-side behavior are not established.

## Unresolved

- The follow-up
  [`rk-v4.6-side-led-message-map-follow-up.md`](rk-v4.6-side-led-message-map-follow-up.md)
  decodes the ten MFC message entries and traces selection-like callbacks into
  the shared Side LED state records. The symbolic meaning of the custom
  messages remains unresolved, and no direct callback-to-report-builder call
  was recovered; a specific user action still cannot be tied to a particular
  HID write.
- The six comma-separated fields in each `SideLedOptN` record are not
  semantically labeled. The report byte offsets are known, but protocol field
  meanings, report IDs, checksums, and firmware interpretation are not.
- Runtime model detection, transport selection, compatibility checks, and
  actual keyboard responses were not tested. No device access was performed.
- The absent `0258` Side LED assets/localization need more package evidence
  before calling that model's feature complete or broken.
- UI geometry and final image composition were not reconstructed from
  proprietary assets; this report intentionally records hashes and paths only.

## Evidence sources

- `models-4.6.json` in the repository: extracted 4.6 profile/model catalog.
- Local extraction, not copied into the repository:
  `.research/rk4_6_official_extract_20261015/app/Dev/02B4/KB.ini`,
  `Dev/0258/KB.ini`, `Dev/02B4/SideLed/en/led.xml`, and the image paths listed
  above.
- `DeviceDriver.exe`, SHA-256 pinned above; inspected offline with GNU
  `objdump -d -Mintel` at the cited VAs.
