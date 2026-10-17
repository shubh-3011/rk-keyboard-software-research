# RK DeviceDriver.exe 4.6 versus installed 4.06: static native binary delta

## Scope and safety

This is an offline comparison of the `DeviceDriver.exe` in the locally supplied
`rk4_6_official_extract_20261015` application folder with the installed RK
Keyboard Software 4.06 `DeviceDriver.exe`. It covers this one PE file only; it
does not analyze the 4.6 updater, its other libraries, model profiles, installer,
or runtime behavior. Neither executable nor an updater was launched. No HID,
serial, Bluetooth, or other device interface was opened, and no keyboard data
was sent or changed.

**Evidence labels:** PE fields, import entries, resource bytes, section contents,
and file literals below are **proven statically** for these exact hashes.
Interpretations of feature strings are **inferred**. Whether any imported API,
UI path, or feature runs on a connected keyboard remains **unresolved**.

## Inputs and method

| Label used here | Input | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| “4.6-folder binary” | `C:\Users\shubh\Downloads\sshorcale\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe` | 2,418,176 | `8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9` |
| Installed 4.06 baseline | `C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe` | 2,326,528 | `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6` |

Python `pefile` 2024.8.26 read each PE header, ordinary and delay import
descriptors, section table, and resource tree. SHA-256 was computed over each
resource leaf and each section's raw bytes. ASCII and UTF-16LE printable
sequences were scanned from the file. Raw executable sections were scanned for
`0F 05`, `0F 34`, and `CD 2E` byte pairs. No decompilation or runtime trace of
the 4.6 binary was made in this pass.

The extracted binary's embedded `FileVersion` and `ProductVersion` are both
`1, 0, 6, 8`, the same values embedded in the installed 4.06 baseline. The
folder name suggests a 4.6 package, but the executable's version resource does
not establish that release label or authenticate the file's origin.

## PE header and section delta

Both files are 32-bit x86 Windows GUI PEs (`Machine=0x014c`, optional-header
`PE32=0x010b`, subsystem 2), image base `0x00400000`, OS and subsystem version
`5.0`, and have the same file characteristics (`0x0102`) and DLL
characteristics (`0x8140`). The 4.6-folder file reports PE timestamp
`0x6ac0632a`, entry RVA `0x001750db`, image size `0x00280000`, headers
`0x400`, and checksum `0x0025653c`. The 4.06 baseline reports timestamp
`0x682ef9ce`, entry RVA `0x0016d9b0`, image size `0x00263000`, headers `0x400`,
and checksum `0x00243328`.

All five section raw-byte hashes differ. Thus the files are not section-identical
builds, even where their metadata or visible features match.

| Section | 4.6-folder RVA / virtual size / raw size | 4.6-folder raw SHA-256 | 4.06 RVA / virtual size / raw size | 4.06 raw SHA-256 |
| --- | --- | --- | --- | --- |
| `.text` | `0x1000` / `0x1a4ae6` / `0x1a4c00` | `899e0a5c3cda384c912a4bfcb5484eb565d0a92c46c02a8adcdc8ce2c2f5c695` | `0x1000` / `0x19ce86` / `0x19d000` | `fbaf7f7eff19371e297853fb4ecb0b11ecd3f84f4a5222c4d3688c691d7cadef` |
| `.rdata` | `0x1a6000` / `0x6058a` / `0x60600` | `dbb7535a3a8db1ae7379950a7cd3757813318956a3129b245f1591860ad4a7bc` | `0x19e000` / `0x5ee06` / `0x5f000` | `f244cb01a8cc0d4a18bff31de40608289f21ce1f331236658549aac167195df1` |
| `.data` | `0x207000` / `0x41c38` / `0x13800` | `067f60d82a8e128f457282084ecf86f605335aa47ad0a67feda5e33ad63d13c7` | `0x1fd000` / `0x2fc58` / `0x6e00` | `5de6d41d258a6a5e2d856f20e67f89aa61248bd44d7a94dec4d98bd32d2a965b` |
| `.rsrc` | `0x249000` / `0x92e4` / `0x9400` | `f6d047a55e2f29d822a903ca340d5f0a555be500a365b95e2f8cd5703b597347` | `0x22d000` / `0x92e4` / `0x9400` | `486250242be00bda351b317ecdacf2079a24fd432736cb33d636689cae004dce` |
| `.reloc` | `0x253000` / `0x2c398` / `0x2c400` | `6d1ebe5624e8894edf4b4ea381d68fba6842330f09a124f4ccd6dc8da7f6c15a` | `0x237000` / `0x2b8d2` / `0x2ba00` | `f7688c872c66c939c3e8cc95525ef99309bf5ff2fe29efc16d99dff4110a739f` |

## Ordinary and delay imports

The 4.6-folder binary has **675 ordinary imports across the same 21 DLLs** as
the 4.06 baseline, plus the same **three delay imports from `oleacc.dll`**.
Counts by ordinary-import DLL are:

| DLL | Imports | DLL | Imports | DLL | Imports |
| --- | ---: | --- | ---: | --- | ---: |
| `advapi32.dll` | 14 | `comctl32.dll` | 2 | `comdlg32.dll` | 1 |
| `gdi32.dll` | 99 | `gdiplus.dll` | 68 | `hid.dll` | 9 |
| `imm32.dll` | 4 | `kernel32.dll` | 172 | `msimg32.dll` | 2 |
| `ole32.dll` | 32 | `oleaut32.dll` | 12 | `oledlg.dll` | 1 |
| `pdh.dll` | 6 | `setupapi.dll` | 4 | `shell32.dll` | 12 |
| `shlwapi.dll` | 8 | `urlmon.dll` | 1 | `user32.dll` | 219 |
| `wininet.dll` | 1 | `winmm.dll` | 5 | `winspool.drv` | 3 |

Against the exact 4.06 import set, the 4.6-folder binary adds four ordinary
entries and drops one:

- Added: `gdiplus.dll!GdipGetPropertyItem`,
  `gdiplus.dll!GdipGetPropertyItemSize`,
  `kernel32.dll!GetPrivateProfileStringA`, and `user32.dll!SendInput`.
- Removed: `gdi32.dll!AddFontResourceW`.

The unchanged delay imports are `oleacc.dll!AccessibleObjectFromWindow`,
`oleacc.dll!LresultFromObject`, and `oleacc.dll!CreateStdAccessibleObject`.
The complete 4.06 API-name inventory is in
[`rk-native-api-imports.md`](rk-native-api-imports.md); applying the exact
four-add/one-remove delta above reconstructs the 4.6-folder binary's imported
API-name set. These are declarations in the PE import table, not proof that an
API is called or a feature is reachable. No 4.6 IAT-call, dynamic-loader,
callback, or per-API control-flow crosswalk was produced here. Neither file
imports `ntdll.dll` or a named `Nt*`/`Zw*` function.

## Resources and high-signal literals

Both resource trees have **61 leaves with identical type, name/id, language,
size, and payload hash**. Counts by standard numeric resource type are: cursor
(1), 16; bitmap (2), 2; icon (3), 1; dialog (5), 10; string table (6), 14;
group cursor (12), 15; group icon (14), 1; version (16), 1; manifest (24), 1.
Thus, the visible binary delta is not a changed embedded dialog/string/icon
payload in this resource tree. The change is in the PE code/data sections and
file literals. Matching resource bytes do not prove identical runtime UI.

The 4.6-folder binary contains these high-signal printable strings not found in
the 4.06 executable scan (RVA locations are for the 4.6-folder image):

| Literal | Encoding | RVA |
| --- | --- | ---: |
| `CSideLedDlg` / `.?AVCSideLedDlg@@` | ASCII | `0x1e1008` / `0x21a4f8` |
| `.?AVCTextMacroBuffer@@` | ASCII | `0x21a198` |
| `ShowLED`, `ShowSideLED`, `ShowTextMacro` | UTF-16LE | `0x1df174`, `0x1dfaec`, `0x1df1b0` |
| `SideLedOpt%d`, `DefSideLedIndex` | UTF-16LE | `0x1dfb48`, `0x1dfb04` |
| `tc_side_led%d` | UTF-16LE | `0x1e117c` |
| `%sDev\%04X\SideLed\%s\led.xml` | UTF-16LE | `0x1e113e` |
| `%sDev\%04X\sideled.png` | UTF-16LE | `0x1e11b4` |
| `sideled_nr.png`, `sideled_ov.png` | UTF-16LE | `0x1e0c54`, `0x1e0e64` |
| `textmacro.dct` | UTF-16LE | `0x1d50f0` |

These strings and RTTI names are evidence that this image includes additional
Side LED and text-macro-related code/configuration references. They do not
prove the dialog is reachable, the associated assets are installed for a given
model, or that the keyboard firmware supports these features. The added
`SendInput` import is likewise only an import-table difference; its caller and
behavior were not traced. Other extracted string-set differences contain many
compiler/data-pattern artifacts and are not treated as feature changes here.

## Raw direct-system-call byte candidates

The 4.6-folder scan of executable `.text` bytes found:

| Pattern | Count | `.text` RVA candidates | Image VA candidates |
| --- | ---: | --- | --- |
| `0F 05` (`syscall` bytes) | 6 | `0x26049`, `0x6a474`, `0x6a5a4`, `0xc54cd`, `0xd018f`, `0xed924` | `0x426049`, `0x46a474`, `0x46a5a4`, `0x4c54cd`, `0x4d018f`, `0x4ed924` |
| `0F 34` (`sysenter` bytes) | 2 | `0x1197b0`, `0x182ebd` | `0x5197b0`, `0x582ebd` |
| `CD 2E` (`int 2e` bytes) | 0 | — | — |

These are raw byte matches, not system-call counts. The surrounding byte context
shows several matches inside x86 relative-call displacements (`E8 rel32`),
two `0F 05` matches in lookup-table-like data, and a `0F 05` overlap between
an `AND` immediate and an `ADD EAX,imm32` opcode. The second `0F 34` match
overlaps a byte-memory instruction's SIB/displacement fields. The remaining
candidates were not individually instruction-boundary or control-flow
validated in this pass. Therefore no direct syscall/sysenter instruction or
reachable native syscall wrapper is established here. This is consistent with
the 4.06 crosswalk's conclusion, but requires a separate 4.6 disassembly to
make a full instruction/reachability statement. The 4.06 baseline byte counts
and interpretation are documented in
[`rk-system-api-crosswalk.md`](rk-system-api-crosswalk.md) and
[`rk-native-syscall-byte-matches.csv`](rk-native-syscall-byte-matches.csv).

Representative exact 4.6-folder `.text` contexts are shown below. Each row
contains the listed candidate pair within the surrounding bytes; the pair is
not separately marked in the hex string:

| Pattern RVA | Surrounding bytes, hex |
| ---: | --- |
| `0x26049` | `e8 da 0f 05 00` |
| `0x6a474` | `0f 0f 0f 0f 0f 0f 0f 0f 0f 05 06 07` |
| `0x6a5a4` | `0f 0f 0f 0f 0f 0f 0f 0f 0f 05 06 07 08 09 0a 0b` |
| `0xc54cd` | `e8 0f 05 f4 ff` |
| `0xd018f` | `e8 f7 0f 05 00` |
| `0xed924` | `83 e0 0f 05 00 ea 00 00` |
| `0x1197b0` | `e8 0f 34 00 00` |
| `0x182ebd` | `88 54 0f 34 8b 0e` |

## What can be reused from 4.06 findings

**Portable only as leads, pending revalidation:** broad subsystem hypotheses
whose static evidence exists in both builds (HID/SetupAPI imports, MFC class
strings, common logs/config keys, and the same declared API names). The new
Side LED/text-macro strings are 4.6-specific leads. Feature names and common
imports can guide a 4.6 analysis, but do not independently confirm command
semantics.

**Not portable as 4.6 facts:** any 4.06 virtual address, IAT RVA, function
boundary, callsite, xref, dialog/message-map edge, branch condition, packet
field offset, serializer behavior, reachability claim, or device-family command
interpretation. The 4.6 file has a different hash; every section's raw content
and the section RVAs after `.text` have changed. In particular, an address such
as `0x004164b0` from the 4.06 HID enumeration report cannot be copied into the
4.6 image and treated as the same function without matching and validating the
code there. Same imported API sets (or similar strings) are not a substitute
for that work.

The next static step for a true 4.6 port is to import this hash-pinned PE into a
separate disassembly project and independently rebuild its function, API-xref,
dynamic-loader, UI/message-map, and device-family call graphs, then compare
normalized code/data references with the 4.06 reports. This delta note does not
claim that the full RK suite has been reverse engineered or that any model is
hardware-compatible based on the 4.6-folder image.
