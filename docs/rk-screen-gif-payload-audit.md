# RK 4.06 screen and GIF payload audit

This note traces the screen-related paths visible in the installed RK Keyboard
Software 4.06 `DeviceDriver.exe` and its matching `Dev/*/KB.ini` files. It uses
existing Ghidra decompilation and read-only package inspection. The vendor
application and updater were not run; no HID or serial interface was opened,
and no report was sent to a keyboard.

Evidence labels used below:

- **Confirmed statically**: directly visible in a decompiled function or an
  installed profile/resource.
- **Inferred**: supported by the static control flow, with a prototype or call
  edge that is not fully resolved.
- **Unresolved**: not established by the available 4.06 package snapshot and
  existing Ghidra exports.

## Profile gates and bundled sample images

**Confirmed statically.** `FUN_00447210` builds the PID profile table from
`Dev/<PID>/KB.ini` and copies `OPT/ShowScreen` into the profile row. The
screen-specific settings loader (shown in the existing brightness/global
export around `FUN_004513B0`) reads the same `ShowScreen` value; only when it is
nonzero does it load `RGBScreen`, `MaxScreenFrame`, `DataUnitSize`, `LatticeW`,
`DrawFrameTime`, `ScreenCRC`, `ScreenViewY`, `FrameViewSp`, and `siScreen`.
Missing-key defaults in the binary are listed below where they affect a
serializer.

The installed snapshot has 15 profiles with nonzero `ShowScreen`:

| PID | Profile name | `ShowScreen` | `siScreen` | `MaxScreenFrame` | `ScreenCRC` |
| --- | --- | ---: | ---: | ---: | ---: |
| `0174` | RK S98RGB | 1 | 320×172 | 60 | 0 (default) |
| `0187` | RK N80 | 1 | 128×128 | 200 | 0 (default) |
| `0193` | RK S85 | 1 | 320×172 | 60 | 0 (default) |
| `01A2` | RK M87 | 1 | 240×135 | 100 | 1 |
| `01AF` | RK-S98RGB-New | 1 | 320×172 | 60 | 0 (default) |
| `01B8` | RK N99 | 2 | 240×240 | 35 | 0 (default) |
| `01BF` | RK-S98RGB ISO Return Keyboard | 1 | 320×172 | 60 | 0 (default) |
| `01D6` | RK M87 ISO Return Keyboard | 1 | 240×135 | 100 | 1 |
| `01F5` | RK M87 Keyboard | 1 | 240×135 | 100 | 1 |
| `01FA` | RK S85 ISO Return Keyboard | 1 | 320×172 | 60 | 0 (default) |
| `0223` | RK-S98 TH Keyboard | 1 | 320×172 | 60 | 0 (default) |
| `0224` | RK-S98 DE Keyboard | 1 | 320×172 | 60 | 0 (default) |
| `022B` | RK-S98 ES Keyboard | 1 | 320×172 | 60 | 0 (default) |
| `022F` | RK-S98 Keyboard | 1 | 320×172 | 60 | 0 (default) |
| `0230` | RK-S98 RU Keyboard | 1 | 320×172 | 60 | 0 (default) |

All 15 also set `Fw=1`. Under the installed profile-to-class map, they select
the G5 path. That is static profile routing evidence, not confirmation that a
physical device matches or accepts these operations.

All 15 explicitly set `RGBScreen=1` and `DataUnitSize=512`; `LatticeW=2`
only for `0187`, and `1` for the other 14. Ten profiles explicitly set
`DrawFrameTime=180`; `01B8` sets it to `0`, and four profiles use the binary
default `25`. Only `01B8` sets `ScreenViewY=60` and `FrameViewSp=50`; other
profiles use defaults `110` and `100`. These names and values are configuration facts;
the meanings of the display-format and preview-related options are not all
recovered from code.

The `01B8` mode is distinguished in device discovery. When the selected row's
`ShowScreen` byte is `2`, the keyboard path asks its device object for six PSD
bytes and searches a secondary screen HID path. `FUN_0040F030` sends report ID
`9` / command `0x82`, reads six bytes, and compares them against the profile
PSD; its log messages call this a screen-device PSD match. This is an active
feature-report transaction, not passive HID enumeration. It was inspected
statically only.

Only `Dev/01FA/KB.ini` contains `GifPID=0x0193`. The available profile-table
initializer demonstrably loads `ShowScreen`, `Fw`, `DevTy`, and wireless IDs,
but the existing exports do not show a read of `GifPID`; its consumer and
effect are **unresolved**. The mapping should not be treated as proof of
runtime pairing.

Two profile folders contain bundled `screen.gif` assets. Static GIF metadata
inspection gives:

| Asset | Bytes | SHA-256 | Dimensions | Frames | Frame duration | Profile frame option |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| `Dev/0193/screen.gif` | 1,353,721 | `a9fe47e6af0b80b6fbc1eaa0e58a8cce4139d2a5952d1cee8c3993674978eae0` | 320×172 | 60 | 40 ms each | `MaxScreenFrame=60` |
| `Dev/01B8/screen.gif` | 1,696,499 | `54023cb42efce6f041bb44aa651ee211b8a1d5e53ae62297ef85e8629c0176ac` | 240×240 | 70 | 80 ms each | `MaxScreenFrame=35` |

Both are GIF89a with an infinite-loop extension. The 01B8 sample has twice as
many encoded frames as its `MaxScreenFrame` setting; whether that field limits
upload frames, selects another screen mode, or means something else is
**unresolved**. The sample dimensions matching `siScreen` support a profile
association, but do not prove how the application converts or uploads them.

## Static serializer paths

### Screen parameters: command `0x0B`

**Confirmed statically.** `FUN_00410230` accepts a caller data pointer and
length. On its direct G5 path it calls the shared feature-report helper with
operation `1` (write), command `0x0B`, report ID from object offset `+0x2D0`,
option `0`, and the caller's length. The helper transfers at most 512 data
bytes in each 520-byte report; the generic header layout is documented in the
[setting serializer audit](rk-setting-serializer-audit.md).

If the direct handle is absent, the wrapper calls a nested object's vtable
slot `+0x48` with the same pointer and length. The command name in the error
log is `SetScreenParam`. No byte-level schema for this data pointer was
recovered: mode, resolution, color depth, orientation, and other fields are
**unresolved**. The direct caller and the UI action that supplies this
structure are also **unresolved**.

### GIF parameters: command `0x0D`

**Confirmed statically.** `FUN_00412890` logs `nGifIndex`, `nFrameNum`, and
`nGifDelay`, builds a five-byte payload, then calls the shared writer with
command `0x0D` and operation `1`:

| Payload byte | Construction | Evidence-backed reading |
| ---: | --- | --- |
| 0 | `(flags << 6) | (byte)gifIndex` | Caller flag bits are shifted into the top two positions and ORed with the low byte of the index. The code does not explicitly mask the index to six bits. |
| 1–2 | `frameNum`, low byte first | 16-bit little-endian frame count. |
| 3–4 | `gifDelay`, low byte first | 16-bit little-endian delay value. |

The helper uses the profile report ID at object offset `+0x2D0`; after a
successful primary exchange, the routine repeats the same command and
five-byte payload on the secondary screen handle using report ID `9` when that
handle exists. It waits for a response through `FUN_0040EC00`; the observed
success check is that byte 3 of the eight-byte response buffer is nonzero. The
meaning of the two high flag bits, index range, delay units, accepted response
values, and whether the secondary exchange is always required are
**unresolved**.

### Frame/page upload: command `0x0C`

**Confirmed statically.** `FUN_00412B10` is the G5 page-transfer serializer.
Its decompiled body divides the caller's total byte count into outer pages of
`DataUnitSize` bytes (default `0x200`, or 512). Each page is split again into
fixed 512-byte subreports. For the 15 screen profiles in this package,
`DataUnitSize` is explicitly 512, so one normal data-unit page is one
subreport. The last chunk is length-limited. The wrapper `FUN_00412F20` selects
the secondary handle at object offset `+8` when present, otherwise the primary
handle at `+4`, and reaches `FUN_00412B10`; the exported prototype does not
fully clarify the register/argument mapping between the selected handle and
the helper's formals.

The 520-byte report layout constructed by `FUN_00412B10` is:

| Offset | Serialized field |
| ---: | --- |
| 0 | The profile report ID (`param1[0xB4]`); becomes `9` when the optional handle matches the object's secondary-screen handle. |
| 1 | Command `0x0C`. |
| 2 | Zero. |
| 3 | Caller-supplied frame value (`param6`). |
| 4 | Rolling subreport counter, starting at zero for the transfer. |
| 5 | Optional checksum byte; zero when `ScreenCRC` is disabled. |
| 6–7 | Current payload length, little-endian. |
| 8–519 | Up to 512 bytes copied from the caller's frame buffer. |

The log calls byte 5 a CRC, but the implementation is a one-byte additive
complement, not a polynomial CRC: it sums the payload modulo 256 and writes
`0xFF - sum`. The code uses separate even/odd accumulators, which still
produce the same modulo-256 total. The response path requires a nonzero
response flag, matching subreport counter, and—when `ScreenCRC` is enabled—a
matching checksum byte. Logs expose outgoing and incoming checksum values.

Each subreport write is attempted up to four times, with 100 ms between failed
attempts. After a page, the helper waits for a page response. A mismatch rewinds
the source offset and packet counter to the start of that page; no separate
fixed page-retry limit is visible. A wait timeout exits the transfer. The
device object's vtable slot `+0x5C` is polled for cancellation after a valid
page response, and an optional callback receives the frame value, total length,
and bytes sent after each subreport. These are observed transfer mechanics,
not a safe read or backup path.

The G5 class dispatch block around `0x005CBA50` contains consecutive entries
for screen parameters (`0x005CBA74`), page transfer (`0x005CBA78`), and GIF
parameters (`0x005CBA7C`). Their presence establishes class-level entrypoints;
the UI-to-slot dispatch and concrete callers are not recovered in the
available exports.

## Image/frame handling and remaining gaps

The installed `DeviceDriver.exe` import-xref inventory shows GDI+ calls for
opening image files, querying dimensions and frame counts, selecting active
frames, and reading pixels (including `GdipCreateBitmapFromFile`,
`GdipImageGetFrameCount`, `GdipImageSelectActiveFrame`, `GdipGetImageWidth`,
`GdipGetImageHeight`, and `GdipBitmapGetPixel`). For example, the existing
[native API xref table](rk-native-api-xrefs.csv) lists frame-count callsites
`0x00467AB0`, `0x00467C52`, and `0x0046A8A6`, and active-frame callsites
`0x0046759D`, `0x004678E0`, `0x004697D5`, `0x00469DF1`, `0x0046AB4A`, and
`0x0046CCDA`. This confirms image and multi-frame processing exists in the
binary. The available decompilation does **not** connect those GDI+ callsites
to `FUN_00410230`, `FUN_00412890`, or `FUN_00412F20`, so it does not establish
that the bundled or imported GIF is what those setters upload.

The following remain open:

- Which UI command and file-selection path feeds each screen/GIF serializer.
- How image dimensions are validated, cropped, scaled, rotated, or padded.
- The exact pixel format and channel order, compression, palette handling,
  dithering, tiling, and relationship to `RGBScreen` / `LatticeW`.
- Whether `MaxScreenFrame` limits an uploaded frame sequence; the 01B8 sample
  has 70 frames while the setting is 35.
- How a GIF frame is selected and converted into the raw `param2` bytes used
  by the page-transfer wrapper, and how the caller's frame index maps to the
  page header.
- Whether `DrawFrameTime` populates `nGifDelay`, and the units or scaling of
  that delay.
- The schema and semantics of command `0x0B` screen parameters; meaning of GIF
  option bits and ACK fields; and which firmware revisions implement them.
- Whether the sole `GifPID=0x0193` entry is consumed by code, and how the
  secondary-screen path is associated with the primary keyboard outside the
  `ShowScreen=2` PSD-match path.

This evidence covers the installed 4.06 snapshot and its bundled profiles,
not every Royal Kludge product or firmware. All protocol descriptions above
come from static code and package data only; no command was tested on a
physical keyboard.

The follow-up [screen image-conversion audit](rk-screen-image-conversion-path-audit.md)
maps the GIF-to-PNG cache routines and frame-conversion worker, while leaving
the visible import and conversion-to-device-writer edges unresolved.
