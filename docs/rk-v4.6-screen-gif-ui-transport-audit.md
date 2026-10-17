# RK DeviceDriver.exe 4.6 screen/GIF UI-to-transport audit

## Scope and evidence identity

This note traces the screen and GIF workflow in the extracted 4.6-labeled
`DeviceDriver.exe`, from MFC image dialogs and frame preparation through the
G5 screen transfer methods. The exact PE is 2,418,176 bytes, SHA-256
`8D8538DE3ADA5FCF80E00C13B364B17ACEFA708480E102EC1E6A0B1309639AE9`, x86,
preferred image base `0x00400000`. Every address below was checked in this
binary; 4.06 findings were used only as leads.

The executable was not launched. No updater was run, no device interface was
opened, and no report was sent. The call graph is static evidence, not a
successful hardware test.

The MFC map, caller edges, packet construction and vtable slots below are
**confirmed statically** for this PE. Matching a configuration row to a real
keyboard revision, or proving that a model accepts a report, is **not** shown.
Function names such as `BurnScreen` are taken from embedded diagnostic strings;
the binary has no symbols that identify all C++ class names.

## Profile gate and declared screen-model coverage

The 4.6 package contains 37 `Dev/*/KB.ini` profiles with nonzero `ShowScreen`.
All 37 declare `Fw=1`. Their display configurations group as follows:

| Declared display size | `MaxScreenFrame` | Profiles |
| --- | ---: | ---: |
| 320×172 | 60 | 18 |
| 240×135 | 100 | 8 |
| 240×135 | 50 | 5 |
| 240×240 | 35 | 4 |
| 128×128 | 200 | 2 |

These entries cover the catalog families L75, M87, N80, N99, S104, S85 and
S98. Four profiles use `ShowScreen=2`; the other 33 use `ShowScreen=1`.
These are software profile declarations from the extracted package, not
independent confirmation of physical devices or firmware compatibility. The
catalog has one separate `Fw=3` profile (M20), but it has no screen declaration;
the 4.6 snapshot therefore assigns no modeled screen profile to the Fw=3
CDev3632 branch. This statement is limited to this package and catalog.

The 4.6 profile selector sends `Fw=1` through its general nonzero branch to
constructor `0x0040F490` (see the
[4.6 profile selector audit](rk-v4.6-profile-selector-audit.md)). That
constructor writes vtable pointer `0x005D3D0C` into the object at `0x0040F4C3`.
In this table, slot 20 (`+0x50`) is `0x00410B60`, slot 21 (`+0x54`) is
`0x00413CB0`, and slot 22 (`+0x58`) is `0x00413620`.

## MFC screen/image dialog map

The 24-byte MFC message-map records beginning at `0x005E36B8` form a candidate
screen/image dialog map. The class name itself is not present in this table;
the attribution is inferred from its image/GIF-related neighbors and the
screen-specific edit handler. These are addresses in the 4.6 PE:

| Map entry VA | Message / signature | Control ID or code | Handler VA | Static reading |
| --- | --- | --- | --- | --- |
| `0x005E36B8` | `WM_ERASEBKGND` / AfxSig 1 | — | `0x0044B310` | Background erase handler |
| `0x005E36D0` | `WM_PAINT` / AfxSig `0x13` | — | `0x004721A0` | Paint handler |
| `0x005E36E8` | `WM_LBUTTONDOWN` / AfxSig `0x35` | — | `0x004753E0` | Mouse-down handler |
| `0x005E3700` | private message `0x800` / AfxSig `0x0E` | — | `0x00472140` | Private dispatch handler |
| `0x005E3718` | private message `0x477` / AfxSig `0x0E` | — | `0x004752D0` | Private dispatch handler |
| `0x005E3730` | private message `0x5D5` / AfxSig `0x0E` | — | `0x004749F0` | Private dispatch handler |
| `0x005E3748` | `WM_COMMAND` / AfxSig `0x39` | `EN_CHANGE`, ID `0x107` | `0x00473810` | Reads edit text, clamps it to 16 bits and stores it at object offset `+0x114`; not the file-import or device-write routine |
| `0x005E3760` | `WM_TIMER` / AfxSig `0x14` | — | `0x00474C50` | Timer handler |

The table ends with an all-zero record at `0x005E3778`. The message-map
addresses and records were decoded from the 4.6 PE data, not copied from the
4.06 report.

## UI image selection and bundled profile GIF

Two image-selection paths are visible in the dialog code:

1. `0x00473B00` copies the filter string at `0x005E3810`
   (`Image Files|*.png;*.jpg;*bmp;*gif||`) into a file-dialog object and calls
   the common dialog construction/selection helpers at `0x00483285` and
   `0x00483AE6`. It is called by the dialog event routine at `0x004741A0`.
   In another branch, `0x00474385` uses the image-only filter at `0x005E38B4`
   (`*.png`, `*.jpg`, `*.bmp`). After that picker returns, `0x0047440A` passes
   the resulting path to image-processing helper `0x004762E0`.

2. `0x00476D30`, called at `0x00474780`, constructs a separate `NewGIF`
   dialog. It uses the GIF filter, title and `.gif` extension strings at
   `0x005E3BB8`, `0x005E3BDC` and `0x005E3BEC`, respectively. This proves a
   GIF-related UI action, but does not by itself prove that the resulting file
   is uploaded to the keyboard.

The profile display loader at `0x00473C50` formats the bundled path
`%sDev\\%04X\\screen.gif` using the string at `0x005E3860`. At `0x00473D49`
it calls the GDI+ `GdipCreateBitmapFromFile` thunk with that path, queries
image dimensions, and obtains the frame count at `0x00473E2F`. This is evidence
that the package's profile GIF is loaded into the application's screen-image
state; it is not evidence that a user's chosen file is the same object passed
to the writer below.

GDI+ API names and their 4.6 thunk sites are also listed in the
[4.6 native API call-site inventory](rk-v4.6-native-api-call-sites.csv). The
inventory records sites such as `GdipImageGetFrameCount` at `0x00471746` and
`GdipImageSelectActiveFrame` at `0x004719EA`. These calls support multi-frame
image processing, while the selected-file-to-frame-array ownership chain
remains unresolved.

## Frame conversion and `BurnScreen` transfer sequence

The frame converter at `0x0046C7D0` gets the image dimensions, allocates a
two-byte-per-pixel output buffer, and calls the GDI+ pixel getter thunk at
`0x0046C89F` for each pixel. It packs the returned color into 16-bit RGB565
(red 5 bits, green 6 bits, blue 5 bits), byte-swaps that word, and writes two
bytes per pixel. This statically establishes an image-to-frame-byte conversion
for the object supplied to the routine.

The function containing the `BurnScreen` diagnostics prepares frame/index
state and performs these operations:

1. At `0x0046CC22` it calls the device object's vtable slot `+0x58`. For the
   G5 vtable installed by `0x0040F490`, that slot is `0x00413620`, the GIF
   parameter method. It retries a failed acknowledgement up to three times
   (`0x0046CC5A` onward), with a delay between attempts.
2. In its frame loop, `0x0046CCDB` calls the RGB565 converter `0x0046C7D0`.
   It then calls device vtable slot `+0x54` at `0x0046CCFC`. In the same G5
   vtable this resolves to wrapper `0x00413CB0`, which selects a primary or
   secondary device handle and calls page-transfer core `0x004138A0`.

The GIF parameter method at `0x00413620` builds a five-byte data value: an
index/flag byte, a 16-bit frame count, and a 16-bit delay. It invokes generic
feature writer `0x0040FFD0` with operation `1` (write), command `0x0D`, length
`5`, and the profile report ID. The generic writer builds a `0x208`-byte
feature report, carries up to `0x200` (512) data bytes per chunk, and reaches
the `HidD_SetFeature` thunk `0x00590A08` (for example, the call at
`0x0041014F`).

The page-transfer core at `0x004138A0` builds `0x208`-byte reports and uses
command byte `0x0C` in the report header. The copy loop caps each transfer
chunk at `0x200` bytes. At `0x00413ACF` it calls the same
`HidD_SetFeature` thunk `0x00590A08`; this call site is independently recorded
for the 4.6 binary in the native API inventory. The routine also performs
retry and response-check logic, but the complete meaning of its page/offset
arguments and every response field has not been resolved here.

Together, the converter, the `BurnScreen` virtual calls, the exact G5 vtable
slots, the page-transfer wrapper/core and the HID API call establish a static
frame-buffer-to-transport path in this 4.6 binary. They do not establish a
successful transfer to a connected keyboard.

## Remaining gaps and model limits

- The MFC table identifies message handlers but strips their class/method
  names. The selected UI control's full handler-to-image-object ownership is
  not recovered.
- The image file picker and `0x004762E0` processing path are visible, and the
  `BurnScreen` converter-to-writer path is visible, but this audit does not
  prove the chosen-file object is what populates the frame array consumed by
  `BurnScreen`. The profile-bundled `screen.gif` loader is a separate observed
  path.
- The `0x0C` report is identified as the G5 page-transfer request by its code
  location, log context and call chain. A complete field-by-field protocol
  definition, CRC algorithm interpretation, device acceptance behavior and
  firmware-version variation remain outside the evidence here.
- The 37 screen-bearing profile rows span seven declared families and five
  display configurations, but this single package cannot show support for all
  Royal Kludge keyboards, revisions or firmware. It does not prove any
  physical model's compatibility.

The 4.06 screen/GIF reports
([image conversion](rk-screen-image-conversion-path-audit.md) and
[payload path](rk-screen-gif-payload-audit.md)) were used only as search leads.
The code addresses, message map, constructor vtable, transfer routine and
transport writer in this report were independently checked against the
hash-pinned 4.6 `DeviceDriver.exe` above.
