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

2. `0x00476D30`, called at `0x00474780`, selects a file workflow based on
   `[EBX+0x64]`. When the count is exactly one, it opens a `New PNG` path and
   saves the first list item's image to a PNG file, as detailed below. When
   the count is not one, it enters the multi-frame `NewGIF` path using the GIF
   filter, title and `.gif` extension strings at `0x005E3BB8`, `0x005E3BDC`
   and `0x005E3BEC`. Only the multi-frame branch feeds the linked frame list
   into the worker path traced below.

### Generic one-file picker preview path

The generic picker caller at `0x0047440A` reaches `0x004762E0` with the
selected path. This helper first disposes an existing object at `[ESI+0xA0]`
when present, then allocates a 16-byte wrapper and initializes its vtable to
`0x005ACE9C`. It calls `GdipCreateBitmapFromFile` at `0x0047633E`, stores the
returned image pointer at wrapper `+0x04` and the status at `+0x08`, then
stores the wrapper at `[ESI+0xA0]`. The API ledger maps subsequent calls at
`0x0047636C`, `0x00476395`, and `0x004763B9` to
`GdipGetImageWidth`/`GdipGetImageHeight`.

The helper calculates a size/scale for the local image using the preview
state, writes a rectangle at `[ESI+0x90]` through `USER32.SetRect` at
`0x0047649A`, stores the scale at `[ESI+0xA4]`, and invalidates the window
handle at `[ESI+0x20]` through `USER32.InvalidateRect` at `0x004764B2`.
Failure cleanup disposes the wrapper and clears `[ESI+0xA0]`. These calls
support image loading and preview-layout preparation. The picker continuation
at `0x0047440A` returns after this helper; it does not enter the NewGIF helper
or the frame-snapshot/worker path.

A follow-up trace checked the candidate `WM_PAINT` handler at `0x004721A0`
and the separate image/frame routine at `0x004765D0`. The paint handler reads
and draws member `[this+0x2304]`; its recovered body does not read the generic
picker fields `+0xA0`, `+0x90`, or `+0xA4`, and does not call `0x004765D0`.
The routine at `0x004765D0`, called independently from `0x004744E3`, checks
`[this+0xA0]` and the scale at `[this+0xA4]`, then separately walks the
existing frame list at `[this+0x6C]`, regenerates/replaces list-node image
wrappers, and clears `[this+0xA0]`. No store or link of the generic picker
image pointer into that frame list was found in these recovered paths.

Thus static evidence currently leaves the generic picker's visible rendering
unresolved and finds no direct dataflow from its image object to the frame list
or the multi-frame screen worker. This does not rule out indirect runtime or
class-alias behavior outside the recovered paths, and it does not prove that
the generic picker can transfer its file to the keyboard.

The profile display loader at `0x00473C50` formats the bundled path
`%sDev\\%04X\\screen.gif` using the string at `0x005E3860`. At `0x00473D49`
it calls the GDI+ `GdipCreateBitmapFromFile` thunk with that path, queries
image dimensions, and obtains the frame count at `0x00473E2F`. This is evidence
that the package's profile GIF is loaded into the application's screen-image
state. In the multi-frame `NewGIF` path, user-selected files are statically
connected to the frame objects consumed by the screen transfer worker below.

GDI+ API names and their 4.6 thunk sites are also listed in the
[4.6 native API call-site inventory](rk-v4.6-native-api-call-sites.csv). The
inventory records sites such as `GdipImageGetFrameCount` at `0x00471746` and
`GdipImageSelectActiveFrame` at `0x004719EA`. These calls support multi-frame
image processing.

## Recovered user-file-to-frame-worker bridge

The 4.6 image/GIF control flow contains a concrete bridge from the NewGIF file
dialog to the frame array consumed by the screen worker. This is static
evidence: the program was not run and no device report was sent.

1. The UI dispatcher at `0x00474780` calls NewGIF helper `0x00476D30` with
   `EBX = parent + 0x88`. The helper branches on `[EBX+0x64]` and enters its
   multi-frame `NewGIF` picker at `0x00476E38` when the frame count is not one.
   After a successful dialog return, execution reaches `0x00476E94` and the
   per-frame loop beginning at `0x00476EFF`; that loop walks the linked list at
   `[EBX+0x6C]`, calls frame helper `0x0046E4A0` for each listed image object,
   then calls finalizers `0x0046E5E0` and `0x0046E390`.
2. This is the same count and list later read by the frame-snapshot handler.
   There, `EDI = parent + 0xE0`; `[EDI+0x0C]` is the same address as
   `[EBX+0x64]` (`parent + 0xEC`), and `[EDI+0x14]` is the same address as
   `[EBX+0x6C]` (`parent + 0xF4`). The handler walks that list, copies each
   node's first pointer into a temporary object's pointer array beginning at
   `+0x3A8`, stores the count at `+0x3A4`, caps the copy at 512 entries, and
   calls `0x004811E6` with that temporary object.
3. The temporary object's constructor `0x0046C4D0` installs vtable
   `0x005E2ABC`. Setup function `0x004811E6` calls the dialog-creation helper
   `0x0048102B`, which reaches `CreateDialogIndirectParamW` at `0x0048113E`
   with dialog procedure `0x00480AD7`. On `WM_INITDIALOG` (`0x110`), that
   procedure retrieves the associated object and invokes vtable slot `+0x150`;
   the exact pointer at `0x005E2C0C` for the temporary object's vtable is
   `0x0046CE50`.
4. `0x0046CE50` calls thread helper `0x0057552B` with worker callback
   `0x0046CA80` and the temporary object. The helper reaches the direct
   `CreateThread` call at `0x0057559F`; its start wrapper `0x005754B4`
   dispatches the saved callback and context. The callback scans the same
   `+0x3A4` count and `+0x3A8` pointer array. Its frame loop at `0x0046CCB1`
   indexes those pointers, calls the RGB565 converter at `0x0046C7D0`, then
   calls the device vtable slot `+0x54` at `0x0046CCFC`. The GIF-parameter
   method at `0x0046CC22` calls slot `+0x58` before that loop.

These address and field equalities connect the multi-frame selected-file path,
the shared frame list, the worker's frame array, and the documented G5 HID
writer path. They establish that this code path is designed to pass the
selected-image frame objects into the screen transfer routine. They do not
prove that a particular model accepts the data, complete UI label/control
identity, exact decoder semantics for every helper, or successful runtime
behavior.

## Single-frame `New PNG` export

The one-item branch of `0x00476D30` is an image export path, not a PNG import
path into the worker. At `0x00476D6A` the helper reads the item count from
`[EBX+0x64]`; equality with one branches to `0x00476D8A`. That branch uses
the PNG filter/title/extension records at `0x005E3B78`, `0x005E3B9C`, and
`0x005E3BAC`, invokes the common-dialog helpers `0x00483285` and
`0x00483AE6`, and retrieves the chosen pathname at `0x00476DCB` through
`0x00483C15`.

The helper then calls `0x0046D1D0` at `0x00476DDD` with `EAX=EBX+0x58` and
`EDX=0`. `0x0046D1D0` reads the linked list at `[EAX+0x14]` (the same address
as `[EBX+0x6C]`) and returns the first item's object pointer. The caller
passes that image object and the selected pathname to `0x00458AA0`. That
routine calls encoder lookup helper `0x004589B0`, which compares encoder MIME
strings against the embedded UTF-16 `image/png` at `0x005E3280` and returns
the matching encoder identifier. At `0x00458AE1`, the call goes through
thunk `0x005908E4` / IAT VA `0x005A6988`, identified in the API callsite
ledger as `GdipSaveImageToFile`; arguments include the image pointer at
`[item+4]`, the chosen path, the PNG encoder identifier, and null encoder
parameters.

This branch reads the existing first list item for file output. It does not
add or replace a linked-list entry and does not call the screen worker from
this branch. Thus the `New PNG` action is statically mapped as saving the
current first image to a PNG file. The profile-bundled `screen.gif` remains a
separate input to screen-image state. The generic picker at `0x00473B00` and
its `0x004762E0` preview setup form another path; its later paint/commit
relationship to the screen worker remains unresolved.

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
  names. The NewGIF-to-worker object path is mapped, but the visible command
  label/control identity and class owner of the candidate map are unresolved.
- The multi-frame `NewGIF` picker and shared frame-list-to-worker ownership
  are mapped. The one-item `New PNG` branch is mapped as a GDI+ export of the
  first list image. The generic one-file picker and `0x004762E0` are mapped
  through GDI+ image loading, preview geometry, and window invalidation. The
  candidate paint handler does not read those preview fields, and the separate
  `0x004765D0` list-processing routine does not show a direct link from the
  preview image into the frame list. Visible rendering and indirect/runtime
  commit behavior remain unresolved. Exact decoder semantics of
  `0x0046E2F0`, `0x0046E4A0`, and adjacent frame helpers remain open. The
  profile-bundled `screen.gif` loader is a separate observed input to
  screen-image state.
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
