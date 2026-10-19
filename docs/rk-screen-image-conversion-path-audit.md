# RK screen image conversion and transfer-path audit

## Scope and evidence

This note follows image and frame handling in the installed RK Keyboard
Software 4.06 `DeviceDriver.exe` snapshot, then compares that path with the
screen/GIF serializers. The executable is PE32 x86, image base `0x00400000`,
SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
Addresses are virtual addresses in that exact image. Inputs were the existing
Ghidra-derived exports and audits in this repository, especially
[`rk-native-api-xrefs.csv`](rk-native-api-xrefs.csv),
[`rk-mfc-message-map-entries.csv`](rk-mfc-message-map-entries.csv),
[`rk-screen-gif-payload-audit.md`](rk-screen-gif-payload-audit.md), and
[`rk-ui-control-command-crosswalk.md`](rk-ui-control-command-crosswalk.md).

The RK application and updater were not launched. No HID, serial, GATT, or
other keyboard interface was opened; no report, command, firmware, or
bootloader operation was performed.

Evidence labels:

- **Confirmed statically**: a recovered code path, callsite, message-map row,
  file operation, or package record directly supports the claim.
- **Inferred**: separate static evidence fits the proposed relationship, but
  an end-to-end call/data edge is missing.
- **Unresolved**: the available export set does not establish the relationship.

## Findings

**Confirmed statically.** The main screen editor has a recovered `CScreenDlg`
message map at descriptor `0x005DA518`, with seven entries beginning at
`0x005DA458`. Its one `WM_COMMAND` row is entry `0x005DA4D0`: control ID
`0x0107`, notification code `EN_CHANGE` (`0x0300`), handler `0x0046C5B0`.
The existing static crosswalk says this handler validates a numeric edit and
stores the value at `this+0x114`. It is not evidence of a file-open or image
import button. Other recovered screen-dialog routes are `WM_LBUTTONDOWN` to
`0x0046DCC0`, private message `0x0800` to `0x0046B260`, private message
`0x0477` to `0x0046DBF0`, and `WM_TIMER` to `0x0046D570`. A focused static
follow-up traces the screen child through a two-row menu whose second row posts
value one to the `CScreenDlg` handler, opening the file picker and inserting
the selected path object into the linked-list wrapper at `CScreenDlg+0xE4`,
whose head is `+0xF4`. The handler calls `0x0046D900`, which rebuilds this
same list only when its count gate equals `0x11`. Its English row labels now
resolve through `tc_screen14` (“New”) and `tc_screen15` (“Import”); successful
conversion of the selected path object to a frame consumed by the transfer
worker remains open.
See the raw
[`CScreenDlg` map rows](rk-mfc-message-map-entries.csv).

**Confirmed statically.** The installed package contains two profile GIFs:
`Dev/0193/screen.gif` (320×172, 60 frames) and
`Dev/01B8/screen.gif` (240×240, 70 frames). The profile audit identifies 15
profiles with `ShowScreen` set; the two GIFs are bundled samples, not evidence
that a chosen file is uploaded. The existing static trace identifies
`FUN_0046C9F0` as decoding the device-profile `screen.gif` into local
`screen_img%d.png` frame files and purging up to 512 stale frame files before
the new cache is saved. `FUN_0046D900` is identified as a PNG-frame
regeneration helper. Exact cache directory construction and the user action
that initiates either routine are not established in the available exports.

**Confirmed statically.** GDI+ frame and image calls occur in the executable.
The native API cross-reference inventory reports direct calls through import
thunks at these addresses:

| GDI+ operation | Direct callsites | What this proves |
| --- | --- | --- |
| `GdipImageGetFrameCount` | `0x00467AB0`, `0x00467C52`, `0x0046A8A6` | These callsites query an image frame count. The xref table alone does not identify which caller is the screen importer. |
| `GdipImageSelectActiveFrame` | `0x0046759D`, `0x004678E0`, `0x004697D5`, `0x00469DF1`, `0x0046AB4A`, `0x0046CCDA` | The executable selects active image frames at these sites; it does not prove that every site processes a GIF used by the keyboard screen. |
| `GdipBitmapGetPixel` | `0x0046626F`, `0x00468673`, `0x0046E387` | Pixel reads exist. The known worker route passes through helper `0x004661A0`; only the matching callsite near `0x0046626F` is consistent with that helper. Pixel format/channel meaning is not recovered here. |
| `GdipSaveImageToFile` | `0x004555A1`, `0x0046803E`, `0x0046DA33` | PNG/image file saves exist. The existing trace identifies `0x0046DA33` within `FUN_0046D900`; the other two callsites are not assigned to the screen cache by the xref export. |
| `GdipCreateBitmapFromFile` | `0x00467983`, `0x0046959B`, `0x0046A7BB`, `0x0046BBB7`, `0x0046CAE9` among many sites | Bitmap file loads exist in this address neighborhood; a callsite by itself cannot distinguish screen artwork from UI artwork or other images. |

These are direct import-call xrefs, not a recovered one-to-one route from a
visible editor button to a particular conversion routine. The full callsite
inventory, including import-thunk addresses and other image APIs, is in
[`rk-native-api-xrefs.csv`](rk-native-api-xrefs.csv).

**Confirmed statically.** A separate frame-transfer worker route is recorded
in the existing native trace: callsite `0x00466820` starts worker
`FUN_00466450`; that worker converts frame images through `FUN_004661A0`,
uses object virtual slots `+0x4C` and `+0x50`, and supplies progress callback
`FUN_004663C0`. `GdipBitmapGetPixel` callsite `0x0046626F` lies in the
`FUN_004661A0` conversion helper. This establishes a local image-to-frame
conversion and an abstract worker interface. A later hash-pinned follow-up
resolves the initiating `WM_INITDIALOG` path and the G5 `+0x4C` page-writer and
`+0x50` GIF-writer targets; see the
[4.06 screen UI-to-worker trace](rk-406-screen-ui-to-worker-modal-follow-up.md).

## Relation to the recovered screen serializers

The binary exposes separate G5 screen writers:

| Routine | Static role | Relationship to image conversion |
| --- | --- | --- |
| `FUN_00410230` | Command `0x0B`; sends the caller's screen-parameter bytes. | No byte schema or direct UI/image-conversion caller was recovered. |
| `FUN_00412890` | Command `0x0D`; constructs five GIF-parameter bytes: flags/index, 16-bit frame count, and 16-bit delay. | The available export does not show whether the frame count or delay comes from GIF metadata, the four-byte `gif_delay.gcc` cache, or an editor control. |
| `FUN_00412F20` → `FUN_00412B10` | Wrapper and command `0x0C` page/frame transfer; serializes up to 512 caller bytes per subreport. | A 4.06 screen worker passes the `FUN_004661A0` conversion buffer through the G5 `+0x4C` slot to this writer. NewPNG/NewGIF are save-as routes. The `0x0477` message branch inserts its selected-path object into the same linked list whose head is `CScreenDlg+0xF4`, later snapshotted by the transfer action. Successful object-to-frame conversion and the profile/cache trigger remain unresolved; see the 4.06 follow-up. |

The G5 dispatch block near `0x005CBA50` contains adjacent entries for screen
parameters (`0x005CBA74`), page transfer (`0x005CBA78`), and GIF parameters
(`0x005CBA7C`). The worker's virtual calls at `+0x4C`/`+0x50` resolve to the
page-transfer and GIF-parameter entries for the recovered G5 vtable, closing
that static buffer-to-writer edge. The worker does not call the adjacent
screen-parameter (`+0x48`) entry. The linked 4.06 follow-up corrects the
NewPNG/NewGIF interpretation: both are save-as dialogs (`bOpenFileDialog=0`),
not input-file pickers. NewPNG requests item zero through helper
`0x00466BC0`, passing the alternate base `CScreenDlg+0xE0`; the helper reads
the same list head at `CScreenDlg+0xF4` that NewGIF traverses directly. The
list wrapper is based at `CScreenDlg+0xE4`, with count/head/tail at
`+0xEC/+0xF4/+0xF8`. `FUN_0046D900` conditionally clears and rebuilds that
same list when its count gate equals `0x11`, using indexed source objects and
builder `FUN_0046EAA0`; otherwise it skips rebuilding. The `0x0477` menu's
value-zero branch constructs a GDI+ bitmap and its value-one branch opens an
image picker; both insert into the same list and call this count-gated helper.
The transfer route can snapshot a positive-count list, but successful
conversion of a created bitmap or imported path object into a device frame,
the profile/cache trigger, and initial source enumeration remain unresolved.

The separate local playback cache helpers `FUN_0046ACC0` and `FUN_0046ADC0`
read/write `gif_delay.gcc` as a four-byte value. The value's units, accepted
range, and direct relation to `nGifDelay` in `FUN_00412890` are unresolved.

## UI/export boundary and remaining gaps

The main feature UI is built dynamically. Its parsed static dialog resources
do not supply the screen editor's visible controls or IDs. The localization
catalog includes `tc_screen*` labels, but no exact label-to-child binding is
recovered. The only screen-dialog `WM_COMMAND` row currently tied to a control
is the numeric `EN_CHANGE` route above. In the 4.06 NewPNG/NewGIF branch,
`bOpenFileDialog=0` selects `GetSaveFileNameW`; selected paths are destinations.
Consequently, this snapshot does not establish:

- whether the `0x0477` open-file path replaces the bundled
  `Dev/<PID>/screen.gif` or yields an object the frame converter can consume;
  it inserts a path object into the same list later snapshotted by transfer,
  while NewPNG/NewGIF remain save-as routes;
- when and how the profile/cache source files are enumerated and used to
  rebuild `CScreenDlg+0xE4` (count/head/tail at `+0xEC/+0xF4/+0xF8`). The
  linked 4.06 follow-up shows `FUN_0046D900` rebuilding this list only when its
  count gate equals `0x11`; it does not identify the profile/cache trigger or
  whether a menu-inserted path object is among the indexed source objects;
- the image dimension validation, crop/scale/rotate/padding rules, color
  depth, channel order, palette, quantization, dithering, or tile layout;
- how the worker's frame value maps to command `0x0C` header byte 3, and the
  exact pixel/color layout produced by `FUN_004661A0`;
- whether generated frame PNGs are a mandatory staging format or only a UI
  preview/cache;
- the relation between GIF frame-count metadata, profile `MaxScreenFrame`,
  `gif_delay.gcc`, `DrawFrameTime`, and the values passed to command `0x0D`;
- the exact progress-to-UI route and runtime cancellation outcome.

The earlier
[`screen/GIF payload audit`](rk-screen-gif-payload-audit.md) documents the
screen command fields, retry/ack behavior, and model profile gates. The 4.06
follow-up establishes a static screen-menu-to-`0x0477`-to-open-picker/list-update
route, a count-gated cache/list rebuild, and a modal-to-worker-to-G5 page/GIF
writer path for a populated frame list. It establishes that the imported path
object is inserted into the same linked list later snapshotted by transfer,
but not that the frame converter accepts that object. The cache trigger,
runtime profile selection, and physical display acceptance remain open.
