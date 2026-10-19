# RK 4.06 screen UI to worker modal follow-up

## Scope and evidence

This follow-up traces the installed RK Keyboard Software 4.06
`DeviceDriver.exe` screen-editor dispatch toward its screen-transfer dialog,
frame-list preparation, and the separately recovered transfer worker. The
binary is PE32 x86, image base `0x00400000`, SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
The installed image at
`C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe` and the
workspace analysis copy `_rk_analysis/inputs/DeviceDriver.exe` both have that
hash.

The analysis is static. The RK application and updater were not run; no HID
interface was opened and no report or command was sent.

Evidence labels:

- **Confirmed statically**: directly supported by instructions, data, or a
  recovered call/message path in this exact image.
- **Inferred**: the static pieces fit the interpretation, but an edge or
  semantic label is missing.
- **Unresolved**: the available static path does not establish the claim.

## Screen-editor transfer action

**Confirmed statically.** In the `CScreenDlg` dispatch routine at
`0x0046D300`–`0x0046D4FC`, the child window handle at `this+0x1408` is compared
with the incoming control handle (`0x0046D399`–`0x0046D3A8`). On a match, the
routine obtains the device object through global `0x0062B380` and invokes its
virtual slot `+0x28` (`0x0046D3AE`–`0x0046D3C0`). A true return proceeds; a false
return takes the alternate message path. The meaning of slot `+0x28` is not
recovered here, so it is only a device-object gate, not a proven `ShowScreen`
profile check.

After that gate, the dispatcher requires the count field at `this+0xEC` to be
positive (`0x0046D3DE`–`0x0046D3E5`). It appears to be the screen frame count,
but that semantic label is inferred from context. It then:

1. Initializes a stack object with `0x00465EA0` (`0x0046D3EB`–`0x0046D3F0`).
   The constructor writes vtable pointer `0x005D9A4C`, initializes the
   pointer-array area at object offset `+0x3A4` for `0x800` bytes, and clears
   fields at `+0x390` and `+0x394`.
2. Traverses a linked list rooted at `this+0xF4`, copies each node's first
   pointer into that object's array, and stops at 512 entries
   (`0x0046D400`–`0x0046D429`). The resulting count is stored immediately
   before that array. This is the strongest UI-to-dialog evidence for the
   screen frame/image object list.
3. Copies the numeric field from `this+0x114` into the object at offset
   `+0xBA4` (`0x0046D429`–`0x0046D43A`). Its UI meaning remains unknown.
4. Calls `0x00479A27` with the initialized object (`0x0046D43A`–`0x0046D441`),
   then destroys the object with `0x00465F50` (`0x0046D44A`–`0x0046D455`).

**Confirmed statically.** The constructor installs vtable `0x005D9A4C`. It
contains `0x00479A27` at offset `+0x14C` and `0x00466820` at offset `+0x150`
(`0x005D9B98` and `0x005D9B9C` respectively). The screen-editor dispatcher
calls `0x00479A27`; that method reaches `0x0047986C`, which calls the imported
`CreateDialogIndirectParamW` at `0x0047997F` with dialog procedure
`0x00479318`. The API callsite is independently recorded in the native API
[cross-reference](rk-native-api-xrefs.csv).

The dialog procedure checks for `WM_INITDIALOG` (`0x0110`) at `0x0047931D`.
It resolves the window to an MFC `CDialog` object through `0x00475329` and
`0x004848BC`, then invokes that object's vtable slot `+0x150` at
`0x00479343`. For the constructed screen modal, that slot is `0x00466820`.
Therefore the recovered create-dialog initialization path dispatches to the
worker setup routine; this is stronger than vtable membership alone. The
related code logs `CBurnScreenDlg: user cancel` (`0x005D9A00`), consistent
with the screen-transfer dialog role.

**Inferred.** The stack object and call to `0x00479A27` form the screen burn
progress/modal path: the object contains the copied frame pointer array and
progress-related state. The visible label and exact dialog resource/control
identity are not established by this trace.

## NewPNG/NewGIF save-as route and frame-list boundary

**Confirmed statically.** A separate `CScreenDlg` dispatch branch compares the
incoming child handle with the child object at `this+0xC74` and directly calls
`0x0046F610` (`0x0046D45C`–`0x0046D478`). That routine reads an item count at
object offset `+0x64` and traverses a linked list at `+0x6C`. The `NewPNG` and
`NewGIF` strings are dialog titles; these branches use save dialogs in this
4.06 image, not an input-file picker.

- For a count of one, the routine selects a `.png` filter and the embedded
  UTF-16 title `NewPNG` (`0x0046F659`–`0x0046F6B0`; strings at
  `0x005DA900`–`0x005DA934`). The dialog object is constructed at
  `0x0046F681`; the caller passes mode `0` at `0x0046F67B`. On a successful
  modal result (`0x0046F695`–`0x0046F6A1`), it reads the selected path through
  `0x0047C4C1` (`0x0046F6AB`) and accesses item zero from the separate
  `CScreenDlg+0xE0` collection (`0x0046F6B0`–`0x0046F6BD`).
- For other positive counts, it selects a `.gif` filter and embedded title
  `NewGIF` (`0x0046F718`–`0x0046F779`; strings at
  `0x005DA940`–`0x005DA974`). The dialog object is constructed at
  `0x0046F732`; the caller passes mode `0` at `0x0046F729`. On a successful
  modal result (`0x0046F749`–`0x0046F750`), it obtains the selected path
  through `0x0047C4C1` (`0x0046F762`), then iterates the existing
  `CScreenDlg+0xF4` list. Each node is passed through frame-processing helper
  `0x00467E50`; the routine calls finalizers `0x00467F90` and `0x00467D40`
  (`0x0046F7D5`–`0x0046F884`).

The dialog object's constructor at `0x0047BB31` stores its first argument at
`this+0x88` (`0x0047BC08`–`0x0047BC11`). Its modal routine branches on this
field at `0x0047C463`–`0x0047C47B`: mode zero calls the save-dialog route
`0x0047B9C2` → `0x0047B8FB` (`GetSaveFileNameW`); the other branch calls
`0x0047B9A6` → `0x0047B821` (`GetOpenFileNameW`). Thus both NewPNG and NewGIF
present destination paths. This establishes a save-as boundary, but the
complete file serialization after path retrieval is not resolved here.

The NewPNG branch reads an item from the separate `CScreenDlg+0xE0`
collection; the NewGIF branch processes the already-present `CScreenDlg+0xF4`
list. The dispatcher passes `EBX = this+0x88` to `0x0046F610` at
`0x0046D46D`–`0x0046D473`; within that helper, the item count at `EBX+0x64`
is the screen-dialog count at `this+0xEC`, and the list head at `EBX+0x6C`
is `this+0xF4`. In the transfer-button branch, `0x0046D3DE` checks the same
`this+0xEC` count and `0x0046D400`–`0x0046D429` walks `this+0xF4`, copying
each node's first pointer into the modal object's frame array. The NewGIF
branch at `0x0046F7DF`–`0x0046F85D` also walks `EBX+0x6C` and calls
`0x00467E50` with each node's first pointer. This establishes that the
multi-item NewGIF route and transfer route use the same
`CScreenDlg+0xF4` collection, but not that its selected destination path
inserts items there.

A separate cache-rebuild route is visible: `0x0046D900` calls list builder
`0x0046EAA0` (`0x0046DA50`–`0x0046DA57`); the builder obtains indexed source
objects through `0x00454D90` (`0x0046EADC`–`0x0046EAE2`) and appends 12-byte
doubly linked nodes to `CScreenDlg+0xF4` (`0x0046EB50`–`0x0046EB7F`). This
links cache regeneration to list construction, not to a NewPNG/NewGIF result.
The trigger and exact source-file enumeration that repopulate the cache/list
for a selected profile and the converted image buffer's required pixel layout
remain unresolved. A separate open-file route through `CScreenDlg` message
`0x0477` is documented below; its relation to the F4 frame list remains open.
The 4.06 profile GIF-to-PNG cache path documented in
[`rk-screen-image-conversion-path-audit.md`](rk-screen-image-conversion-path-audit.md)
is a separate local-file route in the available evidence.

## `CScreenDlg` private message `0x0477` input-file route

**Confirmed statically.** The recovered map entry at `0x005DA4B8` maps private
message `0x0477` to handler `0x0046DBF0` (`CScreenDlg` descriptor
`0x005DA518`). The handler reads its first explicit message parameter and
calls helper `0x0046D5B0` for values zero and one. For value one, the helper
constructs the shared file-dialog object at `0x0046D646` with mode `1`; the
modal branch at `0x0047C463` routes nonzero mode to `GetOpenFileNameW`.
The dialog's filter buffer is copied from the UTF-16 literal at `0x005DA63C`,
`Image Files|*.png;*.jpg;*bmp||` (the `bmp` pattern is stored without a dot).
On the `IDOK` path, `0x0046D680`–`0x0046D6E9` obtains the selected path and
filename through the dialog helpers, and `0x0046D737` retains the resulting
path object for the following collection update.

The handler then inserts that object into the list rooted at
`CScreenDlg+0xE4`: with a nonempty list, `0x0046D877`–`0x0046D883` calls
indexed insertion helper `0x0043E810`; with an empty list,
`0x0046D88B`–`0x0046D892` calls append helper `0x0043E7B0`. It adjusts the
selected-index fields at `+0x110` and `+0x358` when the existing item count
requires it, calls cache/list rebuild helper `0x0046D900`, and invalidates
child windows stored at `+0xA8` and `+0x16C`. This closes a static path from
the `0x0477` message handler's value-one branch through an open-image dialog
and a local screen-editor collection update. The list entry's decoded image
representation and its exact relation to the `+0xE0` index structure and
`+0xF4` frame list are not established by this path alone.

**Confirmed statically.** The `CScreenDlg` child-window path constructs a
two-row menu, and selecting its second row posts `0x0477` with `wParam=1` to
the screen dialog. That reaches the value-one open-file branch above. The
visible label is not recovered, so the code does not prove that its text is
the locale key `tc_screen15` (“Import”). No image decoder, geometry validation,
or direct selected-path-to-frame-pixel conversion is shown in the message
handler. The separate cache builder's indexed source objects and F4 nodes
remain a distinct statically recovered path; runtime behavior and keyboard
acceptance were not observed.

## `0x0477` sender functions and screen context menu

**Confirmed statically.** Two functions in the same hash-pinned 4.06 image
contain literal `PostMessageW` calls that push message `0x0477`:

| Sender | Selected record and message parameters | Remaining edge |
| --- | --- | --- |
| `0x00433960` (call at `0x00433983`) | If `this+0x14D4 != -1`, uses that index with a `0x58`-byte stride from `this+0x88`; for the object created by the screen menu factory, this is row offset `+4`, copied from the row's second DWORD, and becomes `wParam`. `lParam` comes from `this+0x14D8`; target HWND is `this+0x74`. | Its `WM_LBUTTONUP` map entry and screen context-menu caller/factory are statically linked below. The menu labels remain unknown. |
| `0x004345C0` (call at `0x004345E6`) | If `this+0x1324 != -1`, uses that index with a `0x58`-byte stride from `this+0x1F8`; the DWORD at that selected address becomes `wParam`. `lParam` comes from `this+0x1328`; target HWND is `this+0x1E8`. | No static reference ties this second sender object to the screen context menu. |

Both functions pass their stored parent-window handle, selected row field, and
stored `lParam` to the `PostMessageW` IAT slot at `0x0059E738`, then refresh
through `0x00475257`. The first function is an RTTI-backed `CMenuDlg` method:
its constructor at `0x004337C0` writes vtable `0x005D20B4`, whose complete
object locator `0x005E4018` references type descriptor `0x00603928`
(`.?AVCMenuDlg@@`). Its map descriptor at `0x005D20A8` points to entries at
`0x005D2018`; the row at `0x005D2078` maps `WM_LBUTTONUP` (`0x0202`, signature
`0x35`) to `0x00433960`. The preceding row at `0x005D2060` maps
`WM_MOUSEMOVE` (`0x0200`, signature `0x35`) to `0x004339A0`. That handler
calls `USER32!PtInRect` through IAT slot `0x0059E7EC` at `0x004339C9` to test
the 16-byte rectangles rooted at `this+0x11B4`, then writes the selected row
index to `this+0x14D4`; button release submits that row.
The other sender's class and runtime parent remain unresolved.

The screen child-window dispatch at `0x0046D2A2` calls helper `0x0046DB00`
when the child at `CScreenDlg+0x158C` matches, the state at `+0x10C` is zero,
and the count at `+0xEC` is below global `0x00611834`. The caller passes the
`CScreenDlg` object as the helper's parent argument. The helper creates two
`0x58`-byte rows through `0x00433440`, passing `EDX=0xFF` and row indices
`0`/`1`; the second stack argument is also `0`/`1` and is stored at row offset
`+4`. The first DWORD `0xFF` is a row marker, not the posted value.

Menu factory `0x00433680` passes the row count and source list to
`0x00433840`. That routine copies each full `0x58`-byte row to the menu object
starting at `+0x84`, stores the parent HWND at `+0x74`, and stores the count at
`+0x80`. Sender `0x00433960` reads the selected row at
`this+0x88 + index*0x58`, which is the copied row's second DWORD (`row+4`),
and posts it to the stored parent HWND. This closes the static route from the
screen child, through the menu, to `CScreenDlg` message `0x0477`: row zero
posts `wParam=0`, and row one posts `wParam=1`. The handler's value-one branch
opens the image picker. The two menu labels and exact text shown to the user
remain unresolved; the other sender at `0x004345C0` has not been tied to this
menu.

## Boundary to the established transfer worker and writers

**Confirmed statically.** The `WM_INITDIALOG` dispatch starts worker
`0x00466450` through `0x00466820` and thread helper `0x0056DC08`, passing the
screen-dialog object as the worker parameter. The worker reads the frame count
and pointer array from this same object's `+0x3A4`/`+0x3A8` fields, converts
each image through `0x004661A0`, then passes the converted buffer, length,
frame index, and progress callback to device-object virtual slot `+0x4C`.

For the 4.06 `CDevG5KB` vtable at `0x005CBA2C`, the existing vtable map
resolves the worker's calls as follows:

| Worker slot | Resolved target | Static operation | Worker callsites |
| --- | --- | --- | --- |
| `+0x58` | `0x0040D0D0` | Reset screen-transfer cancellation state | `0x004664C1` |
| `+0x50` | `0x00412890` | GIF metadata writer, command `0x0D` | `0x00466600`, `0x00466651`, `0x0046674B` |
| `+0x4C` | `0x00412F20` → `0x00412B10` | Frame/page writer, command `0x0C` | `0x004666CC` |

This establishes a static UI-to-worker-to-G5-writer route for the multi-frame
transfer branch, conditional on the active device object using the recovered
G5 vtable. The 4.06 profiles advertising screen support route statically to
G5, but runtime profile selection, physical device identity, protocol
acceptance, and visible transfer success were not observed. The worker does
not call the adjacent G5 `+0x48` screen-parameter slot (`0x00410230`, command
`0x0B`) in this path; its UI caller remains unresolved.

The exact UI meaning of the copied numeric field, frame-value mapping into
command `0x0D`/`0x0C` arguments, and when the cache/list is initialized for a
selected profile remain unresolved. The NewPNG/NewGIF save-as result is not
shown to populate `CScreenDlg+0xF4`; the separate one-image PNG branch is not
shown to reach the multi-frame worker. The `0x0477` value-one route proves an
open-file selection and an update to the screen editor's local item list, but
does not prove that this selected file becomes a frame node in F4 or reaches
the transfer worker.

The available click-handler block reads no `ShowScreen` field directly. It
has a positive frame-count condition and calls the device object's virtual
`+0x28` gate; whether that gate implements profile eligibility, connection
readiness, or both is unresolved. Existing profile parsing proves that
`ShowScreen` gates loading screen-related profile settings, but not that this
specific UI action uses that field as its gate.

## Bounded conclusion

The 4.06 screen editor has a concrete child-window route that processes the
same `CScreenDlg+0xF4` item collection later copied by the transfer action into
the modal's frame array. NewPNG/NewGIF are save-as routes. Separately, the
`CScreenDlg` message-map entry for private message `0x0477` reaches an
open-file-dialog branch that inserts the selected path object into the local
list rooted at `+0xE4` and calls the cache/list rebuild helper. The visible
sender route is closed through the screen's two-row menu: its second row posts
value one and opens the picker. The visible labels and relation between the
imported path object and the F4 transfer-frame collection remain unresolved.
A separate cache-rebuild helper also constructs F4 nodes from indexed source
objects.
The transfer action
gates on the device object's `+0x28` method and a nonempty frame list. Its
`WM_INITDIALOG` route starts the frame worker, whose converted frame buffers
and GIF metadata reach the statically mapped G5 command `0x0C` and `0x0D`
writers. This is a static write
path, not proof that the connected keyboard selected that family or accepted
any payload. Cache/list initialization for a selected profile, relation of the
`0x0477`-inserted item to F4, exact pixel layout, physical-device
compatibility, and runtime outcome remain unresolved.
