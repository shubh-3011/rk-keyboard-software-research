# V4.6 native API feature-path follow-up

## Evidence boundary

This follow-up statically traces three native API paths in the 4.6-labeled
`DeviceDriver.exe`, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
The binary was not run. No RK process, browser, HID handle, or keyboard was
opened by this analysis, and no device data was sent or changed. Addresses
below are VAs for the PE image base `0x00400000`.

The parent import/callsite ledger remains the inventory for this binary.
These traces refine purpose for the four imports added relative to installed
4.06; they do not prove control-flow reachability or runtime behavior.

## `USER32!SendInput`: host Unicode input synthesis

The 4.6 import at IAT VA `0x005A66DC` is called directly at `0x0045877A`
from helper `0x00458680`. That helper takes a UTF-16 string pointer, counts
UTF-16 code units, allocates `0xE00` bytes, and processes at most 64 code
units per batch. For each code unit it builds two 28-byte `INPUT` records:
keyboard input with Unicode scan code and flags `0x0004`, then the matching
key-up record with flags `0x0006`. It calls `SendInput` with `cbSize=0x1C`.
The code constructs host OS input records; this path does not call a keyboard
HID feature-report writer.

One decoded caller is at `0x0044B1BF`. Its surrounding code gates on two
numeric values (`EDI == 10` and `ESI == 0x5B`), looks up a key in a 50-entry
table at `0x0060D3C4` with `0x404`-byte stride through helper `0x0041F480`,
and passes the UTF-16 text at the matching record's `+4` to `0x00458680`.
The table occupies `0xC8C8` bytes, matching the size read/written by the
separate `textmacro.dct` helpers. This is consistent with text-macro playback
and uses the same fixed table that those helpers persist. The numeric gate
fields and visible UI trigger remain unresolved. See
the [local text-macro path audit](rk-v4.6-textmacro-path-audit.md).

## GDI+ image-frame timing and selection

The added `GdipGetPropertyItemSize` and `GdipGetPropertyItem` imports are
called through thunks at `0x0046F34C` and `0x0046F376`. In the surrounding
routine `0x0046F210`, the image's frame count is checked. When it has multiple
frames, code requests property identifier `0x5100`; if the property query
succeeds, the first DWORD in the returned item is multiplied by ten and
stored as the interval. The fallback interval is 100 milliseconds.

Caller `0x0046F060` stores the returned frame count and delay in object fields
`+0x60` and `+0x64`. The control path at `0x0046F0B0` starts timer `0x777`
when the frame count exceeds one. Timer handler `0x0046F150` selects the next
frame through `GdipImageSelectActiveFrame` thunk `0x005908F0` at
`0x0046F1A6`, wraps the frame index at the stored count, and invalidates the
window. This establishes an animated-image display path in the driver. It
does not identify the model-specific image, prove the feature is reachable,
or show that an animated frame is transferred to the keyboard; the separate
[screen/GIF transport trace](rk-v4.6-screen-gif-ui-transport-audit.md) keeps
that connection unresolved.

## `GetPrivateProfileStringA`: `OPT` / `TouchWeb` setting

The added `KERNEL32!GetPrivateProfileStringA` import at `0x005A63C8` is called
at `0x00456748`. The call supplies section string `OPT`, key `TouchWeb`, a
null default, a 50-byte result buffer at `0x00629EA0`, and a filename produced
by path helper `0x004587C0`. When the result buffer is empty, code copies the
literal `https://drive.rkgaming.com` into the same buffer. The value is later
copied into a model-dialog object's string field at `+0x5EC1` from the
initialization path at `0x00460999` and a `CKeyDlg` handler at `0x0041D0DD`.
The handler is `0x0041CF20`, present in the message map at `0x005D4CA0`; its
branch copies the value when the selected row is type `0x0B` or matches global
index `0x0062A27C`. The visible control label/origin for that branch remains
unresolved.

Consumer `0x00412906` reads the NUL-terminated field, logs it with the
`SendWeb: ` prefix, then calls `0x00410C90` with the string, object, and byte
length. The dispatcher has two static branches: when the object has no direct
handle but has a child object at `+0x254`, it calls `0x0040DF10` with selector
`0x12`; when the object has a direct handle, it calls `0x0040FFD0`, also with
selector `0x12`, passing the string length and the byte at object `+0x2DC` as
separate arguments. The dispatcher returns the internal helper's success
status. This maps the setting into RK-specific action/command handling; it
does not establish an opened browser, a successful report transfer, or what
the device does with the string. The exact configuration-file path/value and
runtime reachability remain unresolved. No direct static browser-launch call
was identified in this trace.

This ANSI import is absent from the installed 4.06 import table, but that
alone does not prove the entire setting or behavior was newly introduced.

## Conclusions and limits

**Proven statically:** the exact 4.6 image contains a host `SendInput` path,
an animated-image frame/timer path using the two added GDI+ property APIs, and
an `OPT` / `TouchWeb` profile-string read with an RK Drive URL fallback that
feeds selector-`0x12` RK action/command helpers.

**Inferred:** the input helper likely serves text-macro playback, and the
property lookup likely supplies animation timing. Those names are not assigned
to unidentified controls or state fields.

**Unresolved:** reachability, the actual profile filename/value, the
visible `TouchWeb` control origin, which model uses each UI path, and any
runtime device effect. The host input path is not evidence of keyboard
firmware access or a HID write.
