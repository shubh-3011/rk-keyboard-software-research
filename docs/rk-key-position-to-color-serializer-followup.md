# RK 4.06 key-position mapping to color serializer follow-up

This static follow-up closes a data-flow gap between two `CLedDlg` private
message handlers and the family-specific per-key color serializers. Evidence is
for `DeviceDriver.exe` 4.06, SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
The hash was revalidated against the local image before inspecting the call
sites. No RK program was launched, no HID interface was opened, and no report
was sent.

## Handler data flow

`CLedDlg` message-map rows identify private message `0x0482` as handler
`0x00422640` and `0x0481` as handler `0x00422780`.

- At `0x00422640`, the handler walks the selected-position list using the
  profile position table at `0x00611384` and count at `0x006114D4`. It skips
  invalid positions and writes the chosen mapping value to each eligible
  position record's `+0x9C` field (`0x00422690`–`0x004226CB`). The chosen
  value comes from `0x00612AF0`, or from the current page child at
  `this+0x2C38+0x74` when `0x006117C4` is set. It calls `FUN_00425440` at
  `0x004226E2` to copy the updated dialog state into the active profile.
- At `0x00422780`, the handler validates one position index and toggles that
  position's `+0x9C` mapping field between zero and the selected mapping value
  (`0x0042281A`–`0x0042287B`). It then calls the same
  `FUN_00425440` helper at `0x00422883`.
- Both handlers derive a dirty-group bit as `1 << activeRoot[0x25C0]` and OR
  it into `activeRoot+0x25C4` (`0x004226E7`–`0x004226F6` and
  `0x00422888`–`0x00422895`). If `0x00611794 != 0`, they store mask `4` at
  `0x0061972C` and release semaphore `0x00619724` (`0x00422703`–`0x0042271A`
  and `0x004228A2`–`0x004228B9`). Thus these two callsites bypass
  `FUN_00401080` but wake the same worker with the same shared mask field.

## Dialog-to-active-profile copy

`FUN_00425440` obtains the active root from `0x0062B388` and reads its current
profile index from `root+0x213C`. For the per-key-color profile selected by
`0x006117CC`, it reads the selected group from dialog `this+0x24FC`, stores
that word at `root+0x25C0`, then copies 132 DWORD values into
`root+0x25C8 + group*0x210` (`0x00425523`–`0x00425564`). The source pointer is
dialog `this+0x2C74`; the loop reads each position record at `+0x9C` and
advances by `0x24` bytes. The loop bound is `0x84` entries. The helper has a
separate branch for selected page index `0x1E`; the color-group copy is only
on the non-`0x1E` path and only when the active profile index equals
`0x006117CC`.

This establishes a static bridge from position selections to the active
profile's color-group table and then to the dirty group bit. It does not
identify the visible widget labels, mapping-value meaning, active physical
device, or runtime execution.

## Conditional family serializer destinations

The existing static serializer traces show where mask `4` can lead, depending
on the worker's concrete receiver:

- `CDevRKKB` vtable slot `+0x3C` targets `FUN_00413BF0`. Its flag-`0x04`
  branch is selected-profile gated and reads the same group table at
  `config+0x25C8+group*0x210`; it builds the per-key-color payload with prefix
  `03 7E`.
- `CDevG5KB` slot `+0x3C` targets `FUN_00411B90`; the selected-profile-gated
  flag-`0x04` path serializes dirty color groups as command `6`.
- `CDev3632` slot `+0x3C` reaches `FUN_00411B90` through wrapper
  `FUN_0040E690`; the corresponding color-group command is `2`.

These are conditional static destinations, not proof that the audited PC's
worker held one of these classes or that any physical keyboard received data.
The worker receiver, active profile at runtime, and device acceptance remain
unobserved. See the [Apply signal caller list](rk-apply-signal-callers.csv),
[worker dispatch audit](rk-settings-apply-worker-audit.md),
[serializer audit](rk-setting-serializer-audit.md), and
[key-position message audit](rk-led-key-position-message-followup.md) for the
separate evidence records.
