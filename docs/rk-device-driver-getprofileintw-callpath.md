# DeviceDriver `GetProfileIntW` call-path audit

## Scope and input identity

This note resolves the five register-indirect calls to
`KERNEL32!GetProfileIntW` in the installed 4.06 `DeviceDriver.exe` by tracing
their arguments, UTF-16 literals, and result stores. The inspected executable
is the installed-image hash `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
It was not executed; no keyboard, HID interface, or updater was accessed.
Addresses below are image virtual addresses.

## Recovered call paths

The import pointer is loaded from IAT VA `0x0059E2DC` at `0x0050DAC8` and
`0x0055D068`. Both routines use x86 `stdcall` argument order. The arguments
below are the values pushed immediately before each indirect call:

| Call site | Section (`lpAppName`) | Key (`lpKeyName`) | Default (`nDefault`) | Result destination | One-time guard |
| --- | --- | --- | ---: | --- | --- |
| `0x0050DADB` | `windows` (`0x005B23A0`) | `DragMinDist` (`0x005B23B0`) | 2 | global `0x00607B44` | `0x00607B4C` |
| `0x0050DAED` | `windows` (`0x005B23A0`) | `DragDelay` (`0x005B238C`) | 200 | global `0x00607B48` | `0x00607B4C` |
| `0x0055D07B` | `windows` (`0x005B23A0`) | `DragScrollInset` (`0x005BF3D0`) | 11 | global `0x00608A50` | `0x00608A5C` |
| `0x0055D08A` | `windows` (`0x005B23A0`) | `DragScrollDelay` (`0x005BF3B0`) | 50 | global `0x00608A54` | `0x00608A5C` |
| `0x0055D099` | `windows` (`0x005B23A0`) | `DragScrollInterval` (`0x005BF388`) | 50 | global `0x00608A58` | `0x00608A5C` |

In the routine beginning at `0x0050DA88`, the code checks guard
`0x00607B4C`; if it is zero, it reads the two values, stores their results,
and sets the guard to one. The routine beginning at `0x0055D024` applies the
same pattern to the three drag-scroll values and guard `0x00608A5C`. This
explains why the import's five IAT references are calls through a register,
not direct `call [IAT]` instructions.

## Recovered result consumers

The immediate global consumers close the next step of each path:

- In the routine around `0x0050D92A`–`0x0050DA3C`, the code calls
  `GetTickCount` and compares the elapsed value against `DragDelay` at
  `0x0050DA23`. If the elapsed value exceeds the configured value, it sets
  object state `+0x34`. `DragMinDist` is loaded in helper `0x0050DB2E` and
  passed as both size arguments to `InflateRect` at `0x0050DBB3` before a
  subsequent object-method dispatch at `0x0050DBC3`. The constructor writes
  vtable `0x005B23CC`; its `+0x58` entry resolves to `0x0050D92A`, the routine
  that applies the `DragDelay` comparison. This connects the rectangle
  threshold and elapsed-time checks through a statically recovered vtable
  edge.
- In the routine around `0x0055CA86`–`0x0055CCB8`, `DragScrollInset` is
  negated and passed as both size arguments to `InflateRect` at `0x0055CB31`;
  the resulting rectangle is checked through `PtInRect` at `0x0055CB47` and
  `0x0055CB5B`. `DragScrollDelay` is copied into object field `+0x30` at
  `0x0055CC3E` and compared with an elapsed tick count at `0x0055CC47`.
  When the threshold is exceeded, the code calls an object vtable method and
  then copies `DragScrollInterval` into the same field at `0x0055CC79`. The
  `0x005BF3F4` vtable's `+0x180` entry resolves to `0x00477F76`; the alternate
  object's `+0x140` entry resolves to `0x0049C659`, whose body returns one.
  The former body begins by reading object state and dispatching another
  method, so the final scrolling side effect is not inferred from the vtable
  slot alone.

This statically links all five profile values to Windows rectangle, cursor,
and tick-count handling in host-side drag/drop-style code. The inference that
these are framework drag thresholds/auto-scroll controls follows the literal
key names and value flow. The exact user-visible RK screen or control that
reaches these helpers is not established.

## Confidence and limits

- **Proven statically:** the import/IAT identity; five indirect call sites;
  the section/key strings; the numeric defaults; the destinations for
  returned values; both guarded initialization blocks; and the immediate
  rectangle/tick-count consumers and recovered vtable targets for these
  values.
- **Inferred:** these are framework drag thresholds and drag-scroll timing
  settings. This follows from the literal key names and code flow, not from a
  recovered application UI label or observed runtime effect.
- **Unresolved:** the actual values returned on this PC; profile/registry
  mapping and precedence; which higher-level screens or controls instantiate
  the objects; and any runtime effect.

`GetProfileIntW` takes a section name, key name, and default value; Microsoft
documents that it reads an integer and returns the default if the key is not
found. That API contract helps interpret the recovered stack arguments but
does not prove which backing store Windows uses on this machine:
[Microsoft `GetProfileIntW` documentation](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprofileintw).

The address inventory for these five sites remains in
[`rk-native-api-indirect-call-audit.md`](rk-native-api-indirect-call-audit.md).
