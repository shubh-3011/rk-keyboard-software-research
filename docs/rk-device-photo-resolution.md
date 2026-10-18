# Connected device and product-photo resolution

## Current behavior

The Windows app periodically enumerates present Plug and Play metadata through
SetupAPI. It matches catalogued VID/PID pairs without opening the HID interface.
When a unique software profile has the same direct product ID, the app uses that
profile name and region as the primary photo key. It no longer lets a conflicting
RK Drive alias for a shared ID override a more specific profile.

For example, the 4.6-labeled profile catalog contains `RK-S98 Keyboard` profile
`021E`, region `ANSI`; the RK Drive catalog labels PID `021E` as `RK-S98 POR`.
The old lookup selected the Drive row first and could show Portuguese keycaps for
the ANSI profile. The new lookup uses the exact profile name/region first, which
selects the generic S98 image for that ANSI profile. Region-specific profiles use
their matching image where the image registry contains one.

If the device identity maps to multiple product labels, the overview offers the
available images in a selector. A selection is remembered per device ID or
software profile in the user's local settings. This resolves visual ambiguity
for the user; it does not make a shared receiver ID uniquely identify the
keyboard.

## What the device ID cannot tell us

The public model catalogs do not map S98 case finishes or keycap colorways to
distinct USB product IDs. The native app now offers six official S98 appearance
photos from RK's public product pages and remembers a user-selected photo for
the connected device/profile. This is a manual appearance choice, not a finish
detected from the USB identity. PnP metadata also does not report the currently
active RGB effect or color, so the app does not present a product photo as a
live view of keyboard lighting.

Product photos load from RK Drive or RK's public store over HTTPS. They are not
bundled in the executable or repository, and an internet connection is needed
to fetch an image. The S98 appearance list is documented in
[`s98-appearance.json`](../s98-appearance.json); it is not a complete inventory
of all RK finishes or later models.

## Scope and safety

This behavior is not a full device protocol implementation. It does not open a
HID report interface, read or write lighting state, send a keyboard command, or
change the physical keyboard. `models-4.6.json` and `rk-drive-catalog.json` are
the bounded sources used for the matching; neither proves compatibility with
all physical revisions.
