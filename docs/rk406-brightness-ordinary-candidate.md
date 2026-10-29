# Installed 4.06 G5 ordinary brightness: offline candidate comparison

The existing Ghidra export of `FUN_00411900`, for the installed executable
SHA-256 `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`,
shows a conditional ordinary packing loop. When its mapping sum is not positive,
the row offset starts at `0x3a` and advances by two; for unmasked rows the
translated brightness index is assigned to that offset. A separate selected
special-row branch writes `0x5e`. The export uses an implicit register for
the destination; its context and live device binding still need corroboration.
The existing static instruction audit, including REA objdump evidence
`ev_3cd9be563f80334bed8ef1a62351127206977c720e5f87b695d9c1574454eb74`,
corroborates selected field accesses but is partial, not a complete execution trace.

Fresh REA/Ghidra 12.1.4 pseudocode evidence
`ev_4dc2ac51b0908c98812ff8bc9d4cdefe507cdf89424985e3fe1364fc25b9f364`
independently recovers this loop and a preceding conditional reset-item path:
when apply flags contain `0x10`, configured index/value pairs can write other
offsets. The offline model requires explicit flags and refuses that branch;
it does not infer flags from a user-selected profile. This is decompiler output
for a hash-bound static image, not proof of execution or device identity.

`scripts/rk406_brightness_candidate.py` independently implements a **strict
subset as an offline comparison aid**: bounded rows, exactly zero mapping sum,
unmasked row, no selected special row, and no `0x10` reset flag. It compares three caller-supplied
128-byte blocks, reports every differing offset and exact restoration, and
always returns `hardware_write_authorized: false`. It does not obtain inputs,
change the keyboard, infer a family from VID/PID, or establish causation.

Before this becomes an actual control, independently bind the active vendor
profile, serializer branch and transport; capture one brightness-only change
and restoration with independent readbacks; and examine *all* changed bytes.
A matching candidate offset on its own is not sufficient. No new brightness
write is enabled.
