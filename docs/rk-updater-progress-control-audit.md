# RK updater progress-control static audit

## Scope and evidence

This note traces progress-control bindings and position updates in the pinned
`Dev/01AF/Update.exe` x86 image, SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`.
Evidence is from the PE dialog resource, the initializer and call-site
disassembly. The updater was not launched; no keyboard, HID interface, or
serial port was accessed.

## Control mapping

**Direct:** resource 102 declares `0x0413` and `0x041B` as
`msctls_progress32` controls. Dialog initialization at `0x00406F70` binds
`0x0413` to the MFC control wrapper at `this+0xE8` and `0x041B` to the wrapper
at `this+0x8DF4`. In this object layout, the wrapper's HWND member is at
`+0x20`, making the first HWND `this+0x108` and the second `this+0x8E14`.
The statically resolved `SendMessageW` position calls target `this+0x108`;
together with the resource class and `PBM_SETPOS` message ID, this maps those
calls to control `0x0413`.

The initializer also hides control `0x041B` at `0x0040711B`. A direct scan
found no send to its `this+0x8E14` HWND. Its role beyond being a second,
initially hidden progress bar remains unresolved; indirect aliases are not
excluded.

## Position updates

`PBM_SETPOS` is `WM_USER+2`, message `0x0402`. The 14 statically resolved
`SendMessageW` sites below pass the `0x0413` HWND at `owner+0x108`. Thirteen
call sites call the `SendMessageW` IAT entry directly. At `0x004084EA`, the
code calls through EAX after loading the same IAT entry at `0x004084CC`, so
that one API call is statically resolved but register-indirect. Formula
interpretation is noted separately.

| Call sites | Position evidence |
| --- | --- |
| `0x0040849E`, `0x00408808`, `0x0040908C` | **Direct:** calculate a position from the completed chunk count and total byte length before sending. **Inferred:** the expression is `trunc((completedChunks * 4096 / totalBytes) * 100)`, where `completedChunks` is block index + 1. The `4096.0` and `100.0` constants are present in `.rdata`. No explicit clamp was recovered. |
| `0x004084EA`, `0x0040C29D` | **Direct:** send position zero; these are progress resets on the state-4 completion path and transfer-worker outcome/cleanup path, respectively. `0x004084EA` is the register-indirect call described above. |
| `0x00408E1E` | **Direct:** sends position 100 on the `C0 3F` branch in state 8. |
| `0x004024BC`, `0x00402A22`, `0x00403163`, `0x004034B8`, `0x00403722`, `0x00403926`, `0x0040B953`, `0x0040C04B` | **Direct:** send a computed/dynamic position. The expression and relationship to a particular `0x0419` runtime branch are not resolved in this note. |

This gives 14 position-message call sites: 13 direct IAT calls plus the one
statically resolved register-indirect call at `0x004084EA`.
`0x0052941C` is a separate internal call, not an additional
`SendMessageW`/`PBM_SETPOS` site.

## What this closes and what remains open

The consumer mapping for the `0x0402` position calls is closed statically to
progress control `0x0413`; it is not an unresolved window receiver. The
three chunk-state formulas are also traced to chunk count and total length.
This does not prove which handler is reached for a given selected firmware,
device, or click. The second progress control `0x041B` has no direct position
update found. The imported `SetTimer` reference inventory found no window
timer creation for the `WM_TIMER` handler's IDs 2, 3, or 4; their
scheduling/delivery source remains unresolved. Ownership of the other timer
IDs, dynamic aliases, and the relationship between the UART state machine
and the `0x0419` button workflow remain unresolved. See the
[timer-origin audit](rk-updater-timer-origin-static-audit.md). These limits
are separate from whether the binary contains transfer routines capable of
HID writes.

## Related evidence

- [`rk-updater-command-0419-static-path-audit.md`](rk-updater-command-0419-static-path-audit.md): click-to-worker trace and timer limits.
- [`rk-updater-uart-state-machine.md`](rk-updater-uart-state-machine.md): 15-state serial receive dispatcher.
- [`rk-dialog-resource-audit.md`](rk-dialog-resource-audit.md): updater resource controls and recovered message map.
- [`rk-firmware-readback-audit.md`](rk-firmware-readback-audit.md): `.upf` parser and HID transfer/readback boundaries.
