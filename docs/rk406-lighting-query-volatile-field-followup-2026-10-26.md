# RK 4.06 lighting query: changed fields and normalization boundary

## Outcome

**Keep the existing exact-fingerprint refusal.** The two saved queries differ
at three bytes despite both having mode zero. Static evidence establishes how
those bytes reach the host and how the ordinary vendor packer treats `0x38`;
it does **not** establish a safe volatile-field normalization rule for any of
the three differences. In particular, `0x32/0x33` are not proven battery fields.

This investigation only read saved artifacts and the installed PE. No vendor
process was executed or attached, no hardware interface was opened, and no
writer policy, code, fixture, or saved evidence was changed.

## Identity and evidence

All instruction addresses below are preferred image VAs (image base
`0x00400000`) in installed `C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe`.
Its SHA-256 was independently recomputed during this investigation:
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
PE address translation used existing `pefile`; x86-32 decoding used existing
Capstone, starting at the named function entries, not an arbitrary interior
offset. This is offline static evidence, not an execution trace.

Retained corroboration:

- `.research/rk406-rea-objdump-2026-10-26.json`, REA Evidence
  `ev_3cd9be563f80334bed8ef1a62351127206977c720e5f87b695d9c1574454eb74`:
  full objdump disassembly bound to the same executable digest.
- Local, uncommitted Ghidra export
  `../_rk_analysis/reports/device-targeted-functions.txt`, sections at lines
  176 (`0x411B90`), 882 (`0x40FAD0`), and 1695 (`0x411900`).
  Some exported functions are truncated and some inferred calling conventions
  omit register arguments; exact instructions take precedence.
- Committed query [native-wireless-lighting-read-2026-10-26.json](runtime-evidence/native-wireless-lighting-read-2026-10-26.json),
  file SHA-256 `bffcf9c5f9c127687bbc5c121eb82f9150e5510217d1bf3a0148facc3a19a6fb`.
- New local query `.research/native-mode-awake-before-2026-10-26.json`,
  file SHA-256 `fa4e5a2516bd3f08d57217b21fb15006c25f81aa6a581ea7016bbc2d9de05b8f`.
  The new query is not committed by this follow-up.

## What actually changed

Both JSON files contain 128-byte `LightingBlockHex` values; both have byte
`0x0A = 00` and trailing `5A A5`. Comparing every byte yields exactly:

- `0x32`: `FF` to `49` (new value decimal 73).
- `0x33`: `01` to `00`.
- `0x38`: `FF` to `14` (new value decimal 20).

These are block offsets, not report offsets. On ordered 14-byte framing,
`0x32/0x33` occupy zero-based frame 3, report bytes 13/14; `0x38` occupies
frame 4, report byte 5. They are inside response payload, not report-header
status or the report's final byte.

The saved failure `.research/native-mode-awake-apply-first-2026-10-26.json`
records `VerifiedByQuery: false` and the exact-fingerprint rejection. That
failure JSON alone is not a wire capture or an independent count of writes;
the existing policy rejects this block before authorizing configuration sends.

## Query producer and consumer: no host battery overlay

**Proven static, wireless branch.** `FUN_0040FAD0` takes its destination in
`ECX`. At `0x40FAF7–0x40FB1D`, when the ordinary handle is absent and the
child at device `+0x250` exists, it calls `FUN_0040DA80` with command `0x44`,
that same destination, and length `0x80`. It returns the helper result through
the common epilogue. There is no post-call field population in this branch.

`FUN_0040DA80` builds the 20-byte query at `0x40DAE0–0x40DB60`: marker
`0x13`, caller command, count `1`, zero index and payload, additive outgoing
checksum. It sends through `0x40E0F0`. At `0x40DBBD–0x40DBCB`, it obtains
matching records through `0x40D370`. After duplicate-index handling, it reads
the reply payload length from report byte 4, masks with `0x0F`, caps at 14 and
the requested length, and copies report bytes beginning at byte 5 into the
caller destination plus the accumulated byte count (`0x40DC17–0x40DC67`,
copy call `0x40DC5F`). It tracks completion at `0x40DC6B–0x40DC8C`.
There is no assignment of battery/power values into block `+0x32/+0x33` or
`+0x38` in this path.

**Proven static, G5 feature branch.** `0x40FB8E–0x40FBAA` prepares command
`0x84`; `0x40FBBE` sends the feature request; `0x40FC19` gets the reply.
After checking command `0x84`, `0x40FC2E–0x40FC41` copies from feature-buffer
payload offset 12 to the caller destination. It likewise does not manufacture
the three changed block bytes.

**Independent replacement decoder evidence.**
`rebuild/windows/WirelessLightingReader.cs:28–43` concatenates exactly report
payloads at offset 5, checks `5A A5`, and returns the bytes. Lines 139–147
skip non-`0x44` records, explicitly including `0x0A`. Thus the native JSON
block is reassembled received payload, not a vendor-populated object overlay.
The two JSON files do not retain their individual incoming reports, so this
does not independently authenticate each historical input frame.

**Boundary:** “received payload” does not mean “all persistent settings.”
Firmware or receiver code could populate live status inside a query response.
Neither firmware provenance nor such an overlay's layout is recovered here.

## Separate battery/status consumer actually found

`FUN_0040D2E0` tests report byte 1 against `0x0A` at `0x40D2E0–0x40D2E4`.
For these status reports it can set child field `+0x260` when byte 5 is 2
(`0x40D301–0x40D30F`). It packs report bytes 5, 6, 7 into the low three bytes
of a window-message argument and posts message `0x7EB`
(`0x40D32D–0x40D355`). Other report commands are queued unchanged as 20-byte
records at `0x40D35C–0x40D365` for the query consumer.

The static message-map record at `0x005D4C68` associates `0x7EB` with handler
`0x004487E0`. That handler extracts the low byte as a subtype. When subtype
is 5, it stores the next two bytes into the settings-dialog object at
`+0xE6C` and `+0xE6D` (`0x448848–0x448873`) and invalidates its display area.
Power painting consumes `+0xE6D` as high/low nibbles
(`0x457AF5–0x457AFB`, `0x457C26–0x457C32`) and uses `+0xE6C` to scale a fill
and format displayed text (`0x457DB9–0x457DCD`, `0x457EF0–0x457EFD`).
This supports power-level/status semantics for **that separate UI state**.

There is also a distinct two-byte power query: `FUN_0040DE50` asks
`FUN_0040DA80` for command `0x4A`, length 2 (`0x40DE50–0x40DE64`), then
zero-extends each returned byte into caller outputs (`0x40DE69–0x40DE84`).
The corresponding G5 helper `0x40FD10` requests command `0x87` and returns
two bytes (`0x40FDD1`, `0x40FE93–0x40FEAF`); the adjacent diagnostic is
`GetPower failed` at `0x005CAC3C`.

**Not established:** no data-flow edge recovered here connects these power
outputs or `+0xE6C/+0xE6D` to lighting-block `+0x32/+0x33`. Decimal 73 is
compatible with a percentage but is not proof of one. `FF 01` versus `49 00`
must not be labeled battery percentage/charging flags as a settled result.

## Apply and the reason `0x38` becomes `FF`

**Proven static.** In `FUN_00411B90`, apply mask bit `0x02` selects lighting
(`0x411FE2–0x411FEE`). The 128-byte local block starts at `[ESP+0x3C]`;
`0x412050–0x412069` clears it and queries it. Signature checking occurs in
**Apply**, at `0x4120D4–0x412106`, not inside `FUN_0040FAD0` itself.

Apply chooses the special packer `0x411700` when device field `+0x24C` is 2;
otherwise it calls ordinary packer `0x411900`
(`0x412121–0x41214E`). The latter modifies the freshly queried block, then
the wireless branch sends command 4, length `0x80`
(`0x412179–0x4121B2`).

In ordinary `FUN_00411900`, these instructions are unconditional after the
optional profile override loop and mode/header packing:

```text
004119F2  mov al, 0xff
004119F4  mov byte ptr [esi+0x39], al
004119F7  mov byte ptr [esi+0x38], al
```

This initializes a **pair**, not an isolated status byte. The following
lighting-record loop writes two-byte records using one of these destinations:

- Profile-mapped mode number `m`: `0x38 + 2*m`
  (`0x411A35–0x411A3B`).
- Unmapped/index layout: `0x3A + 2*i` (`0x411A0D`, `0x411A41`).

At `0x411A4D–0x411A65`, the first byte comes from brightness lookup table
`0x611868` indexed by runtime record `+4`. The second combines runtime
record `+0` shifted left four with the low nibble of record `+0x0C` (or
literal 7 when record `+0x2C` is nonzero). Masked records are skipped.
Consequently a mapped `m=0` can overwrite `0x38/0x39` after initialization;
an unmapped layout starts at `0x3A` and leaves this initial pair alone.

**Interpretation:** `FF FF` is an explicit packer initialization/sentinel-like
pair at the base of the ordinary per-mode record area. Why firmware returns
`14 FF` in the new query, and whether `14` denotes an active brightness value,
scratch state, or something else in this device revision, remain unknown.
It is not proven to be battery data, random padding, or safe to discard.
The fact that a vendor packer overwrites a field does not make it volatile.

Within the ordinary packer, no dedicated fixed store to `+0x32/+0x33` was
found. The early optional mask-`0x10` override loop can write arbitrary
profile-supplied byte offsets (`0x411980–0x4119AF`); therefore an absolute
claim that the vendor can *never* write these offsets would also be false.

## Normalization decision and remaining unknowns

- **Only `0x0A` is currently normalized for eligibility**, because the retained
  Off/first-effect round trip establishes that mode-only mutation. It is a
  controlled setting, not a volatile status field.
- **Do not additionally normalize `0x32`, `0x33`, `0x38`, or `0x39`.** No
  captured round trip establishes writing from this new baseline. The
  committed fixture's two phases retain `FF 01` at `0x32/0x33` and `FF FF`
  at `0x38/0x39` across every read/write/echo block. It covers no changing
  values at these offsets.
- **Do not normalize any bytes for exact-baseline freshness or complete
  readback comparison under the current contract.** Eligibility's mode
  normalization is not permission to hide changes during a transaction.
- Never replace the received block with the old fixture, “repair” the three
  bytes to the old values, apply the whole vendor packer as a normalization
  operation, or weaken endpoint/signature/mode guards to get past rejection.
- A future proven status-only field might justify a separate semantic
  comparison rule, but would not automatically prove that replaying its old
  value on command 4 is harmless. Both comparison and write treatment need
  independent evidence. No such change is proposed here.

Answered: raw host data path, separate status-message path, exact ordinary
pair initialization and mapped consumers, conservative rejection rationale.
Partially answered: `0x38` has a statically demonstrated per-mode-record role,
but the new returned value's device meaning is unresolved. Unresolved:
firmware producer and exact semantics/persistence of `0x32/0x33`, the source
and lifetime of the new `0x38 = 14`, and safe command-4 behavior for this new
baseline. Two query snapshots alone cannot establish volatility or causality.
