# RK 4.6 mode-3 status-probe to section-worker follow-up

## Scope and identity

This follow-up resolves the next static call edges after the mode-3
`0603:1021` status probe in the packaged x86 image
`app/Dev/01AF/Update.exe`, SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`.
Addresses are image VAs for this exact PE. The earlier
[preflight audit](rk-v4.6-update-mode3-hid-preflight-audit.md) documents the
HID selectors and probe report. This note follows the probe's response branch
through the second worker and conditional `FUN_00406BD0` creation.

Only static disassembly was used. The updater was not launched, and no HID,
serial, or keyboard access occurred.

- **Direct** means the instruction, branch, API call, or object/global access
  appears in this image.
- **Inferred** means a relationship follows from the static branch/data flow
  but was not observed at runtime.
- **Unresolved** means static evidence does not establish the result.

## Probe response branch and first follow-on thread

`FUN_00409760` (`0x00409760`) builds a feature report beginning `05 C9 60`
and calls `HidD_SetFeature` through the IAT at `0x004097A8`. It then polls
with `HidD_GetFeature` at `0x0040980D`, using a loop counter initialized to
5 at `0x004097BE`; each pass sleeps 1,000 ms at `0x004097D0`. The returned
bytes are copied from the read buffer to a local response buffer at
`0x00409813`–`0x0040981C`.

**Direct:** when response byte 0 equals `0x60` and response byte 2 equals
zero (`0x0040981F`–`0x00409828`), the code sets global byte `0x005C5F08` to
1 at `0x00409888`, updates dialog controls/status, kills dialog timer ID 2
at `0x0040989B`–`0x004098A0`, and creates a thread with start address
`0x00406C20` at `0x0040992D`–`0x0040993D`. The helper returns the value of
`0x005C5F08` in `AL` at `0x00409943`–`0x0040994E`.

The mode-3 caller `FUN_0040A0F0` invokes the probe at `0x0040A35A`, tests
`AL` at `0x0040A35F`, and returns through its epilogue when it is nonzero
(`0x0040A361` to `0x0040A570`). Thus the successful response branch's
follow-on work is carried by the separate `0x00406C20` thread; the caller
does not itself create `0x00406BD0` on this edge.

## Second worker and mode-3 transition branch

Thread routine `0x00406C20` receives the dialog pointer as its first argument
and passes that object in `ECX` to `0x0040B770` at `0x00406CE8`. It then
releases its thread-side state and returns. `0x0040B770` calls
`0x0040BB10` up to three times (`0x0040B787`–`0x0040B79E`) and retains the
last return value. A return value of 1 takes the early branch and sets
`this+0x8E6D` to 1 at `0x0040B79E`; the routine then sends a further feature
report via `HidD_SetFeature` at `0x0040B800`.

On the early-return branch, the retry count is below 3, so execution reaches
`0x0040B979`. If `this+0x8E6C` is zero, the mode value is read from
`0x005C5F0C`; mode 3 takes the `0x0040BA53` branch, sleeps 1,000 ms, and
calls `FUN_0040A580` at `0x0040BA60`. The `0x0419` click handler clears
`this+0x8E6C` at `0x00409DEA`. The reviewed direct edges through
`0x0040A0F0`, `0x00409760`, `0x00406C20`, and this `0x0040B770` branch do not
write that byte. **Inferred:** absent an intervening asynchronous writer,
the mode-3 early-return path therefore enters `FUN_0040A580`.

There is also an exhausted-retry branch: if all three `0x0040BB10` attempts
miss and the final return value is `0x0F`, mode 3 takes another direct
`FUN_0040A580` edge at `0x0040B847`–`0x0040B876`. Other exhausted results
take separate status/error paths. The return values' device-level meanings
are not established here.

## Conditional edge into the section-transfer worker

In `FUN_0040A580`, the branch `this+0x8E6C == 0` is at `0x0040A648`–
`0x0040A654`. For mode 3, the initial short-interface selector uses
`0603:1021` only when `this+0x8E6F == 1` (`0x0040A662`–`0x0040A684`); in
the other case it uses the VID/PID values held in globals `0x005C6F78` and
`0x005C6F74` (`0x0040A69F`–`0x0040A6B4`). When a short handle exists, the
function can issue the six-byte `05 75` buffer through `HidD_SetFeature` at
`0x0040A75A`. It then sleeps 3,000 ms at `0x0040A760` and searches the
separate fallback pair `0603:1020`: the long collection length argument is
`0x802` at `0x0040A76B`–`0x0040A77A`, followed by the short-interface search
at `0x0040A787`–`0x0040A796`.

**Direct:** when both fallback handles differ from `-1`, the routine creates
a thread with start address `FUN_00406BD0` at `0x0040A833`–`0x0040A841`.
That worker calls `FUN_0040C090`, which enters section dispatcher
`FUN_00402A40`; the transfer routines and their device-write/readback limits
are documented in the [firmware audit](rk-firmware-readback-audit.md).
`FUN_0040A580` retries this `0603:1020` search after failures; static code
does not establish that either collection is present on a physical device.

Accordingly, the static chain from the probe's response branch to the
section-transfer worker is:

```text
0603:1021 probe response (byte0=0x60, byte2=0)
  -> FUN_00406C20 thread
  -> FUN_0040B770 secondary status/transition worker
  -> [mode 3; this+0x8E6C == 0; qualifying 0x0040BB10 result]
  -> FUN_0040A580
  -> [0603:1020 long and short feature collections both found]
  -> FUN_00406BD0 section-transfer worker
  -> FUN_00402A40 dispatcher
```

The bracketed branch predicates are static conditions, not claims that the
physical keyboard satisfies them.

## Timer and message boundary

The response-success branch explicitly kills timer ID 2 and starts
`0x00406C20`; it does not call `SetTimer` or create `0x00406BD0` directly.
The follow-on `0x00406C20` → `0x0040B770` → `0x0040A580` path includes
ordinary `Sleep` calls and the conditional thread creation described above.
No timer-ID-3 creation or explicit `WM_TIMER` post is present in these
reviewed direct edges. This is consistent with the image-wide timer census,
which did not identify a window `SetTimer` call for IDs 2, 3, or 4.

The dialog's separate `WM_TIMER` ID-3 handler at `0x00409950` calls
`FUN_00409A50`; if that helper returns nonzero it kills timer 3 and creates
`0x00406BD0` at `0x00409A15`–`0x00409A34`. Its timer origin/delivery remains
unresolved in the [timer-origin audit](rk-updater-timer-origin-static-audit.md)
and [low-timer producer follow-up](rk-updater-low-timer-producer-followup.md).
That unknown timer is not needed to describe the distinct conditional
`0x00409760` response → `0x00406C20` → `0x0040B770` → `0x0040A580` route.

## Findings and limits

- **Proven statically:** response bytes `60 ?? 00` from the status probe take
  a branch that sets `0x005C5F08`, kills timer 2, and creates worker
  `0x00406C20`; the mode-3 caller returns when that helper reports the set
  flag.
- **Proven statically:** the `0x00406C20` routine calls `0x0040B770`; for
  mode 3, `this+0x8E6C == 0`, and a qualifying secondary status result,
  `0x0040B770` calls `0x0040A580`.
- **Proven statically:** `0x0040A580` can create `0x00406BD0` after both
  `0603:1020` feature collections match; that worker reaches the section
  dispatcher.
- **Inferred:** when these branch predicates hold, the `0603:1021` probe
  success path can reach section transfer through the secondary transition
  worker and the `0603:1020` fallback pair.
- **Unresolved:** actual response bytes, `0x0040BB10` results, concurrent
  writes to `this+0x8E6C`, runtime handle selection, presence/meaning of either
  device ID, whether any HID write is accepted, and timer-ID-3 origin.

## Static reproduction

With GNU `objdump` and the same packaged image, these ranges reproduce the
principal edges without executing the program:

```powershell
objdump -d -M intel --start-address=0x00409760 --stop-address=0x00409950 Update.exe
objdump -d -M intel --start-address=0x0040A0F0 --stop-address=0x0040A580 Update.exe
objdump -d -M intel --start-address=0x00406C20 --stop-address=0x00406D30 Update.exe
objdump -d -M intel --start-address=0x0040B770 --stop-address=0x0040BB10 Update.exe
objdump -d -M intel --start-address=0x0040A580 --stop-address=0x0040A860 Update.exe
```
