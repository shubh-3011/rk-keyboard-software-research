# V4.6 G5 command-`0x88` read callsite completeness follow-up

## Scope and evidence boundary

This follow-up rechecks static references to `CDevG5KB` vtable slot `+0x70`
and its command-`0x88` helper in the hash-pinned V4.6 `DeviceDriver.exe`:
2,418,176 bytes, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
Addresses below are preferred-image-base VAs. The executable was disassembled
from disk only. No RK program, HID/serial interface, updater, or bootloader
was run or opened.

## Method behavior relevant to callers

G5 vtable entry `0x005D3D7C` points to wrapper `0x00411030`. The wrapper
returns zero when object flag `+0x238` is set (`0x00411030`–`0x0041103B`);
otherwise it forwards the caller's output-buffer pointer and requested length
to helper `0x00410890` (`0x0041103E`–`0x0041104D`). The helper reads the G5
object's saved handle at `+0x04` and report byte at `+0x2DC`, divides the
requested length into chunks no larger than `0x200`, and builds a `0x208`-byte
feature request with command `0x88` at report byte 1. It calls
`HidD_SetFeature`, then conditionally calls `HidD_GetFeature` on the same
handle. Only if the read succeeds and response byte 1 is `0x88` does it copy
`chunkLength` bytes from response offset 8 into `output + offset` with
`memcpy` wrapper `0x0057BA90` (`0x00410A06`–`0x00410A20`). The requested
length therefore controls how many bytes this method would copy if invoked
and the conditional exchanges succeeded. This is code-level behavior, not an
observed report or device response.

The wrapper has no file sink. The method's downstream buffer consumer cannot
be identified without an attributable caller.

## Expanded reference scan

The bounded scan used the complete decoded `.text`, an exact raw-byte search
for the wrapper VA, and the known vtable entry:

- There is no decoded direct relative call to `0x00411030`. The only decoded
direct call to helper `0x00410890` is the wrapper call at `0x00411048`.
- The only raw occurrence of pointer value `0x00411030` is at file offset
`0x001D2D7C`, corresponding to vtable entry `0x005D3D7C`. No other literal
wrapper address was found for a callback or dispatch-table registration.
- Decoded transfers explicitly using a virtual slot operand `+0x70` comprise
77 `call [reg+0x70]` instructions and three tail `jmp [reg+0x70]`
instructions. The earlier [caller-attribution audit](rk-v4.6-cdevg5-realdata-caller-audit.md)
screened the 77 call sites and did not attribute one to the G5 method. The
three tail relays are:

| Tail-call site | Forwarded receiver and evidence | Caller/data status |
| --- | --- | --- |
| `0x0047FFA0` | Loads a member pointer from `[outer+0x4C]` and jumps to that object's slot `+0x70`; the wrapper preserves its two stack arguments. | No G5 receiver or callsite-specific output buffer/length is established. The signature shape alone cannot exclude it. |
| `0x004EDD9E` | Loads the member pointer at `[outer+0x138]` and jumps to its slot `+0x70`, preserving caller stack arguments. | Eight direct callers were found in the `0x004A...` region (`0x004A5521`, `0x004A587F`, `0x004A5CD6`, `0x004A64D5`, `0x004A700B`, `0x004A90B7`, `0x004A9316`, `0x004A9952`). Their receiver is obtained through generic object/member helpers; these calls do not establish a G5 object or the method's buffer/length pair. |
| `0x0051B04E` | After state checks, uses an embedded receiver at `[this+0x160]` and tail-jumps through its slot `+0x70`. | No direct G5 object flow, callsite-specific length, or downstream consumer is established by the scan. |

A short-window check for a method pointer loaded from `[reg+0x70]` and then
transferred through that same register found no additional candidate within
the next seven decoded instructions. This check does not cover longer-lived
cached pointers or dynamically computed targets. The three tail relays are
left unresolved rather than excluded: no static evidence identifies their
receivers as `CDevG5KB`, but the forwarding shape by itself does not rule out
an indirect alias.

## Conclusion and limits

The expanded scan found no direct caller or callback registration that
identifies a request length for `CDevG5KB::+0x70`, and no attributable caller
whose output buffer can be followed to a file or other persistent sink. It
adds three generic `+0x70` tail-forwarding candidates to the prior 77-call
screen. Those candidates do not prove a G5 invocation and are not completely
excluded by static type evidence. A computed target, longer-lived cached
function pointer, runtime-generated dispatch, or external call cannot be
ruled out by this scan. Consequently, the requested range, data meaning,
firmware interpretation, full-image behavior, and downstream persistence
remain unresolved.

The existing [readback audit](rk-firmware-readback-audit.md) and
[GetFeature argument audit](rk-v4.6-hid-getfeature-argument-audit.md) remain
the evidence for the conditional feature-read implementation and paired
handle use; neither documents a hardware response or a firmware export.
