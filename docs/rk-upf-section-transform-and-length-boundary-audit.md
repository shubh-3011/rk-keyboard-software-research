# RK `.upf` section transform and length-boundary audit

## Scope and exact inputs

This report adds a static trace of the per-section transform called by the
mode-dispatched `.upf` parser. It supplements the existing
[firmware readback audit](rk-firmware-readback-audit.md), which documents the
container header, payload offset, section lengths, and transfer direction.
It does not claim that the packaged sample is valid or reaches a device.

The analyzed x86 image is the 4.6-labeled package's
`app/Dev/01AF/Update.exe`, 2,109,952 bytes, SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`.
Addresses below are virtual addresses in this PE image (base `0x00400000`).
The package sample is
`app/Dev/01AF/KB_762_1_v258A_p01AF_F90_8818_V90.0f.1.00.upf`, 193,652
bytes, SHA-256
`e21c11e023247afc7fdbbe27548570240efa5b646147741d5354eecb3041b628`.

Only file bytes and disassembly were inspected. No RK executable or installer
was run; no HID, serial, bootloader, or keyboard connection was opened or
used, and no device data was written.

- **Direct** means the instruction or byte sequence occurs in these exact
  inputs.
- **Inferred** means a conclusion follows from the static data flow but was
  not confirmed at runtime.
- **Unresolved** means the available static evidence does not settle it.

## Mode-3 section buffers and transform calls

The parser `FUN_0040A940` dispatches mode 3 at `0x0040AF0A` and prepares its
three section buffers in sequence:

| Section | Length global | Buffer global | Allocate / zero / read callsites |
| --- | --- | --- | --- |
| A | `0x005C6F7C` | `0x005C6F84` | `0x0040AF0F` / `0x0040AF21` / `0x0040AF31` |
| B | `0x005C5F04` | `0x005C5EFC` | `0x0040AF3C` / `0x0040AF48` / `0x0040AF58` |
| C | `0x005C5F00` | `0x005C5EF8` | `0x0040AF66` / `0x0040AF77` / `0x0040AF82` |

At `0x0040AF8D`–`0x0040AF96`, the parser asks its stream-read helper for
four bytes into local storage at `[EBP-0x44]`. The mode-3 branch then calls
`FUN_004044B0` once per section, passing that local address in `ECX`, the
section-buffer pointer in `EDX`, and the declared length on the stack:

| Section | Call to `FUN_004044B0` | Buffer | Length |
| --- | ---: | --- | --- |
| A | `0x0040B05A` | `0x005C6F84` | `0x005C6F7C` |
| B | `0x0040B06E` | `0x005C5EFC` | `0x005C5F04` |
| C | `0x0040B082` | `0x005C5EF8` | `0x005C5F00` |

**Direct:** `FUN_004044B0` treats `ECX` as a four-byte key pointer and
`EDX` as the input buffer. It converts groups of four input bytes into
big-endian 32-bit words in a temporary allocation, transforms pairs of words
in `FUN_004045A0`, then serializes words back into the original input buffer.
The mode-3 calls therefore request an in-place transform of each section,
using the same four bytes read immediately before dispatch.

`FUN_004045A0` loads key bytes at offsets `0` through `3` from the supplied
key pointer, initializes a 32-iteration counter at `0x004045CD`, and applies
two-word arithmetic/XOR/shift rounds at `0x004045E0`–`0x00404619`. The
visible constants are `0xC6ED3720` (`0x004045D5`) and per-round increment
`0x61C89647` (`0x00404610`). It writes the resulting pair back to the
temporary word pair at `0x0040461B`–`0x00404624`.

This describes the observed operations without assigning a cryptographic
algorithm name or claiming what the transform is intended to protect. The
four key bytes' meaning, origin in a valid package, and reuse policy are
**unresolved**. In particular, the sample's declared A length is larger than
the bytes available after the parser's `0x80` payload seek, so a valid key
read or successful parse of this file has not been established.

## Length arithmetic and sample boundary conditions

`FUN_004044B0` derives a temporary word count with signed 32-bit arithmetic:
it sign-extends the length (`CDQ` at `0x004044BC`), adds `length & 3`, then
arithmetic-shifts right by two (`0x004044C7`–`0x004044CF`). It allocates four
bytes per resulting word at `0x004044D2`–`0x004044E2`; multiplication
overflow changes the requested allocation size to `0xFFFFFFFF`. The
transform-block count is separately computed from `length + (length & 7)`
with an arithmetic right shift by three at `0x0040452B`–`0x00404538`. The
conversion and copy-back loops process complete four-byte groups; the block
loop processes eight-byte groups.

For the packaged sample, the previously decoded values are A=`0xF000716D`,
B=`0x0000A187` (41,351), and C=`0`. Their behavior at the transform helper is
not the same:

- **Direct:** A's high bit is set. Under the helper's signed operations, its
  computed word and block counts are negative, so the conversion, block, and
  copy-back loops are skipped. The temporary-allocation size calculation
  overflows and passes `0xFFFFFFFF` to allocator `FUN_0040E083`. The
  allocator's behavior for that request is **unresolved**.
- **Direct:** B is positive and not divisible by four. The helper computes
  10,338 words and 5,169 two-word blocks. Its four-byte conversion and
  copy-back loops therefore cover 41,352 bytes while the parser's declared B
  buffer length is 41,351. The final group indexes byte offset 41,351, one
  byte beyond the declared span. This is a statically visible boundary
  mismatch; actual allocation padding, adjacent-memory contents, and runtime
  consequences are **unresolved**.
- **Direct:** C's zero length makes both loop counts zero; the helper still
  reaches its allocator/free sequence. The zero-size allocator behavior is
  **unresolved**.

The parser passes these declared lengths to the section-buffer allocator and
read helper before calling the transform. The A length also exceeds the
sample's total remaining payload (193,524 bytes). **Unresolved:** whether the
section allocation/read helpers succeed, how short reads update stream
state, whether a failed earlier read is checked elsewhere, what bytes occupy
the four-byte local key after an unsuccessful read, and whether this sample
ever reaches the transform calls. These observations are static boundary
conditions, not evidence of an observed crash, device write, or accepted
firmware image.

## Evidence and reproduction

Principal direct evidence is in the hash-pinned updater at:

```text
0x0040AF0A–0x0040AF96  mode-3 section allocation, clearing, reads, and key read
0x0040B046–0x0040B08B  mode-3 calls to FUN_004044B0 for A, B, and C
0x004044B0–0x00404599  length arithmetic, word conversion, block loop, copy-back
0x004045A0–0x00404629  four-byte-key, 32-round two-word transform
```

These commands reproduce the relevant instruction ranges without executing
the updater:

```powershell
objdump -d -M intel --start-address=0x0040AF0A --stop-address=0x0040B08B Update.exe
objdump -d -M intel --start-address=0x004044B0 --stop-address=0x004045A0 Update.exe
objdump -d -M intel --start-address=0x004045A0 --stop-address=0x0040462A Update.exe
```
