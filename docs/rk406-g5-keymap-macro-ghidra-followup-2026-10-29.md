# Installed 4.06: G5 keymap and macro decompiler cross-check

This is a focused static cross-check, not a complete app audit or a device
compatibility claim. Target: installed `DeviceDriver.exe`, SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
REA used Ghidra 12.1.4; the four complete evidence records are retained locally
in `.research/rk406-g5-keymap-macro-rea-20261029.json`. No device reports or
vendor UI actions were issued for this analysis.

## Cross-checks

- `0x0040F700`, evidence `ev_bbd3fefc6d673d0268f2be1ab3f797f0ad34cc3b7837e7d285931c1e9fb2809c`:
  decompilation shows 520-byte Feature buffers, chunks up to 512 payload bytes,
  and a SetFeature request even on its read branch before GetFeature. The
  decompiled read branch checks the returned command byte before copying data;
  this is not evidence that all other response fields are validated or that a
  particular undocumented query exists.
- `0x0040F9C0`, evidence `ev_18ec2a3362e3f832aad073acfed5c394275cc8727c15ce68d9e1f5992e315249`:
  the direct G5 branch calls that transport with operation 1 and command 3;
  a separate 3632 branch calls a different transport. This is a matrix write,
  not a current-keymap read. Ghidra infers a void return for the transport
  while its caller tests a return value; this calling-convention discrepancy
  requires assembly-level review before relying on success/failure semantics.
- `0x00411260`, evidence `ev_8f4376cbaa28f84bfbffeaf56b09f568b0175acd136532279e69874d8cce70f9`:
  the decompiled path iterates four layers of 132 source records, maps records
  to slots, and separately processes macro-tagged entries and buffer IDs. The
  decompiler warns that type propagation did not settle; use the independently
  checked instruction witnesses in the [keymap analysis](rk406-g5-keymap-next-step-2026-10-27.md)
  for exact offsets and bounds. A remap can interact with macro references.
- `0x00410F00`, evidence `ev_3fef383d05ead5ecf105ff87c9424217678a0e4146314dea17ca7387b79ca9d6`:
  decompilation shows a bounded UTF-16 name prefix followed by four-byte event
  entries, with special event cases and a 20-bit delay cap. Exact event meaning,
  output bounds for all inputs, calling convention, and device acceptance are
  not established by pseudocode alone.

## Engineering boundary

The existing analysis has not established a current-keymap reader or a safe
device snapshot and restore path. Do not guess command `83`, treat a local
profile as hardware state, or enable remap/macro writes on these observations.
First recover the current-state and restoration semantics for the exact
family/transport, then validate a reversible change and unrelated state on real
hardware. Connection discovery and other feature families must be investigated
independently; this G5-only cross-check does not generalize to all RK products.
