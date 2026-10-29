# Installed 4.06 G5 macro serializer: termination boundary

This static follow-up concerns only the installed `DeviceDriver.exe` SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
The REA/Ghidra decompilation of `0x00410F00` retained in
`.research/rk406-g5-keymap-macro-rea-20261029.json` is evidence
`ev_3fef383d05ead5ecf105ff87c9424217678a0e4146314dea17ca7387b79ca9d6`.
The prior [macro format audit](rk-macro-format-and-path-audit.md) establishes
the `0x342`-byte record format. This follow-up checks the local executable's
selected instruction bytes independently with
`scripts/audit_rk406_g5_macro_termination.py` (SHA-256 pinned; no execution).

## Observed local control flow

- The serializer reads a 16-bit first event code at record `+0x6A` and uses
  successive eight-byte event rows. The loop at `0x00411009` reads the next
  16-bit code and branches back if it is nonzero. The decompiled function
  returns a computed output byte count in EAX, corroborated at `0x00411037`.
- A `0x342`-byte record has 91 complete eight-byte positions starting at
  `+0x6A`; the code word after the 91st is at `+0x342`, outside that record.
- If this serializer is called with a buffer containing exactly one such
  record and all 91 event-code words are nonzero, its next-code read would be
  beyond that record. The inspected loop does not itself compare against the
  record end. This is a **conditional static boundary candidate**, not proof
  of a crash, exploitation, or a reachable malformed-input path: allocation
  extent, import validation, callers, and actual runtime data require separate
  investigation. No malformed file was opened or executed.

For a separately authored parser, the safe design is to require a terminator
within the supplied record and reject missing terminators; do not silently
read adjacent bytes or infer a device macro from a host file. This proposal is
not a statement that every vendor import accepts unterminated records, and no
new hardware command or macro writer is enabled by this finding.
