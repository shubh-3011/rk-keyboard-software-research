# 4.06 uninstaller scrollbar fallback indexed-candidate correction

## Scope and evidence

This note rechecks the possible indexed consumer at VA `0x0044B2C0` in the
package-matched `unins000.exe` snapshot. Its SHA-256 is
`b4ca28b192d5a50307d2b28f3323b58b39cb51edd6682e75706cac2dd69a4a14`.
The file was inspected statically with GNU `objdump` and raw bytes only. The
uninstaller was not launched; no keyboard or HID interface was accessed.

## Candidate rejected as a linear-disassembly artifact

A broad linear disassembly at `0x0044B2C0` prints
`jmp DWORD PTR [ebx+0x00502094]`. Decoding from the coherent preceding
instruction boundary shows that address is not the start of that jump:

```text
0044B2B7  push 0x0044B318
0044B2BC  call 0x00409A8C       ; bytes: E8 CB E7 FB FF
0044B2C1  mov [0x00502094],eax ; bytes: A3 94 20 50 00
0044B2C6  push 0x0044B334
0044B2CB  call 0x00409A8C
0044B2D0  mov [0x00502098],eax
```

The alleged `jmp` begins at `0x0044B2C0`, the final `0xFF` byte of the
relative displacement for the call at `0x0044B2BC`. Its following `A3` byte
begins the absolute `mov` at `0x0044B2C1`. The apparent indexed memory
operand is thus formed by decoding across the call boundary, not by the
instruction sequence shown from `0x0044B2B7`.

This removes the only previously noted indexed-reference candidate for the
USER32 fallback slots. No EBX provenance should be attributed to that
candidate. A relative-branch byte-pattern scan of the executable sections
found no direct relative branch target at `0x0044B2C0`; because `.text` also
contains data, this is supporting evidence rather than proof against every
computed or external entry.

## Result for the fallback imports

The eight USER32 scrollbar fallback pointers are still written by resolver
`0x0044B5E0` into `0x0050209C` through `0x005020B8` when the corresponding
`FlatSB_*` lookup returns null. The existing full-image reference scan finds
only those initialization stores for these globals. The candidate correction
does not uncover a reader or call through any slot. Therefore the eight
fallback imports remain **unresolved**, not unused: no in-image invocation
site was recovered, and computed aliases, callbacks, or outside-image
consumers remain open.

See [`rk-remaining-native-api-path-audit.md`](rk-remaining-native-api-path-audit.md)
and [`rk-remaining-native-api-gap-deep-scan.md`](rk-remaining-native-api-gap-deep-scan.md)
for the import mapping, resolver stores, and separate direct `comctl32!FlatSB_*`
call paths.
