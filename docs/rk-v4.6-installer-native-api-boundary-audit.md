# RK 4.6 installer native API and syscall boundary audit

## Scope and artifact identity

This is a static inspection of the outer Windows installer, not the extracted
application members. The input is
`.research/RK_Keyboard_Software_Setup_V4.6_20261015.exe`, 96,720,579 bytes,
SHA-256
`47a1fc21c3af548b93fa40d499584abecb3341e62b15948ae537b78ca987aad8`.
The installer was not launched or installed. No RK process, device interface,
updater, or bootloader was opened or run.

The reproducible entry point is
[`audit_rk46_installer_native_api.py`](../scripts/audit_rk46_installer_native_api.py).
It verifies this exact SHA-256, parses the PE import table with `pefile`, and
reuses the repository's GNU `objdump` call/thunk scanner. The resulting
[per-import transfer ledger](rk-v4.6-installer-native-api-call-sites.csv)
records decoded instruction sites and retains the scanner's linear-sweep and
non-CFG limitations.

## Static import and callsite findings

The installer is a 32-bit x86 PE with preferred entry VA `0x004163c4`. Its
executable PE sections are `.text` (82,944 raw bytes) and `.itext` (3,072 raw
bytes); the appended Inno setup-data overlay is not part of those executable
sections. GNU `objdump` produced 30,444 instruction records across the PE's
executable sections.

The import table contains 135 ordinary IAT rows, representing 114 unique API
names across their DLL descriptors, and no delay-import rows. The decoded
transfer scan finds 135 `jmp [IAT]` import stubs and 281 relative calls to
those stubs. Every imported IAT row has at least one recognized transfer in
this scan. This is address-level transfer coverage for this PE's decoded
sections; it does not show which call paths execute during setup or recover
all arguments, callbacks, dynamically resolved API targets, or Inno script
actions.

There is no `ntdll.dll` import and no imported symbol named `Nt*` or `Zw*`.
The executable-section scan found one raw `0F 05` byte pair at VA
`0x0041356f`; disassembly places it inside the 32-bit relative displacement of
the `JMP` at `0x0041356e` (`e9 0f 05 00 00`). No raw `0F 34` or `CD 2E` pair
was found, and no direct `syscall`, `sysenter`, or `int 2e` instruction was
recognized in the decoded instructions. These findings are bounded to this
hash-pinned PE's executable sections and the documented decoder; they do not
cover external Windows components, unpacked runtime code, or the setup-data
overlay as potentially transformed code.

## What remains unknown

This audit does not recover the compiled PascalScript callbacks, the exact
setup operation sequence, dynamic `GetProcAddress` targets, or what the
installer generates after installation. The generated 4.6 uninstaller is
absent from the extracted package; its behavior remains unknown. API import
presence and decoded transfers do not establish that a particular setup
action ran. See the [package membership and version-boundary audit](rk-package-membership-and-version-boundary-audit-2026-10-19.md)
and the [Inno script-recovery boundary](rk-v4.6-inno-script-recovery-audit.md).
