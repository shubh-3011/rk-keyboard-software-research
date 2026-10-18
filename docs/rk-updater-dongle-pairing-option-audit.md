# Updater “retain dongle pairing” checkbox audit

## Scope and safety

This audit follows the updater dialog's “Dongle保留对码信息” checkbox
(resource 102, language 1028, control ID `0x0422`) through its static state
handling in the installed `Dev/01AF/Update.exe`. The exact x86 PE snapshot has
SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`.

The updater was not launched. No HID interface, serial port, bootloader, or
keyboard was opened, and no report, command, or configuration was sent. The
evidence is static and specific to this binary.

## Evidence

**Proven — control and handler.** The dialog resource declares `0x0422` as a
button with checkbox style and the Chinese caption shown above. Its recovered
MFC message map routes the `WM_COMMAND` to `0x0040C2D0`; dialog initialization
binds control `0x0422` to the control member at `this+0x8E74`. The handler uses
the corresponding window handle at `this+0x8E94`.

**Proven — state read and normalization.** At `0x0040C2D0`, the handler pushes
`0, 0, 0xF0, HWND` and calls the `SendMessageW` IAT slot at `0x005608AC`.
`0xF0` is `BM_GETCHECK`. It tests the returned value and executes
`setne byte ptr [0x005C5F09]`, so any nonzero checkbox state is stored as 1
and an unchecked state as 0.

The global is in the zero-filled virtual tail of `.data`: RVA `0x1C5F09`,
section offset `0x12F09`, beyond the section's `0xCA00` bytes of raw data and
within its `0x15200`-byte virtual size. The static initial value is therefore
zero unless some other initialization or write changes it.

**Proven — no direct in-image consumer recovered.** A whole-file search of
this exact PE for the four-byte absolute address of `0x005C5F09` finds one
occurrence: the operand of the `setne` store in the checkbox handler. No second
direct absolute-address reference, read, or transfer-buffer construction for
this flag appears in the image. This is stronger than the earlier finding
that only identified the setter.

## Conclusion and limits

For this updater build, the visible checkbox is read and saved to a local
zero-initialized global, but the static image contains no second direct
reference that consumes that value. Its advertised effect on transferred
firmware or pairing data is therefore **not demonstrated**; this static
evidence suggests the option may be inert in this build. This does not prove
that every possible computed alias, external component, or runtime behavior
is absent. In particular, it does not establish what a compatible receiver
would do if an update were run.

The reproducible verifier is
[`audit_rk0422_dongle_pairing_flag.py`](../scripts/audit_rk0422_dongle_pairing_flag.py).
It pins the executable hash, verifies the handler bytes, checks the unique
absolute-address occurrence, and confirms the global's zero-filled section
location. The resource and message-map inventories remain in the
[dialog audit](rk-dialog-resource-audit.md); this follow-up narrows the flag's
state-use conclusion without extending updater runtime claims.
