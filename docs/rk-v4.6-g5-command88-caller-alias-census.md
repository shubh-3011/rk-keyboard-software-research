# V4.6 G5 command-`0x88` caller and alias census

## Scope and evidence boundary

This report extends the existing G5 command-`0x88` caller review with a
hash-pinned census of direct wrapper references, exact `+0x70` virtual-slot
transfers, register-mediated slot aliases, and the three tail relays. The
V4.6 input is the extracted `DeviceDriver.exe` at
`C:\Users\shubh\Downloads\sshorcale\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe`,
size 2,418,176 bytes, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
Addresses are preferred-base x86 VAs. The file was read statically; it was
not executed. No HID interface, updater, or bootloader was accessed.

The corresponding installed V4.06 image is
`C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe`, size
2,326,528 bytes, SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
V4.06 places the G5 `GetRealData` wrapper at `0x00410700`, slot `+0x68` of
the vtable at `0x005CBA2C`; its helper is `0x0040FF60`. V4.6 moves the wrapper
to `0x00411030`, slot `+0x70` of vtable address point `0x005D3D0C`; its helper
is `0x00410890`. The different offsets and function addresses must not be
combined across images.

## Method and reproducibility

The V4.6 result is reproduced with the new standalone static census:

```powershell
python scripts/audit_rk46_g5_cmd88_alias_census.py ..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe
```

The script rejects a size/hash or architecture mismatch. It linearly decodes
the executable PE sections, records exact direct calls/jumps to the wrapper
and helper, enumerates indirect `call`/`jmp` operands with displacement
`+0x70`, searches all file bytes for literal addresses, and taints a register
loaded from `[register+0x70]` through plain register copies until a
register-indirect transfer or a clobber. Conditional-branch fall-through is
kept in that last pass; an unconditional jump or return ends the linear
sequence. The scan does not infer that every decoded byte is code or that a
candidate is runtime-reachable.

Key output from the pinned run:

| Check | Result |
| --- | --- |
| Input size and SHA-256 | `2,418,176`; `8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9` |
| Executable section | `.text`, VA `0x00401000`, raw size `1,723,392` bytes |
| Decoded records | `570,714`, including Capstone skip-data records |
| Direct relative calls to wrapper `0x00411030` | `0` |
| Direct relative calls to helper `0x00410890` | `1`: site `0x00411048`, bytes `E8 43 F8 FF FF`, from the wrapper |
| Literal pointer `0x00411030` | One occurrence: file offset `0x001D2D7C`, `.rdata` VA `0x005D3D7C` (the G5 slot) |
| Literal G5 vtable address point `0x005D3D0C` | Two code references: `0x0040F4C5` and `0x0040F5EB` |
| Exact virtual-slot transfers | `77` calls and `3` tail jumps through `[reg+0x70]` |
| Non-stack loads from `[reg+0x70]` | `82`; none reached a register-indirect call/jump in the bounded taint pass |

The exact 77 call sites and their earlier receiver/argument screening are in
the [caller-attribution audit](rk-v4.6-cdevg5-realdata-caller-audit.md).
The three tail transfers are retained as candidates below; the census does
not count them as proven G5 invocations.

## Tail-relay review

### Relay at `0x0047FFA0`

The containing helper starts at `0x0047FF7A`. Its fallback path calls the
imported `USER32!GetDlgItem` through IAT `0x005A6624`, using `[outer+0x20]`
as the window handle, `[ebp+8]` as the child ID, and `[ebp+0xC]` as an
output pointer for the resulting handle. If `[outer+0x4C]` is present, it
forwards those same two stack arguments to the nested object's slot `+0x70`
at `0x0047FFA0`.

Six direct call sites were found: `0x004BB75A`, `0x004BB7A4`,
`0x004BB7F5`, `0x004BB85A`, `0x004BB8C6`, and `0x004BBAE8`. They use the
relay as a child-ID-to-window-handle lookup, with the ID in the first
argument and handle-output pointer in the second. That is incompatible with
the G5 read wrapper's output-buffer/byte-length pair and its `ret 8` cleanup.
These six known call paths therefore do not establish a G5 read. The nested
receiver's concrete type and other computed or external entries remain
unresolved.

### Relay at `0x004EDD9E`

The helper begins at `0x004EDD8D`. It loads a nested pointer from
`[this+0x138]`, then tail-jumps through that object's `+0x70` slot; if the
pointer is null, it returns zero. Its eight direct call sites are
`0x004A5521`, `0x004A587F`, `0x004A5CD6`, `0x004A64D5`, `0x004A700B`,
`0x004A90B7`, `0x004A9316`, and `0x004A9952`. At each call, the caller sets
`ECX` to the object and supplies no explicit stack arguments. The returned
`EAX` is treated as an object pointer or tested for null. This nullary getter
shape is incompatible with the G5 wrapper's two required stack arguments
and `ret 8`; the eight observed direct callers do not prove a G5 invocation.
No literal function-pointer occurrence for `0x004EDD8D` was found. Other
computed dispatch into this relay is outside the direct-call census.

### Relay at `0x0051B04E`

The enclosing sequence begins at `0x0051B02B`. After state checks it uses an
embedded receiver at `[this+0x160]` and jumps through its `+0x70` slot. The
linear executable-section census found no direct relative call or jump to
`0x0051B02B`, and the full-file literal search found no pointer to that
address. This leaves no statically identified entry path to this sequence
in the scanned image. Computed control flow, runtime-generated dispatch, or
an external entry cannot be excluded.

## Cross-version V4.06 evidence

The existing V4.06 [G5 vtable and `GetRealData` audit](rk-406-cdevg5-vtable-audit.md)
records no direct call to wrapper `0x00410700`; helper `0x0040FF60` has one
direct caller, wrapper site `0x00410718`. Its decoded scan records 60
`call [reg+0x68]` sites and two `jmp [reg+0x68]` sites, plus a separate
90-row load-then-register-transfer pattern census. The
[candidate-census script](../scripts/audit_rk406_vcall_candidate_census.py)
reproduces the register-mediated subset; the audit documents the candidate
reviews, including text-rendering and rectangle/layout false positives.
Those results do not identify a G5 caller or a returned-buffer consumer.

## Conclusion and limits

The pinned code proves that each version contains a conditional command-
`0x88` feature-read helper that copies response chunks into a caller-provided
memory buffer. In V4.6, the helper call is reached statically only from its
wrapper; the wrapper has no direct relative callers, and its sole literal
pointer is its vtable entry. The 77 ordinary `+0x70` virtual calls were not
attributed to G5. The three tail relays are generic forwarding candidates;
their known call paths are either incompatible with the G5 read signature or
have no identified entry, while a receiver reached by arbitrary computed
dispatch remains outside the census.

No caller-owned buffer was attributed to the G5 read method, so this work
does not trace response bytes to a consumer or file sink. The helper itself
has no file-write path in the inspected body. The method issues
`HidD_SetFeature` before the conditional `HidD_GetFeature`, so this static
path is not a passive read-only transaction. The response meaning, requested
range, firmware interpretation, complete firmware-copy path, and actual
device behavior remain unproven. This negative result is limited to the
hash-pinned binaries and the described scans; it is not proof that no other
runtime or external caller exists.
