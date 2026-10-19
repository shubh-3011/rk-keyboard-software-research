# RK 4.6 G5 command-5 payload source trace

## Scope and evidence identity

This offline static follow-up traces the operation-1/command-5 call in
`CDevG5KB::ApplySetting` at `0x00412DAC` to its data buffer and
`HidD_SetFeature` helper. The input is the extracted 4.6-labeled
`DeviceDriver.exe`, SHA-256
`8D8538DE3ADA5FCF80E00C13B364B17ACEFA708480E102EC1E6A0B1309639AE9`.
No RK executable was launched and no keyboard interface, updater, report, or
command was used.

## The command-5 source buffer

In the key/macro `nFlag & 0x01` branch, `ApplySetting` calls the builder at
`0x00411BA0` (`0x004129C6`) with caller-owned output buffers. One output
pointer is formed at `0x0041299E` by `lea edx,[esp+0x18A8]` after two earlier
argument pushes. Relative to the function's stable local-frame stack pointer,
that points to `S+0x18A0`. The builder returns with `ret 0x10` on its shared
epilogue, so it removes its four stack arguments and leaves `ApplySetting`'s
local-frame base unchanged.

Later in the same branch, `ApplySetting` pushes seven arguments for helper
`0x0040FFD0`. At `0x00412DA5`, `lea ecx,[esp+0x18BC]` accounts for those
28 bytes of pushes and again resolves to `S+0x18A0`. Thus the helper's source
pointer is exactly the same caller-owned buffer supplied to `0x00411BA0`; it
is not a separate buffer whose relation to the key/macro builder is unknown.
The relevant code is reproducible from the hash-pinned PE with:

```powershell
objdump -d --start-address=0x004127B0 --stop-address=0x00412E20 `
  "C:\path\to\extracted\app\DeviceDriver.exe"
objdump -d --start-address=0x0040FFD0 --stop-address=0x00410284 `
  "C:\path\to\extracted\app\DeviceDriver.exe"
```

The caller supplies operation `1`, selector/command `5`, a length of
`0xC8` (200 bytes), a byte read from `[object+0x2DC]`, and the device handle
loaded from `[object+0x04]`. In `0x0040FFD0`, ECX is saved as the data source;
the operation-1 branch copies up to `0x200` bytes from that pointer into its
feature-report frame. Since `0xC8 <= 0x200`, this call copies the first
200 bytes from the builder's output buffer. The frame is zero-initialized to
`0x208` bytes and has this statically recovered layout for this call:

| Frame offset | Construction | Value in this command-5 call |
| ---: | --- | --- |
| `0x00` | Caller byte from `[object+0x2DC]` | Runtime field value unresolved |
| `0x01` | Command argument | `0x05` |
| `0x02` | Caller trailing argument | `0x00` |
| `0x03` | Literal zero | `0x00` |
| `0x04` | `ceil(length / 0x200)` | `0x01` |
| `0x05` | Current byte offset plus one | `0x01` for the first chunk |
| `0x06–0x07` | Current chunk length, little-endian | `C8 00` |
| `0x08–0xCF` | Bytes copied from the source pointer | 200-byte prefix of the builder output |
| `0xD0–0x207` | Zero-filled remainder of the frame | `0x138` zero bytes |

The helper passes the complete `0x208`-byte frame to the imported
`HidD_SetFeature` thunk at `0x0041014F`; that callsite is recorded in the
hash-pinned [native API ledger](rk-v4.6-native-api-call-sites-reconciled.csv).
The offsets above describe construction in this helper. They do not assign
firmware meanings to the header bytes.

This resolves the specific buffer-provenance question: the command-5 write
uses a 200-byte prefix of one output buffer passed to `0x00411BA0`. It does
not, by itself, identify whether those bytes are the pair table, serialized
event data, padding, or a mixture; nor does it prove that a visible macro or
key UI action reaches this branch. It establishes code-level dataflow and a
write call, not execution, acceptance, or firmware semantics.

## Proven / inferred / unresolved

**Proven statically:** for the traced branch, the `0x00411BA0` output pointer
and the `0x0040FFD0` source pointer resolve to the same local-frame address;
the writer receives length `0xC8`, operation `1`, selector `5`, the object's
`+0x2DC` byte, and the object's handle; the helper's operation-1 path copies
source bytes and calls `HidD_SetFeature`.

**Inferred:** because the source buffer is populated by the key/macro builder,
command `5` transports some portion of that builder output. Its user-facing
identity cannot be assigned solely from the nearby `SendWeb` diagnostics.

**Unresolved:** which of the builder's output structures occupies this
buffer, the exact 200-byte grammar and field meanings, the visible control and
profile gate that reach the branch, the active runtime device family, and
whether firmware accepts the request.

## Relation to the broader G5 audit

This narrows the macro-builder-to-writer gap in the
[G5 vtable/settings audit](rk-v4.6-cdevg5-settings-and-vtable-audit.md).
The rest of the G5 protocol map remains incomplete; this finding does not
validate support for physical models or revisions.
