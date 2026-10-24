# S98 updater feature-read consumers: bounded static audit — 2026-10-24

## Scope and artifact identity

This follow-up examines two `HidD_GetFeature` consumers in the selector's
English-UK S98 Tri-mode RGB updater,
`S98-Tri-RGB-01BF-L10-20260527170338_1467.exe`. The file is 2,140,176 bytes
with SHA-256
`475e8d7b97adfbd861c3b7b16721ad598df04095b81228e381319b6be23129e6`; its
`.text` section SHA-256 is
`3643f4d710a296b62598d3d8b71c7dd9dcab049ebbb540588b11757ccd5f03ed`.
Seven of the eight selector packages share this executable-section hash.
Thai PID `0x0223` is a distinct build with a different `.text` hash, so its
addresses are covered in a separate counterpart section below rather than
being treated as byte-identical.

The package was inspected as a file only. It was not launched and no HID
interface or keyboard was opened. The package itself is not redistributed in
this repository. The [evidence ledger](rk-s98-feature-read-consumer-evidence-2026-10-24.csv)
and [verifier](../scripts/audit_s98_feature_read_consumer.py) pin exact bytes,
imports, and hashes.

## Update verification consumer at `0x004029B0`

The helper first builds a feature request beginning with bytes `05 52` at
`0x004029F7`, then calls the `HidD_SetFeature` import at `0x00402A03` through
IAT slot `0x0055A1E0`. After an accepted return, it allocates a `0x802`-byte
buffer, writes response prefix `06 72`, and calls `HidD_GetFeature` at
`0x00402AFD` through IAT slot `0x0055A1C8` with that buffer and length.

The subsequent loop reads the host image pointer from `0x005BE3F8` and payload
length from `0x005BE3FC`. It compares up to `0x800` bytes at a time against
bytes beginning at response-buffer offset `+2`, advances the host-image
offset by `0x800`, and returns a comparison result. Its direct caller at
`0x0040265F` retries the helper while the attempt count remains below ten.
This bounded path supports an update-image verification/readback
interpretation: the response is consumed as an in-memory comparison with the
host package image. It does not establish a standalone firmware export or a
file sink in the traced helper/caller slice.

## Six-byte feature status query

The separate path at `0x00409183` constructs a six-byte request beginning
`05 52 F0 FC 04 00` (`0x00409205` and `0x0040920B`), sends it with
`HidD_SetFeature` at `0x00409218`, and then changes the buffer prefix to
`05 72` before the `HidD_GetFeature` call at `0x0040924D`. On a successful
API result, it checks response byte `+2` against `0x61` and reads byte `+5`
into updater state selection logic. The enumerated values map to state fields;
their protocol names and meanings are unresolved.

## Thai PID `0x0223` counterpart build

The Thai package
`S98-Tri-RGB-0223-L7-20260527164526_9235.exe` is 2,140,176 bytes with
SHA-256 `399020b7b66fda67cc6c69ae81336d67024204cbc9e15ffabde26a2cccd072ca`.
Its `.text` section hash is
`bfc4506d668ee1ff8809a0455abd5f589545e45ff1d0b358a5fe3d4871e85ff2`,
different from 01BF. Static instruction comparison identifies counterparts
for both read consumers:

| Consumer | 01BF entry / `HidD_GetFeature` | Thai entry / `HidD_GetFeature` | Correspondence |
| --- | --- | --- | --- |
| Update verification | `0x004029B0` / `0x00402AFD` | `0x00402810` / `0x0040295D` | Request prefix `05 52`, response prefix `06 72`, chunked comparison to the host image; read call at helper offset `+0x14D`. |
| Six-byte status query | `0x00409183` / `0x0040924D` | `0x00408FD3` / `0x0040909D` | Request `05 52 F0 FC 04 00`, response prefix `05 72`, checks byte `+2 == 0x61`, consumes byte `+5`; read call at entry offset `+0xCA`. |

The verifier accepts the Thai binary as an optional `--thai-binary` input,
checks its file and `.text` hashes plus HID import slots, and records 14 exact
instruction facts for the relocated consumers in the same evidence ledger.
This establishes static correspondence for these two routines only; it does
not prove the rest of the Thai build equivalent to 01BF.

Reproduce both checks and regenerate the combined ledger with:

```powershell
python scripts/audit_s98_feature_read_consumer.py `
  --binary ..\.research\rk-selector-software-2026-10-19\S98-firmware-packages\S98-Tri-RGB-01BF-L10-20260527170338_1467.exe `
  --thai-binary ..\.research\rk-selector-software-2026-10-19\S98-firmware-packages\S98-Tri-RGB-0223-L7-20260527164526_9235.exe `
  --out docs/rk-s98-feature-read-consumer-evidence-2026-10-24.csv
```

## Limits

- These are static code paths in the 01BF and Thai package builds. API success,
  device acceptance, response contents, and runtime reachability were not
  observed.
- The update-verification path compares response data with the host `.upf`
  image; it is not evidence that the same operation reads arbitrary keyboard
  firmware or saves a dump.
- This audit does not prove that an export path is impossible elsewhere. Other
  updater functions, transitive callers, remaining Thai functions, and other
  package families remain separate work.
- Request and response meanings are not inferred from report prefixes alone.

The wider [S98 updater audit](rk-s98-firmware-updater-static-audit-2026-10-19.md)
still has open UI-to-transfer, firmware-transform, revision-compatibility,
retry/cancel, and device-acceptance questions.
