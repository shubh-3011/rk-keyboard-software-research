# Loaded-profile scalar correction, installed 4.06

## Finding

The earlier brightness probe named `WORD[0061158E]` `profile_code`. That field
participates in a constructor scan, but it is **not sufficient to identify the
profile currently loaded into the lighting UI**. A separate DWORD at
`0061175C` is written from the profile loader argument and consumed by the
lighting UI.

Bounded passive REA observation
`ev_2cd220be745ac3dfb3a2c62d09cc9ac058943ba0801190d8ac423dfe85e8926a`
returned loaded scalar **01AF** and constructor-scan scalar **023D** in the
same snapshot. Six relocated instruction witnesses passed. No vendor
function was called and no device command was sent. The installed executable
was independently hash-checked against
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.

This explains why mapping `023D` through Cfg.ini produced a G98 label while
the UI had displayed S98. It does not prove physical model identity, current
INI contents, or that a particular endpoint is open.

## Exact static chain

- Loader `004513B0` receives the numeric profile argument in ECX.
- `004513CB: 8BF9` saves ECX in EDI.
- `004513D9: 68B44E5D00` pushes the `KB.ini` string.
- `004513DE: 57` pushes the same EDI code into the path-format arguments.
- `004513DF: 6818956100` pushes the application-root string.
- `004513E4: 68C44E5D00` pushes the `%sDev\\%04X\\%s` path template.
- `004513FB: 893D5C176100` stores EDI to `0061175C`.
- `00451401: E811CE1100` invokes the path formatter.
- Lighting UI `00424AEA: 8B0D5C176100` loads the same DWORD.

There is also a direct mutation at `00447941: 891D5C176100`, so do not treat
the scalar as immutable or sufficient proof a file was successfully read.
The constructor scan instead loads `0061158E` at
`004465E0: 8B158E156100`. These addresses are not interchangeable.

All six probe witnesses and their explicit HIGHLOW relocation operands were
independently matched against the hash-pinned PE before attaching. Relocation
adjustments are explicit; no wildcard byte masking is used. The probe emits
only two scalar codes, no pointers, paths, handles, keymaps or input buffers.

## Brightness correlation and limits

The installed `Dev/01AF/KB.ini` bytes still have SHA-256
`7764882e813660dc0fc1b0ac9e95307faed300b4fd36731612261e37cc03e1db`.
Its ASCII-valued options declare `Fw=1`, `GaoshouIndex=17`, `DefBri=5` and
both `LightUI` and `LightHW` lists `0,4,8,12,16,20`. The file has no UTF-16 BOM;
it must not be blindly decoded as UTF-16. Its missing `LedOpt18` still ends
the override loop before textual rows 19/20.

A separate passive mapping snapshot,
`ev_9050794125da134081040a45623061e23f5c20621f04ab721f9e0f8c65fb66f6`,
passed all 24 witnesses and again returned:

- 24 zero mapping DWORDs, ordinary gate sum zero;
- Fw 1, mask zero, Gaoshou index 17, Off ordinal 18 and row count 19;
- selected ordinal 18, brightness index 5, LightUI and LightHW byte 20.

The older script's retained `profile_code: 023D` field means the
**constructor-scan scalar**; do not relabel original evidence or infer a G98
binding from it. The two observations were separate, not an atomic profile/
table snapshot. Matching INI values strengthen correlation but do not prove
complete active-profile/endpoint binding.

The next hardware gate remains a correctly targeted lighting-page
brightness-only observation and exact restoration with complete wire
preservation evidence. No new brightness write policy is enabled by this
finding, and no settings change was made during these snapshots.

## Retained files

- [Loaded-profile snapshot](runtime-evidence/rk406-loaded-profile-2026-10-27.json)
- [Mapping snapshot](runtime-evidence/rk406-wired-brightness-mapping-2026-10-27.json)
- [Passive scalar probe](../scripts/snapshot_rk406_loaded_profile.js)
- [Earlier bounds and parser recovery](rk406-brightness-next-step-2026-10-26.md)
