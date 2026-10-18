# RK 4.6 profile routing verified against constructor vtables and RTTI

## Scope and inputs

This audit joins the 265-row profile selector map to the class vtables that
the V4.6-labeled `DeviceDriver.exe` installs. The PE is pinned by SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`
(2,418,176 bytes; preferred image base `0x00400000`). The input is the
extracted file at
`.research/rk4_6_official_extract_20261015/app/DeviceDriver.exe`; profile
fields come from [`models-4.6.json`](../models-4.6.json) through the
[selector map](rk-v4.6-profile-selector-map.csv).

The executable was only read as PE bytes and disassembly. The RK application
and updater were not run. No HID or other device interface was opened; no
report or command was sent. This proves software-side configured routes in
this exact file, not physical keyboard compatibility or runtime success.

## Verified direct-profile routes

The vtable constructor address point is confirmed from executable instructions.
Each table's preceding MSVC Complete Object Locator resolves to its named
TypeDescriptor and a hierarchy that includes `CHidDev`.

| `Fw` in profile | Rows | Selector action and constructor | Installed class vtable | RTTI class | Static protocol evidence |
| --- | ---: | --- | --- | --- | --- |
| omitted or `0` | 133 | Allocates `0x298` bytes; calls `0x0040D640` to initialize the `CHidDev` base; selector then overwrites the first word with `0x005D410C` at `0x0041655B`. | `0x005D410C` | `CDevRKKB` : `CHidDev` | This audit establishes the family route only. The 4.6 RKKB feature-method map is not complete. |
| `1` or `2` | 131 | General nonzero branch; allocates `0x2F0` bytes and calls `0x0040F490`, which writes `0x005D3D0C` at `0x0040F4C3`. | `0x005D3D0C` | `CDevG5KB` : `CHidDev` | The separate 4.6 screen/GIF audit traces G5 slots `+0x54` and `+0x58` to GIF-parameter and page-transfer methods and a `HidD_SetFeature` path. Other feature routes remain incomplete. |
| `3` | 1 | Dedicated descriptor gate; allocates `0x2D4` bytes and calls `0x0040DAD0`, which writes `0x005D2464` at `0x0040DB03`. | `0x005D2464` | `CDev3632` : `CHidDev` | The 20-byte request/read/write path and selector call roles are statically mapped; selector meanings and device acceptance remain unresolved. |

The row-level result is [`rk-v4.6-profile-family-rtti-map.csv`](rk-v4.6-profile-family-rtti-map.csv).
Its `physical_compatibility_validated` column is `no` for every row. The
reproducible audit is [`audit_rk46_profile_family_rtti.py`](../scripts/audit_rk46_profile_family_rtti.py);
it checks the PE hash, validates each vtable-install instruction, follows RTTI,
then joins the verified constructor route to every selector-map row.

### Selector and RTTI evidence

- The selector body is at `0x00416460`. Its Fw-zero path starts at
  `0x00416537`; allocation and base initialization are at `0x00416541` through
  `0x00416554`, and the `CDevRKKB` vtable write is at `0x0041655B`. This
  distinction matters: `0x0040D640` alone installs the base `CHidDev` vtable
  `0x005D23F4`; it is not the final Fw-zero object vtable.
- The nonzero constructor `0x0040F490` installs `0x005D3D0C`; that table's
  TypeDescriptor is `.?AVCDevG5KB@@` at `0x0061A0EC`.
- The Fw-three constructor `0x0040DAD0` installs `0x005D2464`; that table's
  TypeDescriptor is `.?AVCDev3632@@` at `0x0061A0BC`.
- The Fw-zero vtable `0x005D410C` has TypeDescriptor
  `.?AVCDevRKKB@@` at `0x0061A104`.
- The three class hierarchies list `CHidDev` as their base. One earlier report
  used the expanded but incorrect name `CDevHidDev`; it has been corrected to
  the exact RTTI name.

The selector applies descriptor-capability gates before these allocations.
The gates are listed per profile in the row-level CSV and documented in the
[selector audit](rk-v4.6-profile-selector-audit.md). Static catalog IDs are
candidate inputs to those gates; the needed HID descriptor fields were not
read from a physical keyboard.

## Model groups and limits

The sole Fw-three row is profile `0208`, **M20**, configured ID `258A:0208`.
It is the only direct-profile row routed to `CDev3632` by this selector. This
does not rule out a separate companion/wireless `CDev3632` path elsewhere in
the binary; that path is not covered by this direct-profile table.

All 12 S98-labeled rows in this package (`0174`, `01AF`, `01BF`, `021E`,
`0223`, `0224`, `022B`, `022F`, `0230`, `023F`, `0240`, and `0241`)
have `Fw=1` and route to `CDevG5KB`. This statement is limited to those
installed profiles and is not a claim that
every physical S98 revision is supported. (The S98 profile detail is also
listed in [`rk-s98-profile-variants.csv`](rk-s98-profile-variants.csv).)

The earlier
[4.6 projected map](rk-profile-driver-family-map-v4.6-projected.csv) applied
the installed 4.06 zero/nonzero rule and put Fw-three M20 in the G5 bucket.
This RTTI-backed route supersedes that projection for the 4.6-folder binary:
the verified counts are **133 `CDevRKKB`, 131 `CDevG5KB`, and 1 `CDev3632`**.
The earlier file remains useful only as the explicitly labeled 4.06-rule
projection.

The model-to-family map still does not establish:

- whether any named physical model or revision presents the descriptor fields
  required by its selector branch;
- which model revision or wireless receiver corresponds to reused USB IDs;
- whether all controls and serializers are reachable for every profile in its
  family, or accepted by firmware;
- complete V4.6 `CDevRKKB` feature semantics or complete G5 settings path. A
  partial 26-slot `CDevRKKB` vtable and `ApplySetting` route is now documented
  in the [RKKB settings audit](rk-v4.6-cdevrkbb-settings-and-vtable-audit.md)
  and [row-level method map](rk-v4.6-cdevrkbb-vtable-map.csv);
- exact meanings for the `CDev3632` selectors or its possible companion path;
- support for keyboards absent from this package snapshot.

These are the remaining model/family protocol gaps. No static finding here
justifies opening the connected keyboard or sending it a discovery request.
