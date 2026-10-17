# RK DeviceDriver.exe 4.6 profile selector and Fw=3 audit

## Scope and evidence identity

This report statically examines device/profile selection in the extracted
`DeviceDriver.exe` from the V4.6-labeled package. The exact input is
`DeviceDriver.exe`, 2,418,176 bytes, SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
The PE is x86 with preferred image base `0x00400000`; addresses below are
preferred-image VAs. Disassembly came from GNU `objdump -d` over this exact
file. The executable was not launched, and no device interface was opened.

The profile rows come from the extracted 265-file `Dev/*/KB.ini` catalog
represented by [`models-4.6.json`](../models-4.6.json). The row-by-row result
is [`rk-v4.6-profile-selector-map.csv`](rk-v4.6-profile-selector-map.csv),
reproducible with [`audit_rk46_profile_selector.py`](../scripts/audit_rk46_profile_selector.py).
The catalog JSON is 2,139,805 bytes with SHA-256
`2035aa6013a559770eac41fdfbbe7cc87472d8e8b30a3f736a88eebfadc6e91e`;
its source manifest digest is documented in the profile-catalog delta report.

**Evidence labels:** the branch conditions, immediate values, calls, table
offsets, and profile fields are **proven statically** for these inputs.
The correspondence from the distinct constructors to a model name or exact
keyboard electronics remains **inferred or unresolved**. A config profile is
evidence of declared software selection data, not proof of a physical model's
existence, detection, or compatibility.

## Recovered call path

The selector is at `0x00416310` and spans the decoded body through
`0x00416402`. Its direct callsite is `0x004164C7`, inside the per-profile
matcher/constructor routine at `0x00416460`–`0x0041675C`. That routine is
called by the wrapper at `0x00416410` (`0x00416412`), and the wrapper is called
from two decoded device-event paths at `0x00448BA8` and `0x00449FA4`.

At `0x00416493`, the per-profile routine starts at table address
`0x00626DDA`; it reads the two preceding words at offsets `-0x0A` and `-0x08`
as the candidate profile IDs, and forms the profile pointer at `ESI-0x0A`.
It calls the selector at `0x004164C7`, then advances by `0x28` bytes at
`0x00416725` until `0x00629CBA`. This is a 300-slot runtime table. The
extracted package has 265 configured direct-PID profiles, leaving unused
capacity; the table capacity is not the configured profile count.

The selector iterates capability records beginning at `0x0063C048` in
`0x22C`-byte increments, stopping at `0x00646E08` (80 record slots). It first
checks the supplied profile/device ID fields against record offsets `+0x08`
and `+0x0C`, then reads the profile `Fw` byte from offset `+0x0A`.
The relevant instructions are `0x00416330`–`0x00416349`.

## Selector branches in this binary

| `Fw` value | Static descriptor acceptance branch | Implementation factory in caller |
| --- | --- | --- |
| Omitted or 0 | Vendor page `0xFF00`, usage 1, marker `0x41`; or consumer page `0x000C`, usage 1, record field `-0x0C == 3`, with PID `0x49` excluded. | `0x0040D640` (`Fw=0` path at `0x00416537`–`0x004165C8`) |
| Exactly 3 | Vendor page `0xFF02`, usage 2, and both capability-record fields at `-0x0C` and `-0x08` equal `0x14`. | Dedicated allocation size `0x2D4` and constructor `0x0040DAD0` (`0x004165CD`–`0x0041667D`) |
| Other nonzero values | General nonzero branch: vendor-defined `0xFF00`/`0xFF02` capability pattern with marker `0x208`, or the consumer-page alternative. | Allocation size `0x2F0` and constructor `0x0040F490` (`0x00416682`–`0x0041671B`) |

The conditions are visible in the selector at `0x0041634B`–`0x004163E0`.
For `Fw=3`, `0x0041637D` checks the value equals 3; `0x00416382` checks
`0xFF02`; `0x0041638A` checks usage 2; and `0x00416390`–`0x0041639D`
checks the two `0x14` fields. A match returns through `0x004163F9` to the
caller. The caller then tests `Fw` at `0x00416537`, branches specially for 3
at `0x004165CD`, and uses separate constructor paths.

For values 1 and 2, the caller selects the same general nonzero constructor
path. This states the selection implemented in this binary; it does not prove
every firmware version under those profiles accepts the same reports. The
new `Fw=3` path is distinct from that general nonzero branch both in its
capability gate and its constructed object. The constructor's RTTI and vtable
are mapped separately in the
[`Fw=3 CDev3632 vtable audit`](rk-v4.6-fw3-cdev3632-vtable-audit.md). That
class identity describes the implementation selected by this code path, not a
validated physical model or firmware revision.

## Reconciliation with the extracted KB.ini rows

The catalog contains 265 direct-PID rows. The raw `Fw` distribution is:

| Raw `Fw` value in `KB.ini` | Rows | Selector/factory path |
| --- | ---: | --- |
| Omitted | 132 | Loaded as zero; zero branch / constructor `0x0040D640` |
| `0` | 1 | Zero branch / constructor `0x0040D640` |
| `1` | 113 | General nonzero branch / constructor `0x0040F490` |
| `2` | 18 | General nonzero branch / constructor `0x0040F490` |
| `3` | 1 | Dedicated branch / constructor `0x0040DAD0` |

The sole `Fw=3` row is profile `0208`, model label **M20**, USB ID
`258A:0208`, with configured `Psd` text `6,0,0,0,0,54`. These are values
from the extracted configuration. `Psd` is listed for row-level comparison;
this audit does not show that this string is consumed by the recovered direct
selector.

The 4.06 installed-build selector at `0x004155C0` (documented separately)
routes all nonzero values through its general nonzero descriptor predicate.
The candidate 4.6 selector adds the explicit `Fw==3` predicate and the
separate constructor case described above. Consequently, projecting 4.06's
zero/nonzero rule onto all 4.6 rows would misdescribe profile `0208`.

## What this establishes and what it does not

**Established statically:** this exact 4.6-folder executable loads an `Fw`
profile field, matches candidate records using configured identity fields and
HID capability records, applies three selector cases (`Fw=0`, `Fw=3`, other
nonzero), and dispatches those cases through three distinct constructor
addresses. The one `Fw=3` catalog row is `0208` / M20 / `258A:0208`.

**Not established:** that a physical M20 exists in a given revision, reports
the required `0xFF02`/usage-2/`0x14` descriptor fields, is successfully detected
by this path, or can execute any specific setting operation. No keyboard was
connected or queried. The report does not analyze downstream `Fw=3` protocol
semantics, device-event success, runtime branches, firmware revision checks,
other package components, or all keyboard models/releases outside this one
extracted package.
