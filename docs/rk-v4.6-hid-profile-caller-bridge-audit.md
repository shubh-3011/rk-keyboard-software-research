# RK 4.6 HID eligibility methods: caller-to-profile bridge

## Scope and evidence identity

This static follow-up resolves the caller arguments for the eligibility methods documented in the [HID record-to-interface audit](rk-v4.6-hid-record-to-interface-eligibility-audit.md). It uses the 4.6-labeled `DeviceDriver.exe` at `.research/rk46-extract-full/app/DeviceDriver.exe`, PE32, preferred image base `0x00400000`, SHA-256:

`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`

The hash was rechecked against the local file. Addresses below are VAs from static disassembly of that exact binary. The executable was not run, and no physical device or HID interface was accessed.

## Where the expected VID/PID pair originates

The per-profile routine at `0x00416460` walks a runtime profile table with cursor `ESI` from `0x00626DDA` to `0x00629CBA`, stepping `0x28`. For each candidate, `0x00416498` reads a WORD from `[ESI-0x0A]`, `0x0041649C` reads a WORD from `[ESI-0x08]`, and `0x004164A0` sets `EDI = ESI-0x0A`. Thus `EDI` points to the current profile row: expected VID is its WORD at `+0`, expected PID is its WORD at `+2`, and `Fw` is its byte at `+0x0A`.

Before constructing a driver object, this same candidate pointer is passed to selector `0x00416310` at `0x004164C7`. That selector compares the candidate row's VID/PID to the discovered-interface table's VID/PID fields, then applies the HID usage/report-capability predicates. When the candidate is accepted, the per-profile routine passes the unchanged `EDI` pointer to the selected object's virtual slot `+4`. The `0x0040DD80` and `0x00413DD0` methods therefore receive the selected profile row directly; their `[arg+0]` and `[arg+2]` comparisons are against that row's VID/PID, not an independently supplied runtime probe structure.

The row-level catalog join is in [`rk-v4.6-profile-selector-map.csv`](rk-v4.6-profile-selector-map.csv). The [4.6 profile-selector audit](rk-v4.6-profile-selector-audit.md) documents that the 300-slot runtime table is reconciled to the 265 configured `Dev/*/KB.ini` direct-PID profiles represented by [`models-4.6.json`](../models-4.6.json). This is the software-configured profile source; it is not evidence that a physical keyboard presents the configured IDs or descriptor.

## Vtable routes and exact callsites

| Profile `Fw` branch | Constructor and installed vtable | Callsite to virtual slot `+4` | Vtable target | Profile-row argument |
| --- | --- | --- | --- | --- |
| Omitted or `0` | `0x0040D640` base initialization; `0x0041655B` installs `0x005D410C` (`CDevRKKB`) | `0x0041657E` | `0x00413DD0` | `EDI`, passed at `0x00416577` |
| `3` | `0x004165EF` calls `0x0040DAD0`, which installs `0x005D2464` (`CDev3632`) | `0x0041660C` | `0x0040DD80` | `EDI`, passed at `0x0041660B` |
| Other nonzero values, including `1` and `2` | `0x0040F490` installs `0x005D3D0C` (`CDevG5KB`) | A different virtual implementation is selected | Neither method in this audit | Same per-profile `EDI` row is used by the surrounding routine |

The vtable entries are corroborated by [`rk-v4.6-cdevrkbb-vtable-map.csv`](rk-v4.6-cdevrkbb-vtable-map.csv) (slot `+0x04`, entry `0x005D4110`, target `0x00413DD0`) and [`rk-v4.6-cdev3632-vtable-map.csv`](rk-v4.6-cdev3632-vtable-map.csv) (slot `+0x04`, entry `0x005D2468`, target `0x0040DD80`). The constructor-to-RTTI joins are in [`rk-v4.6-profile-family-rtti-map.csv`](rk-v4.6-profile-family-rtti-map.csv) and its [audit](rk-v4.6-profile-family-rtti-audit.md).

At both callsites, the caller loads the object vtable and its `+4` function pointer, sets `ECX` to the object, pushes `EDI`, and calls the function pointer. The target methods then compare the two profile-row words at `EDI+0` and `EDI+2` with the discovered row's stored VID/PID and apply their additional HID interface-shape filters.

## Profile joins

The selector map provides the configured names and IDs passed down this route:

- Profile `0208` is **M20**, configured VID/PID `258A:0208`, `Fw=3`, constructor `0x0040DAD0`; the family map resolves it to `CDev3632`, so its virtual slot `+4` reaches `0x0040DD80`.
- The `Fw` omitted/`0` branch uses `CDevRKKB` and `0x00413DD0` for its 133 catalog rows. The same family map links these rows to vtable `0x005D410C`.
- S98-labeled rows in the selector CSV, including profile `021E` (`RK-S98 Keyboard`, `258A:021E`), have `Fw=1` and use constructor `0x0040F490`; they do not route through either of the two methods traced here.

These are configuration-to-code joins from the exact 4.6 package snapshot. Profile labels and IDs come from the extracted package catalog; family assignments come from the binary's selector branches, constructor vtable writes, and RTTI. They should not be presented as verified physical-device identification.

## Conclusion and limits

**Proven statically:** the expected VID/PID arguments at `0x0040DD80` and `0x00413DD0` are the first two WORDs of the selected profile row. The `Fw` byte selects the driver family: omitted/zero uses `CDevRKKB` / `0x00413DD0`; `Fw=3` uses `CDev3632` / `0x0040DD80`; other nonzero values use a separate `CDevG5KB` route. The extracted profile map joins `0208` to M20 `258A:0208` and shows S98 examples on the other nonzero route.

**Physical-compatibility caveat:** no connected keyboard was opened or queried. The extracted profile catalog and static HID predicates do not prove which revision, wired/wireless interface, or physical unit reports those values, nor that a named keyboard will pass the gates. The profile-family map's `physical_compatibility_validated` column remains `no`.
