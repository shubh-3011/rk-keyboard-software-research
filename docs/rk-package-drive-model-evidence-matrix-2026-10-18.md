# RK model and package evidence matrix — 2026-10-18

This matrix joins the two pinned Hub Driver profile catalogs with the dated
RK Drive public keyboard registry. It records identifier-level overlaps and
keeps package configuration, public web-app declarations, and physical-device
compatibility as separate evidence. It is a static comparison: no RK
application or updater was run, no HID interface was opened, and no device
report was sent.

## Snapshot-level coverage

| Artifact | Inventory in this archive | What the inventory establishes | What it does not establish |
| --- | --- | --- | --- |
| Installed Hub Driver 4.06 profile catalog (`models.json`) | 188 named PID profiles across 57 derived name-family labels; 189 `KB.ini` directories, including unregistered `01C7` | The installed package contains these profile/configuration records. Its `Fw` field routes profiles through the 4.06 native class-selection path described in [`rk-profile-family-protocol-coverage.md`](rk-profile-family-protocol-coverage.md). | That a physical model exists under every label, that a device passes HID descriptor checks, or that listed controls work on it. |
| Official 4.6-labeled Hub Driver extraction (`models-4.6.json`) | 265 named PID profiles across 70 derived name-family labels; 265 `KB.ini` directories; no unregistered profile directory | This package snapshot adds 77 profile codes to the 188-code baseline and drops none. Its extracted `Cfg.ini` still says `Ver=0x406`; the 4.6 label identifies the installer snapshot, not a confirmed internal software version. | That it is a universal catalog or that every profile corresponds to a validated retail model/revision. |
| RK Drive public JavaScript registry (`rk-drive-catalog.json`) | 177 general keyboard connection descriptors, 96 displayed labels, 104 distinct VID/PID pairs; 171 declare `BeiYing`, six `QiWang`; two specialized RK68 HE profiles are stored separately as `Bytech` | These are records in the dated public web app bundle, including declared connection types, HID usages, layouts, effects, and image URL references. | That the registry covers all RK products or revisions, or that a declared feature is reachable/accepted by hardware. |
| [`SOFTWARE-DIRECTORY.md`](../SOFTWARE-DIRECTORY.md) | Community project references and their documented scope | It helps locate independent projects and states their README-level claims. | It is not a model-to-driver compatibility catalog or independent validation of those claims. |

The complete package delta is in [`rk-profile-catalog-v4.6-delta.md`](rk-profile-catalog-v4.6-delta.md); the Drive registry extraction method and feature limits are in [`rk-drive-web-app-audit.md`](rk-drive-web-app-audit.md).

## Exact profile PID overlap with RK Drive

The profile extractors record the configured default VID `0x258A` and each
four-digit profile code. For this comparison, a Drive descriptor is counted as
an **exact direct-ID overlap** only when its VID is `0x258A` and its PID equals
that profile code. No model-name similarity was used to create this match.

| Profile snapshot | Named profile codes | Exact direct-ID overlaps in Drive | Profile codes without that exact Drive pair |
| --- | ---: | ---: | ---: |
| Installed 4.06 | 188 | 39 | 149 |
| 4.6-labeled package | 265 | 93 | 172 |
| New codes in 4.6-labeled package | 77 | 54 | 23 |

All 39 baseline overlaps and all 54 additional overlaps have Drive rows
declared as USB `BeiYing` descriptors. Their declared HID usages are
`0xFF00:0x0001` (35 baseline, 50 additional) and `0xFF02:0x0001` (four
baseline, four additional). The exact product-ID match is useful cross-catalog
evidence, but it does not prove the legacy driver's runtime checks accept the
same HID collection, nor that two products with the same ID share hardware,
firmware, or feature behavior.

The 4.6 Drive registry has 104 distinct VID/PID pairs in total. The 93 exact
profile-code overlaps are only the direct USB-ID subset. The other pairs
include receiver identifiers shared by many labels and separate vendor/usage
families. A Drive row with no direct profile-code overlap is therefore not
evidence that a model is unsupported by either application; it simply lacks
this exact numeric link in the compared catalogs.

## Configured wireless IDs are many-to-many candidates

The 4.06 package has seven profiles with `VID_Wireless`/`PID_Wireless` values;
the 4.6-labeled package has 23. Each version configures the same four receiver
pairs, and each pair appears in the Drive registry:

| Configured receiver ID | 4.6 profile rows | Drive receiver labels in this snapshot | Static interpretation |
| --- | ---: | ---: | --- |
| `258A:0150` | 6 | 46 | Shared by many products, including ten S98 labels; not a unique model identifier. |
| `258A:01BB` | 11 | 2 | Shared receiver pair; multiple profiles and two Drive labels refer to it. |
| `258A:0233` | 4 | 5 | Shared receiver pair; multiple profiles and Drive labels refer to it. |
| `3554:FA09` | 2 | 24 | Shared receiver pair; the M70 configuration rows are only two among 24 Drive labels. |

These rows are configured scan candidates, not validated receiver-to-keyboard
bindings. A receiver VID/PID match cannot select one model when the Drive
registry reuses that pair. This is consistent with the existing wireless
selection caveats in [`rk-profile-family-protocol-coverage.md`](rk-profile-family-protocol-coverage.md).

## S98 identifier and artwork evidence

| Evidence source | S98 records | Direct conclusions |
| --- | --- | --- |
| 4.06 profile catalog | Eight profile codes: `0174`, `0224`, `022B`, `022F`, `0230`, `0223`, `01BF`, `01AF` | Eight package profiles are named/derived as S98 family entries; this is package configuration evidence. |
| 4.6-labeled profile catalog | Twelve codes: the eight above plus `021E`, `023F`, `0240`, `0241` | Four more S98-named profile configurations are present in this package snapshot. All twelve have `Fw=1`, a static package-class input, not a physical firmware-version observation. |
| RK Drive keyboard registry | Ten displayed S98 labels and 20 rows: ten USB PIDs plus ten receiver rows | Ten USB PIDs exactly overlap 4.6 profile codes. The labels map `01AF` to base S98, `0223` TH, `0230` RU, `022F` JP, `022B` ES, `0241` FR, `0240` KR, `023F` TC, `0224` DE, and `021E` POR. `0174` and `01BF` have no exact S98 PID row in this Drive snapshot. |

All ten S98 receiver descriptors use `258A:0150`, usage `FF02:0002`. That same
receiver pair is shared across 46 displayed Drive labels in the snapshot, so
it cannot by itself identify the S98 regional variant. Exact USB PIDs provide
more separation in this registry, but the static catalog does not observe
which device is actually attached.

The Drive catalog records RK-hosted product-photo **URLs** for the ten S98
labels; for example, its base entry references
[`keyboard_rk-s98.png`](https://drive.rkgaming.com/src/assets/images/keyboard_rk-s98.png).
The image URL index is [`rk-drive-image-references.csv`](rk-drive-image-references.csv).
This archive stores references, not image bytes. The Hub Driver package also
has profile-local `keyimg.png`/`kbled.png` resources for some profiles; those
are UI-layout/lighting resources, and their presence does not prove that they
are product photographs or that the app selects the same image as Drive.

## Package class and firmware boundary

`Fw` in `KB.ini` is a profile-selection field used by the inspected software;
it is not the keyboard's observed firmware version. The verified native
class counts are:

| Driver binary snapshot | `CDevRKKB` | `CDevG5KB` | `CDev3632` |
| --- | ---: | ---: | ---: |
| Installed 4.06 | 125 | 63 | 0 |
| 4.6-labeled package's own driver | 133 | 131 | 1 |

The class counts describe static routing after package-profile and descriptor
gates in the audited binaries. They do not validate that an attached model
passes those gates or accepts the class's operations. For exact route
evidence, use [`rk-profile-driver-family-map.csv`](rk-profile-driver-family-map.csv)
for 4.06 and [`rk-v4.6-profile-family-rtti-map.csv`](rk-v4.6-profile-family-rtti-map.csv)
for the 4.6-labeled driver. Do not use the older *projected* 4.6 map as a
verified result; it is explicitly superseded by the RTTI-backed map.

## Still unknown from these artifacts

- A global RK model-to-driver/version/region matrix, including every Hub,
  Web, firmware, QMK/VIA, and product-specific route.
- Physical identity and firmware revision for any attached keyboard, or
  whether catalog matches correspond to the same board revision.
- A validated mapping from shared receiver IDs to one model or regional
  variant.
- Whether all declared profile features and Drive UI controls are reachable
  and accepted by each corresponding device.
- Whether the 4.6-labeled package's 77 added profiles are supported by each
  current product carrying a similar marketing name.

The storefront crosswalk is a dated name-token discovery aid, not a global
catalog; see [`rk-public-model-coverage-gaps.md`](rk-public-model-coverage-gaps.md).
