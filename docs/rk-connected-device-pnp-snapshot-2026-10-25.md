# Present RK-vendor PnP identity snapshot (2026-10-25)

## Scope and boundary

This is a one-time, read-only Windows Plug and Play metadata snapshot used to
check whether the connected unit can be matched to the S98 profile catalogs.
It queried present PnP records and registry-backed device properties only. It
did not open a device interface or handle, read a HID report, launch RK
software, or send a command. The instance-specific PnP path and USB port
location are intentionally omitted.

## Observed host metadata

The present-device inventory returned one product ID under VID `258A`:
PID `0150`. Its USB parent is reported as a generic `USB Composite Device`;
the hardware-ID list includes `USB\VID_258A&PID_0150&REV_0206` and
`USB\VID_258A&PID_0150`. The service is `usbccgp`. Windows reports the
manufacturer as `(Standard USB Host Controller)` and the bus-reported product
description is empty. Child HID collection names are generic.

The inventory therefore proves only that Windows currently has a present USB
composite device exposing VID/PID `258A:0150` and hardware-ID revision `0206`.
The revision field is not evidence of a firmware version. The generic strings
do not identify a retail model. No S98 PID was present in the `VID_258A`
records during this snapshot.

## Comparison with RK profile catalogs

The static catalog join gives these results:

| Catalog | Profiles | Direct profile code `0150` | `258A:0150` as wireless alias |
| --- | ---: | --- | --- |
| Installed 4.06 model catalog (`models.json`) | 188 | None | `020F` RK A70 Keyboard |
| Extracted 4.6 model catalog (`models-4.6.json`) | 265 | None | `020F` RK A70; `025A`, `02D1`, `02DA`, `02DB`, and `02F6` RK S104 variants |

The 4.06 catalog's S98-named rows are `0174`, `01AF`, `01BF`, `0223`, `0224`,
`022B`, `022F`, and `0230`. The 4.6 catalog has twelve S98-named rows:
`0174`, `01AF`, `01BF`, `021E`, `0223`, `0224`, `022B`, `022F`, `0230`,
`023F`, `0240`, and `0241`. None declares `258A:0150` as its wireless alias.
These are package-catalog facts; they do not establish which physical model a
shared or mode-dependent USB ID represents.

The joins were made from the profile JSON `code`, `name`,
`features.wirelessVendorId`, and `features.wirelessProductId` fields. The
catalogs use `258A:0150` as a wireless alias for A70/S104 rows, not as a direct
profile code. That suggests a possible wireless-path association for those
rows, but does not establish the meaning of this connected composite device.

## Assessment

- **Proven:** This Windows snapshot exposes a present `258A:0150` composite
  USB device. The two captured RK model catalogs have no direct profile code
  `0150`; their S98 rows use other codes.
- **Inferred:** In the examined catalogs, `258A:0150` is associated with the
  wireless aliases of A70/S104 profiles, so this ID alone does not support
  identifying the connected unit as an S98.
- **Unresolved:** The physical product, revision, connection mode, and whether
  the unit is an S98 using an undocumented/shared/alternate ID. PnP metadata
  does not identify the device more specifically, and no HID descriptor or
  device report was queried.

This identity result does not change the separate static `0x88` finding: the
4.6 G5 helper contains a conditional feature-write/read/chunk-copy path, but
no caller requesting a complete image or saving its buffer to a file is
proven. The present PnP ID cannot be tied to that method or to firmware
readback. See the [command-`0x88` sink audit](rk-v4.6-g5-command-0x88-response-sink-audit.md)
and [profile-family map](rk-v4.6-profile-family-rtti-audit.md).

## Reproduction outline

The snapshot came from `Get-PnpDevice -PresentOnly`, filtered in memory for
present `VID_258A` records, followed by `Get-PnpDeviceProperty` for
`DEVPKEY_Device_HardwareIds`, `DEVPKEY_Device_Service`,
`DEVPKEY_Device_Manufacturer`, and `DEVPKEY_Device_BusReportedDeviceDesc`.
Only sanitized product identifiers and properties are recorded here; the
computer-specific instance path and port are not part of this finding.
