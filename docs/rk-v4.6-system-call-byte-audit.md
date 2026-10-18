# RK 4.6 DeviceDriver system-call byte audit

## Scope

This audit rechecks all eight `syscall` (`0F 05`) and `sysenter` (`0F 34`)
byte-pattern matches recorded for the 4.6-labeled package's
`app/DeviceDriver.exe`. The input is 2,418,176 bytes with SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
The executable was not run. No keyboard, HID, serial device, updater, or
bootloader was contacted.

The package's `Update.exe`, `InitSetup.dll`, and `uninstall.dll` are
byte-identical to the 4.06 files. The 4.06 `unins000.exe` is absent from the
4.6 package. Their static syscall-byte results are covered by the
[4.06 system API crosswalk](rk-system-api-crosswalk.md); this report covers
the changed main driver only.

## Findings

The original raw scan found six `0F 05` pairs, two `0F 34` pairs, and no
`CD 2E` pair in the driver's executable section. Each pair was checked
against GNU `objdump` instruction boundaries and nearby references. The exact
addresses and classifications are in the
[candidate ledger](rk-v4.6-syscall-byte-matches.csv).

| Pattern | VA | Static interpretation |
| --- | ---: | --- |
| `0F 05` | `0x00426049` | Bytes 2–3 of the `E8` relative-call displacement at `0x00426047`. |
| `0F 05` | `0x0046A474` | Inside an indexed byte table. Code at `0x0046A370` reads bytes from table base `0x0046A3FC` after range-checking the index; the candidate lies within the accepted table range. |
| `0F 05` | `0x0046A5A4` | Inside the adjacent indexed byte table. Code at `0x0046A4A0` reads from table base `0x0046A52C`; the candidate lies within the accepted table range. |
| `0F 05` | `0x004C54CD` | Bytes in the `E8` relative-call displacement at `0x004C54CC`. |
| `0F 05` | `0x004D018F` | Bytes in the `E8` relative-call displacement at `0x004D018D`. |
| `0F 05` | `0x004ED924` | Crosses an instruction boundary: `0F` is the immediate byte of `AND EAX,0x0F` at `0x004ED922`; `05` begins `ADD EAX,0xEA00` at `0x004ED925`. |
| `0F 34` | `0x005197B0` | Bytes 2–3 of the `E8` relative-call displacement at `0x005197AD`. |
| `0F 34` | `0x00582EBD` | SIB/displacement bytes of `MOV BYTE PTR [EDI+ECX+0x34],DL` at `0x00582EBB`. |

The two candidates that a linear decoder labels `syscall` are bytes in the
indexed tables, not standalone instruction bytes. The remaining six matches
are inside other instructions or cross instruction boundaries. This closes
the raw-byte candidates for this exact PE: **no direct `syscall`, `sysenter`,
or `int 2e` instruction was identified**. The 4.6 driver also has no
`ntdll.dll` import and no imported name beginning with `Nt` or `Zw`.

This is a static instruction-boundary result, not a runtime system-call
trace. Calls made inside Windows libraries, device drivers, dynamically
loaded modules, COM servers, or other external components are outside this
PE. It also does not prove every indirect target in the driver or entire RK
suite has been resolved.

## Reproduction

The PE was examined with GNU `objdump` without executing it. Representative
commands, run from the research repository root:

```powershell
objdump -d --start-address=0x00426030 --stop-address=0x00426060 ..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe
objdump -d --start-address=0x0046A370 --stop-address=0x0046A3A0 ..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe
objdump -s --start-address=0x0046A400 --stop-address=0x0046A5D0 ..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe
objdump -d --start-address=0x0046A4A0 --stop-address=0x0046A4BC ..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe
objdump -d --start-address=0x004C54C0 --stop-address=0x004C54E8 ..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe
objdump -d --start-address=0x004D0180 --stop-address=0x004D0193 ..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe
objdump -d --start-address=0x004ED91C --stop-address=0x004ED92A ..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe
objdump -d --start-address=0x00519790 --stop-address=0x005197C0 ..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe
objdump -d --start-address=0x00582EA0 --stop-address=0x00582EE0 ..\.research\rk4_6_official_extract_20261015\app\DeviceDriver.exe
```

The addresses are specific to this hash-pinned PE. The 4.06 inventory and
limits remain in the [cross-version API and system-call report](rk-system-api-crosswalk.md).
