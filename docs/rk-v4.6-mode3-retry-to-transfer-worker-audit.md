# RK 4.6 mode-3 retry and transfer-worker audit

## Scope and evidence

This audit traces the retry and status branches of `FUN_0040A0F0` in the
model-specific updater through its next worker and section-dispatch calls.
It concentrates on the mode-3 path, its `0603:1021` and `0603:1020` HID
selectors, and the directly connected report APIs. It does not attempt to
reconstruct the entire updater or assign a protocol meaning to these
selectors.

Evidence is static PE bytes and import-table entries from the exact binary
below. The verifier checks 101 instruction-byte facts and 13 import mappings.
The updater was not launched. No HID or serial interface was opened, no
report or command was sent, and no bootloader or firmware write was attempted.

- **Direct** means an instruction, import, or dataflow is present in this PE.
- **Inferred** means the path follows from direct static branches but was not
  observed at runtime.
- **Unresolved** means the static evidence does not establish the result.

## Exact input and reproduction

The input is the extracted 4.6-labeled package member
`.research/rk46-extract-full/app/Dev/01AF/Update.exe`, a 2,109,952-byte x86
PE with image base `0x00400000` and SHA-256
`27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c`.
It is byte-identical to the installed 4.06 updater documented in the
[command `0x0419` trace](rk-updater-command-0419-static-path-audit.md).
The V4.6 package's `.upf` sample has a malformed parsed A-section length, so
the paths here are conditional code paths; this audit does not establish that
the sample is accepted.

From the repository root, run:

```powershell
python scripts/audit_rk46_mode3_retry_worker.py `
  --binary ".research/rk46-extract-full/app/Dev/01AF/Update.exe"
```

The script requires Python and `pefile`. It reads the PE as data and checks
its size, SHA-256, machine, image base, exact instruction bytes, and named IAT
slots. It does not execute the PE or access hardware.

## Entry into the mode-3 retry path

At `0x0040A17D`, `FUN_0040A0F0` compares `this+0x8E6C` with zero
(`80 BE 6C 8E 00 00 00`). A nonzero value branches to the separate path at
`0x0040A431`; the trace below covers the zero-flag path used by the reviewed
`0x0419` command chain. The retry counter is initialized to 7 at
`0x0040A1A7` (`BF 07 00 00 00`).

For mode 3, the worker calls the existing interface-search helpers with VID
`0x0603`, PID `0x1021`, and long-feature length `0x408`:

| Step | VA | Bytes | Static observation |
| --- | ---: | --- | --- |
| Set length | `0x0040A1B2` | `68 08 04 00 00` | Pushes `0x408` for the long-feature search. |
| Mode gate | `0x0040A1B7` | `83 F9 03` | Selects the mode-3 hard-coded pair. |
| First selector | `0x0040A1BC` | `BA 21 10 00 00`; `0x0040A1C1` `B9 03 06 00 00` | Sets PID `0x1021`, VID `0x0603`. |
| Long search | `0x0040A1C6` | `E8 65 C5 FF FF` | Calls `FUN_00406730(0x408)`. |
| Short selector/search | `0x0040A1CB`–`0x0040A1F2` | `BA 21 10 00 00`; `B9 03 06 00 00`; `E8 09 C7 FF FF` | Calls `FUN_00406900` for the same IDs. |
| Save/validate handles | `0x0040A1ED`–`0x0040A208` | `A3 14 5F 5C 00`; `A3 18 5F 5C 00`; `83 F8 FF`; `83 3D 14 5F 5C 00 FF`; `0F 85 D7 00 00 00` | Saves both handles to `0x005C5F14/18`; both must differ from `-1` to take the status-probe branch. |

The helper criteria are covered by the [mode-3 preflight audit](rk-v4.6-update-mode3-hid-preflight-audit.md): SetupAPI enumerates HID collections, `CreateFileW` requests read/write access with sharing and overlapped I/O, and the helpers check HID attributes/capabilities. In particular, the long collection must match the requested feature length and usage page `0xFF00`; the short helper accepts a nonzero feature length no greater than 8. These checks describe static selection logic, not a match on the connected keyboard.

## Initial-pair status probe

When both `0603:1021` handles pass the `-1` checks, `FUN_0040A0F0` resets
global gate `0x005C5F08` and calls `FUN_00409760` at `0x0040A35A`.
The helper constructs a feature buffer beginning `05 C9 60`
(`0x00409797` and `0x0040979C`), calls `HidD_SetFeature` at `0x004097A8`,
then polls with `HidD_GetFeature` at `0x0040980D`. Its poll counter is
initialized to 5 at `0x004097BE`, and each pass includes a one-second sleep
at `0x004097D0`.

The response check compares byte 0 against `0x60` at `0x0040981F`, loads
response byte 2 at `0x00409824`, tests it at `0x00409826`, and branches on
zero at `0x00409828`. On that qualifying response path the helper sets
`0x005C5F08=1` at `0x00409888` and starts a separate thread with entry
`0x00406C20` at `0x0040992D`–`0x0040993D`. `FUN_0040A0F0` tests the helper's
return value at `0x0040A35F`; nonzero returns from this worker at
`0x0040A361`.

The existing [status-to-transfer follow-up](rk-v4.6-mode3-status-to-transfer-worker-followup.md)
traces the separate `0x00406C20` → `0x0040B770` path. Under its additional
mode, object-flag, and status-result gates, it can call `FUN_0040A580` and
continue to the section worker. Those gates and device responses are not
runtime-observed.

If the status helper returns zero, `FUN_0040A0F0` permits the fallback only
when the mode is 0 or 3 (`0x0040A367`–`0x0040A373`). For mode 3 it sleeps
one second (`0x0040A379`–`0x0040A37E`), clears `this+0x8E6E` at
`0x0040A382`, and calls `FUN_0040A580` at `0x0040A389`.

## Retry via `0603:1020` and direct worker creation

When the initial pair does not yield two valid handles, modes 0 and 3 take
the search-status branch. It sleeps 2,000 ms via a call through the loaded
`Sleep` pointer (`0x0040A27B`–`0x0040A280`), then tries `VID=0x0603`,
`PID=0x1020`:

- `FUN_00406730(0x802)` is called at `0x0040A291`; `0x802` is decimal 2,050
  and is the required long-feature report length.
- `FUN_00406900` is called at `0x0040A2A8` for the short collection.
- The code stores both handles and compares each with `-1` at
  `0x0040A2B2`–`0x0040A2BE`.

If both pass, `0x0040A395`–`0x0040A3B4` sets `FUN_00406BD0` as the
`CreateThread` start address, passes the dialog object as its thread
parameter, and calls the `CreateThread` IAT at `0x00560480` (absolute IAT VA
`0x00560480` corresponds to the instruction operand at `0x0040A3B4`).
Otherwise, the code loads the old counter, decrements it, tests the old value,
and exits when that value was zero (`0x0040A2CA`–`0x0040A2CF`). With initial
value 7, the failed fallback search can therefore run on eight loop passes
(counter values 7 through 0), provided the mode and flag branches continue
to allow the loop. Exhaustion updates error status and restores the upgrade
button state.

The transfer worker at `0x00406BD0` calls `FUN_0040C090` at
`0x00406C10`. That wrapper passes object field `this+0x160`
(`0x0040C093`) to section dispatcher `FUN_00402A40` (`0x0040C099`). The
dispatcher checks update mode 3 at `0x00402A51`; its mode-3 branch can select
the C-section routine at `0x00402CE0`, while the other dispatched path
selects B-section work. The existing [firmware readback audit](rk-firmware-readback-audit.md)
maps the B/C update and verification routines: both send host-buffer data
through `HidD_SetFeature`, then use `HidD_GetFeature` for bounded in-memory
verification against that host image. That verification is not a firmware
export to disk.

## `FUN_0040A580` transition and second transfer-worker edge

The mode-switch helper allocates six bytes at `0x0040A603`, zeroes the
buffer, and writes prefix `05 75` at `0x0040A63B` and `0x0040A644`. Its
`this+0x8E6C` gate is at `0x0040A648`. On the zero-flag branch, mode 3 plus
`this+0x8E6F == 1` selects short-interface IDs `0603:1021`
(`0x0040A662`–`0x0040A684`); otherwise the helper uses the VID/PID globals
`0x005C6F78/0x005C6F74` (`0x0040A69F`–`0x0040A6AB`).

When a short handle is available, `HidD_SetFeature` is called at
`0x0040A75A` with the six-byte allocation and feature length from
`0x005C5F1C` (`0x0040A74D`). The length may be 1–8 according to the short
collection selector; if it is greater than six, the static call length
exceeds the visible buffer allocation. This is a potential static size
mismatch only: neither the selected length nor the API's behavior was
observed.

The helper sleeps 3,000 ms at `0x0040A765` and searches the fallback pair
`0603:1020` again, requiring a `0x802` long feature collection and a short
collection of length 1–8. If both handles differ from `-1`, it creates
`FUN_00406BD0` at `0x0040A833`–`0x0040A841`. On the failed-search branch,
the local counter is seeded to 3 (`0x0040A610`, `0x0040A654`), then decremented
and tested at `0x0040A7AD`–`0x0040A7B2`; this permits four total search
passes (counter values 3 through 0), subject to the helper's other branch
gates.

## HID and serial API boundary

The exact updater import table contains these relevant mappings, all verified
by the script:

| Absolute IAT VA | Import | Role in this static trace |
| ---: | --- | --- |
| `0x005601C8` | `HID.DLL!HidD_GetFeature` | Status polling and B/C verification reads. |
| `0x005601D8` | `HID.DLL!HidD_SetFeature` | Status/mode reports and B/C transfer writes. |
| `0x005601D0` | `HID.DLL!HidD_GetAttributes` | HID identity filter in the enumerator helpers. |
| `0x005601DC` | `HID.DLL!HidD_GetPreparsedData` | Capability lookup in the enumerator helpers. |
| `0x005601C4` | `HID.DLL!HidP_GetCaps` | Collection usage and report-length checks. |
| `0x005604EC` | `SETUPAPI.DLL!SetupDiGetClassDevsW` | HID interface enumeration. |
| `0x005604E8` | `SETUPAPI.DLL!SetupDiEnumDeviceInterfaces` | HID interface enumeration. |
| `0x005604E0` | `SETUPAPI.DLL!SetupDiGetDeviceInterfaceDetailW` | HID interface-path resolution. |
| `0x00560298` | `KERNEL32.DLL!CreateFileW` | Opens candidate HID interface paths in the selector helpers. |
| `0x00560338` | `KERNEL32.DLL!Sleep` | Retry/poll delays. |
| `0x00560480` | `KERNEL32.DLL!CreateThread` | Starts the status and transfer workers. |
| `0x005602CC` / `0x005602D0` | `KERNEL32.DLL!ReadFile` / `WriteFile` | Imported for the separate serial path; these imports alone do not link UART to this HID path. |

The bounded call path traced here has no direct call to the UART open helper
`FUN_00404E60`; the updater's serial receive state machine and its file sinks
are documented separately in the [UART state-machine audit](rk-updater-uart-state-machine.md).
This direct-edge observation does not exclude an indirect or external trigger
that relates the subsystems elsewhere in the program.

## Findings and limits

- **Proven statically:** the mode-3 path in this image uses hard-coded
  selectors `0603:1021` and `0603:1020`, with exact long-feature lengths
  `0x408` and `0x802` respectively, plus a short-feature collection no longer
  than 8 bytes.
- **Proven statically:** initial `0603:1021` handle success enters a feature
  status probe; its conditional paths can start worker `0x00406C20` or enter
  `FUN_0040A580`. Failed `0603:1021` search can retry `0603:1020` and create
  transfer worker `0x00406BD0` when both fallback handles pass.
- **Proven statically:** `FUN_0040A580` contains a `05 75` feature-write path
  and a second conditional edge to worker `0x00406BD0`.
- **Inferred:** the identifiers `0603:1021` and `0603:1020` correspond to
  distinct device or updater states. Their hardware or bootloader meaning is
  not established by these bytes.
- **Unresolved:** whether this `.upf` sample parses successfully, whether
  these feature collections exist for a physical device, which branch a real
  update takes, what the response bytes mean, whether any write is accepted,
  and whether the separate UART state machine is connected through an
  indirect or external path.
- **Not established:** a passive firmware-copy operation. The traced section
  reads verify data after host-to-device update writes; their returned bytes
  are compared in memory with the chosen host image.

Related evidence: [command `0x0419` trace](rk-updater-command-0419-static-path-audit.md),
[mode-3 HID preflight](rk-v4.6-update-mode3-hid-preflight-audit.md),
[status-probe worker follow-up](rk-v4.6-mode3-status-to-transfer-worker-followup.md),
[firmware readback audit](rk-firmware-readback-audit.md), and
[UART receive state machine](rk-updater-uart-state-machine.md).
