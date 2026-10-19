# RK firmware package PE call-path static audit (2026-10-20)

## Scope

This pass follows the 16 executable-section families in the firmware-family inventory. It selects one full-file SHA-256-pinned representative from each of the six native PE families that do not match either of the two audited S98 updater profiles, and inventories all eight CLR images in the remaining families. Inputs are the local firmware artifacts plus the prior package-detail, executable-family, and artifact-inventory CSVs.

This is offline static analysis. It did not execute vendor code, unpack the UPX-named image or any other payload, open a HID/USB/serial interface, or access the keyboard. The report and ledgers contain analytical metadata and byte offsets only; no vendor source, images, or resources are reproduced.

## Native PE representatives

| Family | Representative | Full package SHA-256 | Imports | Static communication findings |
|---|---|---|---:|---|
| RK918 | `20260701134047_3582.exe` | `55ffc5d825784af480820cdfac131698fc55056a9770ddb0ebb693003a49d2f3` | 652 | SetupAPI and generic file/device I/O imports; no HID or WinUSB imports. One `CreateFileA` site is reached by the bounded entrypoint walk. |
| RK61 / RK918 | `20260701134023_7164.exe` | `1cdf9a58f7005f15f8af5b2e0dd405f905e531f1463c9c41362ba29f3feef0d8` | 606 | HID, SetupAPI, and generic file/device I/O imports. Eight `WriteFile`/`CreateFileA` sites are reached; no HID/SetupAPI call site is reached by the walk. |
| RK68 | `20260701132640_1725.exe` | `13db96f029a307c59b1c630d17b0c90bfc787ab68d460ef0bf1a6229cf53abfd` | 607 | HID, SetupAPI, and generic file/device I/O imports. One `WriteFile` site is reached; HID and SetupAPI calls occur only as linear-disassembly candidates. Four immediate `0x005C` comparisons are recorded; only one lies in the walk's visited instruction set, and none is proven to be a device-selection gate. |
| R99 | `20260604145847_7241.exe` | `53447e088a42cc2050629b7fa97e71130a323d48c630abf4e5413b49ffd02186` | 661 | SetupAPI and generic file/device I/O imports; no HID or WinUSB imports. Three `ReadFile` sites are reached. |
| L98 / M87 | `20260701114713_5183.exe` | `556d738b446bc7f2f555976ea565d3aba7dec7fc1835adad342830b59f7773d5` | 606 | HID, SetupAPI, and generic file/device I/O imports. One `WriteFile` site is reached; HID and SetupAPI calls occur only as linear-disassembly candidates. |
| RK68 HE | `20260701133035_4658.exe` | `1740933f173a3fd3958ffa99d60a3de0fc8b1df024ef37dc6c7dceb92a4e9a30` | 25 | Executable section is named `UPX1`; no HID, SetupAPI, WinUSB, or generic file/device I/O imports were found in its import table. The section was not unpacked or emulated. |

Across the six images, the import tables contain no WinUSB API and no serial-specific API. The I/O imports `CreateFile*`, `ReadFile`, `WriteFile`, `DeviceIoControl`, and `GetOverlappedResult` are generic Windows I/O APIs; their presence alone does not establish that a handle refers to the keyboard. No exports were found in these six native representatives, so their roots are the PE entrypoints.

The bounded entrypoint walk recorded 14 imported generic file/device-I/O call instructions across five native profiles: the `RK918`, `RK61 / RK918`, `RK68`, `R99`, and `L98 / M87` families account for 1, 8, 1, 3, and 1 such sites respectively. (The table's communication findings list those root-reached sites.) No imported HID or SetupAPI call instruction was reached by that walk. This is a static decoding result, not proof those functions never execute: indirect dispatch, callbacks, dynamically resolved imports, data/code ambiguity, and incomplete root coverage can hide call paths.

## CLR image inventory

All eight CLR representatives import only `mscoree.dll!_CorExeMain`, declare CLR metadata runtime version `v4.0.30319`, and expose the standard `#~`, `#Strings`, `#US`, `#GUID`, and `#Blob` metadata streams. Their exact model labels, filenames, hashes, header fields, and stream offsets/sizes are in [the CLR inventory CSV](rk-firmware-clr-profile-inventory-2026-10-20.csv). This pass does not decompile managed IL or infer HID activity from the CLR bootstrap import.

## Evidence and interpretation

- The profile inventory records 14 non-S98 profile representatives (6 native and 8 CLR), full-file hashes checked against the artifact inventory, PE entrypoints, exports, executable-section hashes, import counts, and CLR metadata where present.
- The full import callsite ledger has 27,082 linear-disassembly candidates across the six native sections. Linear sweep can decode embedded data or misaligned instruction bytes as code. These entries must be treated as candidates, not calls proven to execute.
- The entrypoint/export reachability ledger has 1,810 import references decoded by a bounded x86 CFG walk. Of those, 14 are generic file/device-I/O APIs; there are no root-walked HID, SetupAPI, WinUSB, or serial-specific import references. “Reached” means only that the bounded static walk decoded an instruction site from a PE entrypoint; it does not prove runtime execution or intent.
- The unresolved-transfer ledger records 972 indirect call/jump instructions encountered during the entrypoint-rooted walks. Targets are unresolved statically, and these rows do not prove that an I/O operation follows.
- The four `0x005C` comparisons belong to the RK68 representative. The byte/instruction locations and reachability flags are in the PID candidate ledger. Immediate-value matches without data-flow, branch, or input-origin analysis are not proof of a model gate. No other selector PID or USB VID immediate comparison candidate was found by this pass.
- The reported lack of rooted HID calls is limited to statically imported direct IAT references in the selected native representatives. It does not rule out dynamically loaded modules, helper processes, unmodeled indirect dispatch, or device communication implemented by other package components.

## Reproduction

From the research repository root, with `pefile` and `capstone` installed from the existing audit requirements file:

```powershell
python scripts/audit_rk_firmware_pe_call_paths.py
```

The script verifies each representative's SHA-256 before parsing it and writes the following source-free ledgers:

- [Profile inventory](rk-firmware-pe-call-path-profile-inventory-2026-10-20.csv)
- [CLR image inventory](rk-firmware-clr-profile-inventory-2026-10-20.csv)
- [Linear import-call candidates with file offsets](rk-firmware-pe-import-callsite-evidence-2026-10-20.csv)
- [Entrypoint/export-rooted import references](rk-firmware-pe-entrypoint-import-reachability-2026-10-20.csv)
- [PID/VID comparison candidates](rk-firmware-pe-model-pid-callsite-candidates-2026-10-20.csv)
- [Unresolved indirect transfers](rk-firmware-pe-unresolved-indirect-call-evidence-2026-10-20.csv)\n