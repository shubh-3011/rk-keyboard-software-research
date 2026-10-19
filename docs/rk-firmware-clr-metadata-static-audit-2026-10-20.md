# RK updater CLR metadata static audit

**Scope.** This pass parses the eight hash-pinned CLR updater images listed in [the CLR profile inventory](rk-firmware-clr-profile-inventory-2026-10-20.csv), acquired under `.research/rk-firmware-catalog-2026-10-19`. It inspects PE/CLI metadata directly from package bytes. It does not load or execute an assembly, extract a resource, open a device interface, or communicate with a keyboard or updater.

## Results

- All eight images parsed with `ok` status. Their metadata identifies CLR `v4.0.30319`; no custom metadata streams, unsupported metadata tables, or unresolved parser conditions were recorded.
- The ledgers contain 6,074 selected metadata rows: 1,094 TypeRef, 264 TypeDef, 1,136 Field, 1,456 MethodDef, 2,020 MemberRef, 8 Assembly, 48 AssemblyRef, and 48 ManifestResource rows. The target-name ledger contains 512 rows: 304 MethodDef, 104 `#US` heap strings, 40 Field, 32 TypeDef, 24 ManifestResource, and 8 Assembly matches.
- Every image declares six AssemblyRef rows: `mscorlib`, `System.Windows.Forms`, `System`, `System.Drawing`, `System.Management`, and `System.Core`. Each has zero ImplMap rows, so this metadata contains no declared P/Invoke mappings. That does not exclude dynamic loading, calls through managed wrappers, or native behavior in embedded payloads.
- The six X87/X104 images have identical row-byte digests across AssemblyRef, TypeDef, MethodDef, and MemberRef. The two R108 images form a second identical group for those tables. R108 has 139 TypeRef and 254 MemberRef rows; X87/X104 have 136 and 252 respectively. This is metadata-level grouping only.
- Names and references include `WB_HID_DFU_Updater`; `IntelHexReader.FirmwareInfo`; `WestberryFlasher.ProgramArgs`, `USBEventArgs`, `USBDeviceType`, and `USBDeviceMonitor`; and method names such as `EnumerateDevices`, `GetDeviceType`, and `GetDeviceID`. These are declared metadata names, not proof that any method is reachable or used.
- `#US` entries include WMI-like `Win32_PnPEntity`/`DeviceID LIKE 'USB%'` query text, `WB DFU` and `WB APP` connected/disconnected messages tagged `WinUSB`, and `libusb-1.0.dll` references. The ledger records heap tokens, offsets, and hashes; presence of a string does not prove its use.
- Six embedded manifest resources are present in each image. The two updater EXE payloads and two native library payloads have the same in-place hashes across all eight packages: `wb32_f022_hid_dfu_updater_V0.0.4.exe` (247,536 bytes; `0c2a35a685e1a3dd142cc7ee63590b4aa49e26922fe36cfcbef2affb412bf853`), V0.0.5 (248,048 bytes; `e98cb301502891f6b5c37c4fb8fe8a05893ad1fac6def0d49676b5198f46d819`), `libhidapi-0.dll` (66,967 bytes; `8d672ce45d76682a5cbe2b80ab6d65f96fa9cb4b46f3d3773df91f76fcf7088d`), and `libusb-1.0.dll` (223,179 bytes; `d439b7b6bf3bcf1defd3651e6d062513886cf13d25a2a4731e7654eb44419f35`). Resource bytes were hashed in place, not extracted. The properties resource hashes differ among the eight images.
- All 1,456 MethodDef rows have a bounded method-body header status recorded (418 fat and 1,038 tiny); IL was not disassembled. No call reachability or runtime behavior is concluded from these rows, names, or strings.

## Evidence files

- [Reproducible stdlib parser](../scripts/audit_rk_clr_metadata_static.py) — parses PE/CLI headers, metadata tables and heaps, selected method-body headers, and in-place resource ranges. It does not invoke a CLR or extract resources.
- [Metadata row ledger](rk-firmware-clr-metadata-row-ledger-2026-10-20.csv) — table token, file offset, row bytes/hash, names and signatures, MethodDef RVA/body-header information, and manifest-resource locations/hashes.
- [Target-name ledger](rk-firmware-clr-target-name-ledger-2026-10-20.csv) — relevant metadata names and `#US` entries with evidence class, tokens, offsets, and hashes.
- [Image summary](rk-firmware-clr-metadata-image-summary-2026-10-20.csv) — input package SHA-256, metadata version/streams, row counts, parse status, and unresolved conditions for each package.

## Reproduction

From this repository root, with Python 3:

```powershell
python scripts/audit_rk_clr_metadata_static.py
```

The default research path is the sibling `.research/rk-firmware-catalog-2026-10-19`. To select another copy explicitly:

```powershell
python scripts/audit_rk_clr_metadata_static.py --research-root ..\.research\rk-firmware-catalog-2026-10-19
```

The parser hashes each input before analysis and writes the three CSV ledgers above. SHA-256 values, offsets, parser row status, and explicit evidence-class text make the findings independently checkable against the acquired package bytes.

## Limits and unresolved questions

This is a metadata inventory, not a complete decompilation or reverse engineering of the updater. It does not establish which methods execute, whether a named device-discovery path is live, how dynamic/native APIs are called, what firmware protocol bytes mean, or whether a payload is safe. Embedded EXE/DLL resources were not unpacked or analyzed here. The native updater behavior, dynamic loading, method call graph, model/PID filtering behavior, and device-side effects remain unresolved. No hardware was accessed.
