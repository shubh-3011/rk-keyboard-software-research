# RK F99 macOS package: static findings

This is a source-free report of a read-only static inspection of the official
RK 3.2.2 universal macOS disk image. No vendor code was executed; the image was
not mounted; no updater or keyboard interface was accessed; and no device was
changed. The repeatable outer-image/APFS-block/Mach-O pass uses Python's
standard library and keeps its reconstructed APFS partition in a temporary
file that is deleted when the script exits.

## Source and container evidence

- Input: `RK-3.2.2-universal.dmg`, 235,050,258 bytes.
- SHA-256: `d0f624aab5caf23c008c0024a63c3c438c9d5c3340503dc770f4957bae2e1951`.
- The trailer at the final 512 bytes has UDIF `koly` magic, version 4, one
  segment, and an XML property list at file offset 234,998,608, length 39,207.
- The property list describes seven `blkx` maps. The APFS map is ID 3, begins
  at disk sector 40, and spans 1,337,079 sectors (684,584,448 bytes). Its
  compressed/raw/zero runs reconstruct and validate an APFS NXSB at partition
  offset 32. APFS reports 4,096-byte blocks, 167,134 blocks, and container UUID
  `bfb8f183-bfba-4318-9a67-3db690078a02`.
- Reconstructed APFS partition SHA-256:
  `37a2e49490dd1cad7c2cb4ee108aaa7a2e87f67a7c1ac36c82985e2faa6a6c90`.

## Application and native-code evidence

- Seventeen validated fat Mach-O candidates were found in APFS physical bytes;
  all 34 slices have x86_64 and arm64 architectures. These are physical
  signatures, not APFS path records, so the candidate count is not a verified
  count of app-bundle files.
- The candidate at partition offset `3,239,936` has an x86_64 executable slice
  at `3,256,320` (32,832 bytes) and an arm64 executable slice at `3,305,472`
  (69,968 bytes). Both link `@rpath/Electron Framework.framework/Electron
  Framework` and `/usr/lib/libSystem.B.dylib`. The minimum OS load commands are
  macOS 10.13 for x86_64 and macOS 11.0 for arm64 (SDK 12.3).
- A bundle candidate at partition offset `173,424,640` has x86_64 and arm64
  slices and imports Node-API, IOKit/HID, CoreFoundation, and AppKit symbols.
  The symbol ledger includes `IOHIDManagerCreate`,
  `IOHIDManagerSetDeviceMatching`, `IOHIDManagerCopyDevices`,
  `IOHIDDeviceOpen`, `IOHIDDeviceGetReport`, and `IOHIDDeviceSetReport`.
- A valid ASAR header was carved at APFS physical offset `23,875,584`; its JSON
  begins at `23,875,600`, is 247,336 bytes, and describes 4,565 leaf entries.
  Its package metadata says `name=RK`, `version=3.2.2`, and
  `main=background.js`. The metadata includes `node_modules/mi-hid` and
  x64/arm64 Darwin `node-napi-v4.node` prebuild entries. This supports an
  Electron app with a native HID addon. The APFS pathname of this ASAR and the
  pathname of the Mach-O bundle candidate were not recovered, so the mapping
  between those members and physical Mach-O candidates is strong but not
  directly proven.
- The carved ASAR byte range fingerprint is
  `a6b3783602040407932e95e9237cbabb774690bad515d51c21fd59c9f74279db`.
  It is not a pathname-level APFS file hash.

## Difference from the Windows package

The previously inspected Windows `app.asar` is 30,252,260 bytes with SHA-256
`38ebbf1416050d9ab36eee4910ec86130a0919b69334ec3751378f7f00ff2bdf`. The
carved macOS ASAR span is estimated at 30,217,234 bytes and has a different
fingerprint. The available count is 4,565 macOS leaf entries versus 4,569 in
the Windows archive. Therefore the packaged archives are not byte-identical.
An exact added/removed/changed member list was not generated, so this pass does
not characterize the full platform-specific asset or behavior delta.

## Reproducible evidence files

From the research repository root, run:

```powershell
python scripts/audit_rk_f99_macos_dmg.py ..\.research\rk-selector-software-2026-10-19\RK-3.2.2-universal.dmg --out-dir docs
```

The command completed successfully on 2026-10-20 using Python's standard
library only. It generated:

- `rk-f99-macos-dmg-block-map-2026-10-19.csv` — 551 UDIF block-map rows.
- `rk-f99-macos-mach-o-slices-2026-10-19.csv` — 34 architecture-slice rows,
  including physical APFS offsets, load commands, dylib links, and symbol
  counts.
- `rk-f99-macos-mach-o-undefined-symbols-2026-10-19.csv` — 9,297 undefined
  external-symbol records.

The ASAR observation above is a static carve recorded from this investigation;
the current script does not emit an ASAR-member manifest or an exact
Windows/macOS member diff.

## Coverage limits and open questions

- APFS B-trees, file extents, directory paths, app bundle metadata, loose
  assets, and exact file-to-Mach-O attribution remain unresolved. Seven
  block-aligned `APSB` signatures were observed, but were not validated as
  separate volumes.
- Mach-O load commands and undefined imports do not reveal all runtime API
  calls, dynamically resolved functions, IPC, configuration, device support,
  or behavior. No dynamic tracing or device interaction was performed.
- The scan covers validated universal Mach-O signatures and one ASAR carve; it
  is not an exhaustive extraction or reverse engineering of every app file.
- The exact UI assets, model catalog, application lifecycle features, and
  per-keyboard behavior are not established by this pass.
