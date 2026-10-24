# S98 01BF HID discovery to All Start slots

## Scope and artifact

This static trace covers the English-UK S98 Tri-mode RGB package
`S98-Tri-RGB-01BF-L10-20260527170338_1467.exe`, SHA-256
`475e8d7b97adfbd861c3b7b16721ad598df04095b81228e381319b6be23129e6`; the
`.text` SHA-256 is
`3643f4d710a296b62598d3d8b71c7dd9dcab049ebbb540588b11757ccd5f03ed`. It is a
follow-up to the package/resource inventory and the All Start worker trace.
It verifies bytes and resource data only. The updater was not launched; no
live HID enumeration or keyboard communication was performed.

## Discovery sequence

The routine at `0x00408650` obtains the HID class GUID with
`HidD_GetHidGuid`, calls `SetupDiGetClassDevsW` with flags `0x12`, and walks
interfaces through `SetupDiEnumDeviceInterfaces`. For each interface it asks
`SetupDiGetDeviceInterfaceDetailW` for the path, opens that path with
`CreateFileW` (`GENERIC_READ | GENERIC_WRITE`, share mode 3,
`OPEN_EXISTING`, `FILE_FLAG_OVERLAPPED`), then calls `HidD_GetAttributes`,
`HidD_GetPreparsedData`, `HidP_GetCaps`, and `HidD_FreePreparsedData`.

The following gates are direct comparisons in this routine:

| Route | Direct gates | Result in static data flow |
| --- | --- | --- |
| Special paired-interface path | Vendor ID `0x0603`, Product ID `0x1020`, Usage Page `0xFF00`, FeatureReportByteLength `0x0802` | Candidate path is stored in the first 16-entry table rooted at dialog `+0x4A1C`. |
| Special paired-interface companion | Same `0x0603:0x1020` and Usage Page `0xFF00`, FeatureReportByteLength `6` | Candidate path is stored in the parallel table rooted at dialog `+0x6A9C`. |
| Configured-ID probe | Product ID equals the dialog value at `+0x8C24`; Vendor ID equals `+0x8C28`; Usage Page `0xFF00` | Stores the descriptor VersionNumber at `+0x8C3E`, updates the Code Version display path, and attempts a `05 75` `HidD_SetFeature` report using the reported feature length. This branch does not itself put the path in the All Start path tables. |

The configured PID and VID fields are loaded at initialization from globals
`0x005BE400` and `0x005BE404`; their concrete runtime values and source are
not established here. They must not be equated with the package overlay pair
`0x258A:0x01BF`. In the configured-ID branch, the disassembly does not show a
report-length equality gate before its `05 75` attempt. The adjacent API
sequence does not visibly branch on the BOOL results from
`HidD_GetAttributes`, `HidD_GetPreparsedData`, or `HidP_GetCaps` before reading
the local descriptor fields.

The special path tables have 16 entries of `0x208` bytes each, with `0x2080`
bytes between their bases. Routine `0x00408E80` iterates nonempty primary
`+0x4A1C` paths, finds an available slot among 16, and copies the same-index
primary path into dialog row storage at `+0x091C + i*0x208`. It copies the
same-ordinal companion path from the second table into `+0x299C + i*0x208`.
This is ordinal pairing in software; the binary does not establish that the
two paths identify the same physical keyboard or collection.

## Qualification, row state, and worker handoff

For a populated primary path, the routine opens it again and obtains HID
capabilities. It requires a nonzero FeatureReportByteLength, then uses a
six-byte `05 52` `HidD_SetFeature` request followed by a `05 72`
`HidD_GetFeature` request. A true GetFeature result and response byte `+2 ==
0x61` lead to classification from response byte `+5`. The routine copies the
result into same-index dialog state bytes `+0x8E44 + 2*i` (qualification) and
`+0x8E45 + 2*i` (classification). These report calls are active operations;
the trace is not a suggestion to execute them.

The All Start handler at `0x004096A0` iterates `i=0..15`. Its explicit gates
are the global populated byte at `0x005BE460 + i` and the idle worker-state
dword at `0x005BE420 + 4*i`. It also requires dialog field `+0x90C4 == 0`
before calling setup `0x00409730` with `i`, then increments `+0x90C4`. Thus
one traversal can start at most one worker unless another path resets this
field; its meaning and reset lifecycle are unresolved. The handler's slot
gates do not test the response-success byte at dialog `+0x8E44 + 2*i`. The
populated byte is set when the path is assigned, before
the feature-response probe. Thus a failed probe is not statically excluded
from All Start by the `+0x8E44` result alone; later setup and worker behavior
remain conditional. Setup copies the two same-index row paths into the worker
record at `0x005BE480 + 0x41C*i` and `0x005BE688 + 0x41C*i`, stores `i`, and
signals that record's event. This closes the static discovery → per-row
qualification display state and separate All Start worker-record handoff
conditionally.

The dialog resource independently contains 16 static controls with IDs
`0x3E8` through `0x3F7`, captions `1` through `16`. The code formats row
ordinal `i+1` into per-row display storage and shares the same `i` across
qualification, All Start, and worker setup. A direct binding from each
resource control ID to that row storage was not demonstrated; the exact
HWND/control mapping remains unresolved.

## Proven, inferred, unresolved

- **Proven statically:** API imports and callsites; exact hard-coded special
  pair and usage/report-length comparisons; configured pair fields and Usage
  Page comparison; path-table and row strides; same-index path copying;
  response qualification; All Start's per-index populated/idle gates and
  dialog-level `+0x90C4` gate; and worker-record copy and event signal.
- **Inferred:** the 16 numbered static resource controls are intended to
  visually correspond to slot indices 0–15. The matching counts and ordinal
  flow support this, but direct control-ID binding is not proven.
- **Unresolved:** live device identity and enumeration order; whether each
  opened candidate succeeds; whether companion paths actually belong to the
  same device; source/value of configured VID/PID; exact response-byte
  meaning; runtime slot acceptance; and whether the keyboard accepts or acts
  on any report.

The special `0x0603:0x1020` pair used to populate All Start path tables is not
the S98 package header pair `0x258A:0x01BF`. The separate configured-ID branch
does not itself copy its candidate path into those All Start path tables in
this routine. Static evidence here does not establish that the connected S98
keyboard is an All Start worker target, its firmware revision, or whether its
firmware can be copied. No HID interface was accessed and no firmware was
changed.

## Reproduction

```powershell
python scripts/audit_s98_01bf_hid_discovery_slots.py `
  --binary ../.research/rk-selector-software-2026-10-19/S98-firmware-packages/S98-Tri-RGB-01BF-L10-20260527170338_1467.exe `
  --out docs/rk-s98-01bf-hid-discovery-to-all-start-slots-evidence-2026-10-24.csv
```

The verifier checks whole-file and `.text` hashes, 75 instruction byte facts,
seven direct call edges, 13 IAT mappings, the All Start message-map row, and
the 16 numbered controls in `RT_DIALOG #102` language 1028. See the [evidence
ledger](rk-s98-01bf-hid-discovery-to-all-start-slots-evidence-2026-10-24.csv)
and [verifier](../scripts/audit_s98_01bf_hid_discovery_slots.py). The ledger
records static observations, not runtime execution or physical-device
acceptance.
