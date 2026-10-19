# RK 4.6 MFC message-map inventory

## Scope and input

This report inventories statically recoverable Microsoft Foundation Classes
(MFC) message-map accessor/table candidates in the extracted RK 4.6
`DeviceDriver.exe`. The input is pinned by SHA-256:

`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`

The scan found **145 structurally validated accessor/table candidates** and
**1,214 decoded message-entry rows**. **144 candidates have associated MSVC
RTTI/vtable reference evidence**; one has no owner evidence under the scan's
rules. These are bounded static scan results, not a count of every map in the
program.

## Method

[`audit_rk46_mfc_message_maps.py`](../scripts/audit_rk46_mfc_message_maps.py)
scans executable PE section bytes for the x86 byte pattern
`mov eax, imm32; ret`. A candidate is retained only if the immediate points to
a non-executable descriptor, the descriptor's base-map getter is executable,
and its entry array consists of six-DWORD rows ending in an all-zero sentinel,
with each row's handler address inside an executable section. This validates
the observed structure and bounds but does not execute the binary or prove
that MFC dispatch reaches a row at runtime.

For RTTI association, the script searches non-executable sections for
references to the candidate accessor. It walks backward to a valid MSVC
Complete Object Locator, validates the type descriptor name, and requires the
intervening vtable entries to point into executable sections. The CSV field
`rtti_vtable_types` therefore means types whose validated vtable references
contain the accessor; it is evidence of an association, not a guarantee of a
unique direct owner. Shared and inherited MFC maps can be referenced by
multiple types.

The scan deliberately uses a byte signature rather than a full instruction
decoder and function-boundary analysis. An accessor-like byte sequence inside
another instruction may be considered, although the descriptor, array,
sentinel, base-getter, and handler checks make the candidate set narrower.
Other accessor encodings, maps returned through other code paths, dynamic
message routing, and runtime-created dispatch are outside this inventory.

## Application-specific anchors

The early application-owned maps provide useful navigation anchors for later
handler analysis:

| RTTI-associated type | Accessor | Entries | Count |
|---|---:|---:|---:|
| `CCfgDlg` | `0x00401F60` | `0x005CFDC0` | 6 |
| `CKBColorDlg` | `0x00417980` | `0x005D4910` | 8 |
| `CKeyDlg` | `0x0041AE00` | `0x005D4B80` | 11 |
| `CLedDlg` | `0x004234D0` | `0x005D54C0` | 15 |
| `CMacroDlg` | `0x00428780` | `0x005D59E0` | 13 |
| `CMenuDlg` | `0x004358D0` | `0x005DA510` | 5 |
| `CMenuSrDlg` | `0x004362E0` | `0x005DA738` | 3 |
| `COemDrvDlg` | `0x00448870` | `0x005DD0E8` | 15 |
| `CSideLedDlg` | `0x0045D4C0` | `0x005E1030` | 10 |
| `CScreenDlg` | `0x004720C0` | `0x005E36B8` | 8 |

The complete flattened ledger includes MFC framework controls and shared
framework maps as well as app dialogs, views, and controls. Message identifiers
are preserved as numeric values; only a small common Win32 message set is
given symbolic names by the script. Command IDs, signatures, handlers, and
other message numbers still require per-handler interpretation.

The sole accessor without RTTI/vtable association is at `0x004EDB01`, with
descriptor `0x005B4D94` and 11 validated entries. Its owner remains unresolved.

## Files

- [Map summary CSV](rk-v4.6-mfc-message-map-summary.csv): one row per candidate,
  with addresses, entry count, and RTTI/vtable evidence.
- [Flattened entry CSV](rk-v4.6-mfc-message-map-entries.csv): one row per
  decoded entry, including the numeric message/code/ID range/signature and
  handler address.
- [Scanner](../scripts/audit_rk46_mfc_message_maps.py): standard-library-only,
  hash-pinned parser that regenerates both CSVs.

## Limits and next work

This inventory expands 4.6 UI coverage, but it does not recover the full
driver call graph, disassemble every handler, prove runtime UI behavior, or
establish which model/revision displays each page. The next useful step is to
resolve app-specific command/message IDs and trace each handler to state,
storage, worker, serializer, and imported API paths. In parallel, the overall
research still needs an authoritative package/version inventory and deeper
coverage of the installer, updater, feature families, and public web tools;
see the [full-suite gap matrix](reverse-engineering-gap-matrix-2026-10-19.md).

No keyboard HID interface, report, firmware updater, or bootloader was used
for this static inventory.
