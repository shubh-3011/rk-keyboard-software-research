# RK 4.06 LED labels to profile `LedOpt` tuple crosswalk

## Scope and inputs

This report joins LED label candidates from all five installed dictionaries
(`en`, `Japanese`, `Korean`, `sc`, `tw`) to the matching profile `LedOptN`
values for the installed RK 4.06 package. It follows
the slot/ordinal correspondence in the [tree-control row-token audit](rk-406-led-0594-tree-control-row-token-followup.md)
and joins the label candidates to the [profile catalog](../models.json). It
does not assign firmware meanings to tuple cells and does not claim that a
candidate is visible or accepted by a connected keyboard.

The inputs are pinned by SHA-256:

| Input | SHA-256 |
| --- | --- |
| Installed `DeviceDriver.exe` associated with the profile catalog | `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6` |
| [`models.json`](../models.json) | `d7b877dbeef81432ec9914c19bc86af0583497b095f18558575e983e31b8fcf7` |
| [English label-candidate input](rk-led-control-candidates-4.06-en.csv) | `88af1cc45462b00bcef0905a325783dba673ffe161d312ec5306c0c22133ccd2` |
| [Japanese label-candidate input](rk-led-control-candidates-4.06-Japanese.csv) | `43b4488c3983db7f9d6d4aa53261cfecef7822c3eb75509b7c5d8cdd928133da` |
| [Korean label-candidate input](rk-led-control-candidates-4.06-Korean.csv) | `79951ff0205e1641ef0426b745d0737e31bea86e60b3796199a201cb167aba09` |
| [Simplified Chinese (`sc`) input](rk-led-control-candidates-4.06-sc.csv) | `215534fd7aa9a9a8f559f8dd602382499192b27f33b155e59e899dc38ba87945` |
| [Traditional Chinese (`tw`) input](rk-led-control-candidates-4.06-tw.csv) | `d09ab5a3fbd30f365725e0a5919e8482ce314971408828b80e7c57a2ddc3d284` |

The generated [all-locales crosswalk CSV](rk-406-led-label-profile-tuple-crosswalk-4.06-all-locales.csv)
contains one row for each locale, 189 profile codes, and 24 candidate slots,
for 22,680 rows total. It retains the candidate's localized key/text and mask
status, then adds the corresponding `LedOptN` key, raw tuple, cell count, and
presence flag. The 189 profiles include 188 registered catalog entries and
unregistered profile `01C7`. The existing [English-only crosswalk](rk-406-led-label-profile-tuple-crosswalk-4.06-en.csv)
remains available as a smaller example.

## Join rule and evidence

The LED label builder appends candidates in a fixed 24-slot order. For each
inserted tree row, the payload stores its zero-based candidate ordinal next to
the `HTREEITEM` token. The `0x0594` handler retrieves that ordinal for the
selected item. Separately, the profile reader formats `LedOpt%d`, iterates
`LedOpt1` through `LedOpt24`, and stores each parsed tuple at the matching
profile-table row. Therefore candidate slot `N` (one-based) joins to profile
key `LedOptN`; equivalently, the selected zero-based ordinal `i` indexes the
`LedOpt(i+1)` row. This is a static slot correspondence, not an effect-ID
interpretation.

The profile loader parses six comma-separated values for the installed
`LedOptN` assignments into a 0x3C-byte profile-table row. The existing
[profile-to-record audit](rk-lighting-profile-record-path-audit.md) establishes
these partial consumers in the same pinned 4.06 driver:

| Tuple cell | Profile-table row offset | Recovered consumer |
| ---: | ---: | --- |
| 1 | `+0x00`, duplicated at `+0x04` | No downstream use identified in the cited lighting trace. |
| 2 | `+0x08` | Copied to dialog-object field `+0x2C4C` by `FUN_00424B10`; related controls are shown or hidden. |
| 3 | `+0x0C` | Copied to dialog-object field `+0x2C54` by `FUN_00424B10`; related controls are shown or hidden. |
| 4 | `+0x10` | Copied to dialog-object field `+0x2C50`; `FUN_0045A430` also initializes runtime-record `+0x08` to `1` or `2` when the tuple value matches. |
| 5 | `+0x14` | Copied to dialog-object field `+0x2C5C` by `FUN_00424B10`; related controls are shown or hidden. |
| 6 | `+0x18` | Copied to dialog-object field `+0x2C60` by `FUN_00424B10`; related controls are shown or hidden. |

These are field-to-field paths, not recovered names for the visible controls.
The exact names and meanings of the six tuple cells, how UI edits write them,
and their firmware-side effects remain unresolved. The
[confidence-ranked tuple audit](rk-profile-tuple-semantics.md) also records
profile-localized comments for some options but does not establish a universal
cell-to-effect or cell-to-command mapping.

## Snapshot counts

| Locale | Candidate rows | Localized labels present | Unmasked candidates with empty label | `LedOptN` present |
| --- | ---: | ---: | ---: | ---: |
| English (`en`) | 4,536 | 3,765 | 771 | 3,765 |
| Japanese | 4,536 | 3,810 | 726 | 3,765 |
| Korean | 4,536 | 3,810 | 726 | 3,765 |
| Simplified Chinese (`sc`) | 4,536 | 3,765 | 771 | 3,765 |
| Traditional Chinese (`tw`) | 4,536 | 3,810 | 726 | 3,765 |
| **Total** | **22,680** | — | — | **18,825** |

Every present tuple in this snapshot has six cells: 18,825 locale/profile/slot
rows carry a `LedOptN` value and 3,855 lack that key. For each locale, 3,655
rows have both a label and tuple and pass the static mask filter; 57 rows have
both but are skipped by the mask. Label availability, profile-data
availability, and the `LedMask` skip rule are separate conditions; the
crosswalk keeps them in separate columns rather than treating one as proof of
another. The row-to-`LedOptN` join can be combined with the partial consumer
map above, but does not identify which visible label or widget corresponds to
any particular tuple field.

## Reproduction and limits

Run the standard-library generator from the repository root:

```powershell
python scripts/build_rk406_led_label_profile_tuple_crosswalk.py
```

The default command verifies the profile catalog and English source hashes.
To generate the five-locale output, first regenerate each candidate CSV from
the exact installed package:

```powershell
python scripts/audit_rk_led_control_candidates.py --locale en --out docs/rk-led-control-candidates-4.06-en.csv
python scripts/audit_rk_led_control_candidates.py --locale Japanese --out docs/rk-led-control-candidates-4.06-Japanese.csv
python scripts/audit_rk_led_control_candidates.py --locale Korean --out docs/rk-led-control-candidates-4.06-Korean.csv
python scripts/audit_rk_led_control_candidates.py --locale sc --out docs/rk-led-control-candidates-4.06-sc.csv
python scripts/audit_rk_led_control_candidates.py --locale tw --out docs/rk-led-control-candidates-4.06-tw.csv
python scripts/build_rk406_led_label_profile_tuple_crosswalk.py --candidates docs/rk-led-control-candidates-4.06-en.csv --candidates docs/rk-led-control-candidates-4.06-Japanese.csv --candidates docs/rk-led-control-candidates-4.06-Korean.csv --candidates docs/rk-led-control-candidates-4.06-sc.csv --candidates docs/rk-led-control-candidates-4.06-tw.csv --output docs/rk-406-led-label-profile-tuple-crosswalk-4.06-all-locales.csv
```

The tuple-crosswalk generator verifies the registered `models.json` and
candidate-CSV hashes before writing the crosswalk. The candidate-label files
were produced by [`audit_rk_led_control_candidates.py`](../scripts/audit_rk_led_control_candidates.py),
which checks the installed `DeviceDriver.exe` against the expected 4.06
SHA-256 before reading package inputs.
No RK program was run, no HID interface was opened, and no device was queried
or changed.

**Proven statically:** profile code and one-based LED slot join to the label
candidate and the same-numbered `LedOptN` profile value for this 4.06 catalog
snapshot. The generated candidate ordinal maps to that slot index.

**Unresolved:** the tuple-cell schema, exact control-to-cell mapping, per-model
feature semantics, output command field meaning, firmware interpretation,
runtime rendering, and physical device acceptance. These five dictionaries
are the installed snapshot's LED language folders; this does not establish
coverage of language packs from other releases or regional packages.
