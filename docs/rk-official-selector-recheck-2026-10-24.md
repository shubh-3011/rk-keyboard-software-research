# RK public keyboard selector recheck — 2026-10-24

## Scope

This is a read-only recheck of the official English keyboard download selector
at `https://en.rkgaming.com/download/` and its public JSON metadata endpoints.
The existing acquisition script requested the selector page and Drive,
firmware, and QMK catalog metadata. It recorded listed file URLs as strings;
it did not request those URLs, download packages, contact a keyboard, or run
vendor software.

The dated result is in
[`rk-official-download-selector-catalog-2026-10-24.csv`](rk-official-download-selector-catalog-2026-10-24.csv).
Its capture timestamp is `2026-10-24T19:38:20+00:00`, file size is 147,809
bytes, and SHA-256 is
`fb0d508e36b8c227804955d42b17d59c3068c167ca1cca26c1f6afbb5200b37b`.
The prior snapshot is
[`rk-official-download-selector-catalog-2026-10-19.csv`](rk-official-download-selector-catalog-2026-10-19.csv),
captured at `2026-10-19T16:22:37+00:00`, with SHA-256
`ad696ecfc8be20948e0eb75a89576c54ef8ec921601ad7f07c0fb5212c6a4d44`.

## Reconciliation result

Both snapshots contain the same 456 normalized rows:

| Selector | Model choices | Distinct result records | CSV rows |
| --- | ---: | ---: | ---: |
| Drive | 11 | 11 | 19 |
| Firmware | 51 | 118 | 354 |
| QMK | 7 | 83 | 83 |

The 456 rows are the same in order and every field matches except
`observed_at_utc`. Thus the model choices, product and record identifiers,
labels, options, PIDs, descriptions, listed target URLs, and source metadata
URLs did not change between these two captures. The collector also reconciles
the per-model result count against each aggregate endpoint count before
writing the table.

## Evidence limits

- **Proven from these captures:** the three official keyboard selector APIs
  returned the row counts above on the two stated capture times, and all
  non-timestamp CSV fields were byte-for-byte equal after parsing.
- **Inferred:** the current public English selector had no catalog-data
  changes in the five-day interval represented by the captures.
- **Unresolved:** historical or retired products, other language or regional
  catalogs, undocumented package mirrors, physical model revisions, and
  whether any listed package actually supports a particular physical unit.
  A selector record or listed URL is not proof of compatibility or a complete
  supported-SKU universe.

The broader selector field meanings and October 19 catalog inventory remain
documented in the
[selector API audit](rk-official-selector-api-catalog-audit-2026-10-19.md).
Reproduce a new dated snapshot with
[`capture_rk_public_selector_catalog.py`](../scripts/capture_rk_public_selector_catalog.py);
the script refuses to overwrite an existing date-named snapshot by default.
