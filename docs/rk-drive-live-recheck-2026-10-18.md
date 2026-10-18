# RK Drive bundle live recheck — 2026-10-18

## Result

The source-free catalog extractor was run again at `2026-10-18T08:47:15Z`.
It fetched the current public entry and its recursively referenced JavaScript
chunks into memory, then wrote only derived catalog metadata, image URL
references, file sizes, and SHA-256 hashes under the local `.research/` area.
The downloaded vendor JavaScript and product image bytes were not retained in
the repository.

All seven URLs, byte sizes, entry/chunk roles, and SHA-256 values in the fresh
manifest matched [`rk-drive-js-manifest.csv`](rk-drive-js-manifest.csv). The
current entry bundle hash remains
`ec50777e49f34f24f4564c8624d5c39b52447980199fad43e24734826e6531ee`.
After excluding retrieval timestamps, the refreshed JSON catalog exactly
matched the checked-in snapshot.

The refresh parsed 177 general keyboard connection descriptors across 96
displayed labels, two separately constructed RK68 HE profiles, and 96 image
references. The standard S98-labelled rows include multiple USB product IDs
and a shared `0x258A:0x0150` receiver ID. Those IDs are evidence candidates;
the registry alone cannot identify which physical S98 variant is connected.

Reproduce the metadata refresh from the repository root with:

```powershell
python scripts/extract_rk_drive_catalog.py `
  --out-dir .research/rk-drive-refresh `
  --json .research/rk-drive-refresh/rk-drive-catalog.json
```

The extractor parses known registry structures and does not execute the app,
resolve every minified code path, open a WebHID chooser, or access a keyboard.
The hash match shows that the saved source snapshot is current at this check;
it does not establish hardware behavior or grant rights to redistribute RK's
JavaScript, photos, or branding. Product image URLs are references to RK's
host, not included artwork.

## Later full-bundle refresh

At `2026-10-18T11:19:18Z`, the extractor fetched all seven JavaScript URLs
again into memory and compared the source hashes. All seven file sizes and
SHA-256 values still match the checked-in manifest, including the 20,417,509-
byte entry bundle. It again produced 177 keyboard connection descriptors, 96
standard labels, two separate RK68 HE profiles, 96 image URL references, 20
legacy mouse descriptors, and two CB75-Mouse connection rows. No vendor
JavaScript or image bytes were retained.

The native rebuild now includes an RK Drive local-draft page for the registry's
declared key layers, OS tables, lighting effects, and per-effect controls. It
does not copy or execute the site's JavaScript and does not connect to a
keyboard. The other web workflows remain documented as feature inventory and
unresolved model/handler paths in the [web app audit](rk-drive-web-app-audit.md).
