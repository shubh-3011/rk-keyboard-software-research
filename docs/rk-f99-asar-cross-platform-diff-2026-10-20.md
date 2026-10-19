# RK F99 ASAR validation and platform comparison

This read-only comparison validates the ASAR carve in the RK 3.2.2 macOS DMG
and compares its member hashes with the previously extracted Windows
`app.asar`. It read member bytes in memory, wrote a CSV of names, metadata,
and hashes, and kept the reconstructed APFS partition in a temporary file that
was removed on exit. It did not extract member files or execute vendor code.
The ASAR's APFS pathname remains unknown because this pass does not parse APFS
B-trees or file extents.

## Validated macOS ASAR span

At APFS partition physical offset `23,875,584`, the first 16 bytes are
`0400000030c603002cc6030028c60300`. Interpreted as four little-endian words,
they are `4`, `247344`, `247340`, and `247336`, the nested Pickle/string/JSON
lengths. These lengths validate the JSON starting at `23,875,600` with length
`247,336`; the payload starts at `24,122,936`.

The ASAR tree has 4,565 leaf entries. Its 4,547 nonempty in-archive file ranges
claim exactly 29,969,882 payload bytes: they cover offsets `0` through
`29,969,882` with no gaps or overlaps. Every member extent is within the
candidate physical range. The resulting span is 30,217,234 bytes, ending at
APFS physical offset `54,092,818`, with SHA-256
`a6b3783602040407932e95e9237cbabb774690bad515d51c21fd59c9f74279db`.
Package metadata identifies `RK` version `3.2.2`, with `background.js` as main.

The Windows `app.asar` header parses under the same format. Its JSON is 242,968
bytes; its payload is 30,009,276 bytes with no gaps or overlaps. The archive is
30,252,260 bytes with SHA-256
`38ebbf1416050d9ab36eee4910ec86130a0919b69334ec3751378f7f00ff2bdf`. It also
identifies `RK` version `3.2.2` and `background.js` as main.

## Member comparison

SHA-256 was computed from the exact byte range of every in-archive file member
in each archive. For changed members, the comparison also replaced every CRLF
sequence with LF in both in-memory byte strings and checked for equality; the
original bytes and hashes were left untouched.

- 4,362 members have identical raw SHA-256 hashes.
- 186 members have different raw hashes. For 185, replacing CRLF with LF makes
  the byte strings equal. The only remaining difference is `background.js`:
  macOS is 2,835,847 bytes (SHA-256
  `7d24ec44fde96911790ed9578bdec76943868a30b5b2a0b63dbe23bad6c5ab30`);
  Windows is 2,835,093 bytes (SHA-256
  `8db60b45ce93fc20f68950ebb97db0640d6384c3808b06e43c332d8ef4183277`).
- There are 17 members marked unpacked on both sides. They are outside each
  ASAR payload, so the CSV compares their metadata only, not their contents.
- There are no macOS-only members. Four Windows-only members are clipboard
  fallback executables:
  `node_modules/clipboardy/fallbacks/windows/clipboard_i686.exe`,
  `node_modules/clipboardy/fallbacks/windows/clipboard_x86_64.exe`,
  `node_modules/node-clipboardy/fallbacks/windows/clipboard_i686.exe`, and
  `node_modules/node-clipboardy/fallbacks/windows/clipboard_x86_64.exe`.

The 185 normalized matches are evidence of CRLF/LF-only byte differences under
the stated normalization; this does not explain the remaining `background.js`
delta or establish behavior. No embedded ASAR per-file integrity hashes were
present, so the comparison uses hashes computed directly from each member's
payload bytes.

## Reproduction and output

From the research repository root:

```powershell
python scripts/compare_rk_f99_asar_members.py ..\.research\rk-selector-software-2026-10-19\RK-3.2.2-universal.dmg ..\.research\F99_3.2.2_static\selected\resources\app.asar --csv-out docs\rk-f99-macos-vs-windows-asar-members-2026-10-20.csv
```

The script uses Python's standard library and the existing DMG block-map helper.
It reconstructs APFS to a temporary file, validates the ASAR header and complete
member payload span, hashes members in memory, and deletes the temporary file
on exit. The CSV includes the union of member paths, comparison result, sizes,
payload offsets, computed SHA-256 values, and the CRLF-to-LF equality result.

This confirms a well-formed ASAR candidate and its physical byte span, but does
not prove the ASAR's APFS pathname, the physical pathname of any Mach-O member,
or runtime behavior. No app assets or vendor source files were copied into the
repository.
