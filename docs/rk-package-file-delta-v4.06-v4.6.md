# RK 4.06 installed tree versus the 4.6-labeled package payload

## Comparison basis

This comparison joins the installed 4.06 file manifest with the application
payload from the official package labeled 4.6. The baseline is the
810-file installed-tree manifest. In the extracted package, `app/` is mapped
to the installation root and the separate `fonts/` directory is mapped to
the installed `font/` path. The extracted `localappdata/RKKB/lang.ini` is
excluded from this application-payload comparison because it is outside the
installed program tree; it remains included in the full
[4.6 extraction manifest](rk-4.6-package-manifest.csv).

Comparison uses case-insensitive relative paths plus exact size and
SHA-256. It says whether a path and its contents match; it does not infer
what an installer would overwrite, preserve, or delete. An `absent` row means
the path exists in the installed 4.06 snapshot but not the extracted 4.6
application payload, not that running an installer would remove it.

## Results

The baseline has 810 files and the normalized candidate payload has 1,248.
Their union contains 1,265 relative paths:

| Status | Paths | Meaning |
| --- | ---: | --- |
| Identical | 743 | Present in both with matching size and SHA-256. |
| Changed | 50 | Same relative path, different size or SHA-256. |
| Added | 455 | Present only in the 4.6-labeled package payload. |
| Missing from candidate | 17 | Present in installed 4.06, absent from the extracted 4.6 payload. |

The 50 changed paths include `Cfg.ini`, 15 `.ini` files, the main
`DeviceDriver.exe`, seven localized `Text/*/text.xml` files, LED dictionaries,
two GIFs, 12 PNGs, and effect-text assets. Among the named binaries,
`DeviceDriver.exe` changed, `Dev/01AF/Update.exe` is identical, and the
installed Inno-generated `unins000.exe` is absent from the extracted app
payload. The updater and `.upf` hashes are compared in the
[package snapshot](rk-v4.6-package-snapshot.md).

The 17 absent paths include the old unregistered `Dev/01C7` profile and its
two localized LED files, several old per-model animation/effect text files,
one font that is not in the extracted `fonts/` directory, and two
Inno-generated uninstaller files. These path differences alone do not show
whether a model was discontinued or whether an installer carries an
equivalent asset elsewhere.

## Reproduction

The comparison script reads only the two manifests; it does not open the
vendor package. Recreate the CSV from this repository root with:

```powershell
python scripts/compare_package_manifests.py `
  docs/rk-installed-package-manifest.csv `
  docs/rk-4.6-package-manifest.csv `
  docs/rk-file-manifest-delta-v4.06-v4.6.csv `
  --candidate-map-prefix app= `
  --candidate-map-prefix fonts=font
```

The row-level results, including both hashes and sizes for every changed,
added, absent, or identical path, are in
[`rk-file-manifest-delta-v4.06-v4.6.csv`](rk-file-manifest-delta-v4.06-v4.6.csv).
The CSV uses the status value `removed` for the 17 paths missing from the
candidate payload; it is a comparison label, not evidence of an installer
deletion.
Profile-specific changes are explained in the
[catalog delta](rk-profile-catalog-v4.6-delta.md); the distinct main-driver
binary is analyzed in the [native binary delta](rk-v4.6-native-binary-delta-audit.md).
