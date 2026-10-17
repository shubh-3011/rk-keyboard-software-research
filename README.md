# Royal Kludge Keyboard Software Research

An independent, static research archive for Royal Kludge (RK) keyboard
software, profiles, resources, and model-specific native code. The goal is to
make the evidence and its limits easy to inspect so other researchers can
identify models, compare software versions, and continue the analysis.

This is not RK software, is not affiliated with RK, and is not a keyboard
configuration utility. It contains no RK executable, DLL, installer,
firmware image, or copied artwork.

## Coverage

The baseline is one installed **RK Keyboard Software 4.06** package. Its
catalog contains **188 named profiles** and **189 `KB.ini` files**, including
the unregistered profile `01C7`. The package manifest records 810 installed
files by relative path, size, and SHA-256. The machine-readable
[`models.json`](models.json) preserves all decoded named-profile options,
base/Fn mappings, layout metadata, and the unregistered profile. The static
[`profile-to-driver map`](docs/rk-profile-driver-family-map.csv) covers the
installed named catalog, not every physical variant sold under each family.

This is complete coverage of the model entries found in that one software
snapshot, not a claim to cover every keyboard RK has ever released. Regional
catalogs, other utility versions, later models, and models absent from this
package may differ. Current product listings are useful discovery sources,
but a product page does not establish compatibility with the 4.06 profiles or
native protocol. See [coverage status](COVERAGE.md) before treating a mapping
as confirmed.

## Start here

- [Main static reverse-engineering report](docs/reverse-engineering.md)
- [Model profile and `KB.ini` schema audit](docs/rk-profile-schema-audit.md)
- [Profile-to-driver-family map](docs/rk-profile-driver-family-map.csv)
- [Machine-readable 188-profile catalog](models.json)
- [Installed package manifest](docs/rk-installed-package-manifest.csv)
- [Resource and localization audit](docs/rk-resource-localization-audit.md)
- [Native API import, callsite, and syscall crosswalk](docs/rk-system-api-crosswalk.md)
- [Updater and firmware readback audit](docs/rk-firmware-readback-audit.md)
- [UI event and device worker path audit](docs/rk-ui-event-worker-path-audit.md)
- [Installer and uninstaller script audit](docs/rk-installer-uninstaller-script-audit.md)
- [Public product names not found in the 4.06 profile catalog](docs/rk-public-model-coverage-gaps.md)
- [All audit documents and evidence tables](docs/)

The reports distinguish statically proven observations, inferences, and
unresolved questions. Import presence, strings, byte patterns, profile labels,
and callsite candidates are not presented as proof of runtime behavior.

## Rebuild the profile catalog

The two Python scripts read an installed RK package and write derived profile
metadata and CSV ledgers. They do not launch RK software or communicate with a
keyboard. From the repository root on Windows with Python 3.10 or newer:

```powershell
python scripts/extract_rk_catalog.py `
  --rk-root "C:\Program Files (x86)\RK Keyboard Software" `
  --output models.json `
  --driver-map-output docs/rk-profile-driver-family-map.csv

python scripts/audit_profile_schema.py `
  --rk-root "C:\Program Files (x86)\RK Keyboard Software" `
  --repo .
```

For reproducibility, compare the package version and file hashes in
[`rk-installed-package-manifest.csv`](docs/rk-installed-package-manifest.csv)
with the source package before interpreting address-level findings. The
native reports are tied to specific PE hashes and version-specific addresses.

## Research boundary

All findings are static. The RK application and updater were not launched;
the keyboard HID interface was not opened; and no keyboard report, command,
firmware write, or bootloader operation was performed. Static traces do
identify code paths that can write to a keyboard if the vendor application
runs them. They are documented as findings, not recommendations to replay.

## Sources

- [RK official website](https://en.rkgaming.com/)
- [RK official keyboard catalog](https://rkgamingstore.com/collections/rk-keyboard)
- [RK official web configurator](https://drive.rkgaming.com/)
- [KludgeKnight open-source RK configurator](https://github.com/vinc3m1/kludgeknight)

The catalog and product names are RK trademarks. Research notes and scripts
are licensed under MIT; see [LICENSE](LICENSE) and
[data provenance](DATA-PROVENANCE.md).
