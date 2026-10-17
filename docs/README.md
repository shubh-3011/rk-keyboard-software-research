# Audit files

## Package and model catalog

- [Main software reverse-engineering report](reverse-engineering.md)
- [Installed file manifest and hashes](rk-installed-package-manifest.csv)
- [Model profile and `KB.ini` audit](rk-profile-schema-audit.md)
- [Profile-to-driver-family map](rk-profile-driver-family-map.csv)
- [Every profile option field and value](rk-profile-schema-fields.csv)
- [Profile section shapes](rk-profile-section-shapes.csv)
- [Per-key comments and mapping rows](rk-profile-key-records.csv)
- [S98 profile variants](rk-s98-profile-variants.csv)

## Native APIs, device paths, and system calls

- [Native API imports](rk-native-api-imports.md)
- [IAT and thunk references](rk-native-api-xrefs.csv)
- [Imports without a recovered direct/thunk call](rk-native-api-callsite-gaps.csv)
- [Dynamic API lookup candidates](rk-dynamic-api-targets.csv)
- [Raw system-call byte matches](rk-native-syscall-byte-matches.csv)
- [API and system-call crosswalk](rk-system-api-crosswalk.md)
- [UI event, persistence, and device worker](rk-ui-event-worker-path-audit.md)
- [Updater and firmware readback](rk-firmware-readback-audit.md)
- [Static dialog resources and selected updater control handlers](rk-dialog-resource-audit.md)
- [Installer/uninstaller scripts](rk-installer-uninstaller-script-audit.md)
- [Public product names missing from this package snapshot](rk-public-model-coverage-gaps.md)
- [MFC command-map candidates](rk-mfc-command-map-candidates.csv)
- [MFC message-map owner evidence](rk-mfc-map-owner-evidence.csv)

## Package resources and localization

- [Dialog-resource control inventory](rk-dialog-resource-controls.csv)
- [Resource and localization audit](rk-resource-localization-audit.md)
- [Resource groups](rk-resource-group-inventory.csv)
- [Per-model resources](rk-model-resource-asset-inventory.csv)
- [Localization files](rk-localization-file-inventory.csv)
- [Localization key/value matrix](rk-localization-key-matrix.csv)
