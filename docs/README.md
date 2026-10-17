# Audit files

## Package and model catalog

- [Open-source RK software directory](../SOFTWARE-DIRECTORY.md)
- [Main software reverse-engineering report](reverse-engineering.md)
- [Installed file manifest and hashes](rk-installed-package-manifest.csv)
- [Installed manifest verifier](../scripts/verify_installed_manifest.py)
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
- [Follow-up mapping of indirect import calls and callbacks](rk-native-api-indirect-call-audit.md)
- [Dynamic API lookup candidates](rk-dynamic-api-targets.csv)
- [Dynamic API argument and resolver paths](rk-dynamic-api-resolution-audit.md)
- [Raw system-call byte matches](rk-native-syscall-byte-matches.csv)
- [API and system-call crosswalk](rk-system-api-crosswalk.md)
- [UI event, persistence, and device worker](rk-ui-event-worker-path-audit.md)
- [Settings Apply signaling, worker, and family dispatch](rk-settings-apply-worker-audit.md)
- [All recovered Apply signal callsites and masks](rk-apply-signal-callers.csv)
- [HID enumeration and device notifications](rk-device-enumeration-notification-audit.md)
- [Updater UART receive state machine](rk-updater-uart-state-machine.md)
- [Updater and firmware readback](rk-firmware-readback-audit.md)
- [Settings serializer and command paths](rk-setting-serializer-audit.md)
- [Static dialog resources and selected updater control handlers](rk-dialog-resource-audit.md)
- [Installer/uninstaller scripts](rk-installer-uninstaller-script-audit.md)
- [Public product names compared with this package snapshot](rk-public-model-coverage-gaps.md)
- [Dated storefront model-token inputs](rk-public-storefront-models.csv)
- [Generated storefront-to-profile name crosswalk](rk-storefront-model-crosswalk.csv)
- [MFC command-map candidates](rk-mfc-command-map-candidates.csv)
- [MFC message-map owner evidence](rk-mfc-map-owner-evidence.csv)
- [Recovered MFC message-map audit](rk-mfc-message-map-audit.md)
- [All entries from the 26 recovered MFC arrays](rk-mfc-message-map-entries.csv)

## Package resources and localization

- [Dialog-resource control inventory](rk-dialog-resource-controls.csv)
- [Resource and localization audit](rk-resource-localization-audit.md)
- [Resource groups](rk-resource-group-inventory.csv)
- [Per-model resources](rk-model-resource-asset-inventory.csv)
- [Localization files](rk-localization-file-inventory.csv)
- [Localization key/value matrix](rk-localization-key-matrix.csv)
