# Coverage and open work

This file prevents the package snapshot from being mistaken for a universal RK
model or runtime map.

## Covered in the installed 4.06 snapshot

- All 810 files in the examined installation are represented by path, byte
  size, and SHA-256 in `docs/rk-installed-package-manifest.csv`.
- All 188 named `DevName` profile rows and all 189 installed `KB.ini` files
  are inventoried. The extra `01C7` profile has no `DevName` record and stays
  explicitly unregistered.
- Profile options, key/Fn mapping tuples, section shapes, localization labels,
  resource groups, model-associated assets, and the static initial driver
  family selection are recorded in the JSON and linked CSV audits.
- All ordinary and delay imports from the five installed PE files, their
  scanned IAT/thunk references, dynamic API loader candidates, and raw
  system-call byte matches are inventoried.
- The documented native paths include HID enumeration, selected
  device-family protocol routines, updater transfer/readback, local
  profile/macro/screen persistence, installer helpers, and uninstaller
  scripts.

## Not established

- That the 4.06 package contains every RK keyboard model, regional variant,
  receiver, or firmware generation. Other package versions must be added and
  compared separately.
- A unique one-to-one mapping between each profile code and every physical
  keyboard revision. Several families share identifiers or have conditional
  wireless/companion paths.
- Full call graphs for every native procedure, all indirect/COM/callback
  targets, or the runtime branch taken on a given PC.
- Every MFC control label and action, every profile tuple's meaning, all
  packet fields, or the complete UART/update state machine.
- A read-only command that can safely and completely copy firmware from an
  attached keyboard. The analyzed updater paths are not a demonstrated
  firmware backup method.

These gaps are intentional status labels, not claims that the missing work is
impossible. New package snapshots and independently supported findings should
extend the evidence without silently converting candidates into confirmed
hardware mappings.
