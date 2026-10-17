# Data provenance

## Vendor package snapshot

The baseline was read from the RK Keyboard Software 4.06 installation at
`C:\Program Files (x86)\RK Keyboard Software`. The inventory contains 810
files totaling 78,070,176 bytes. `docs/rk-installed-package-manifest.csv`
records each relative path, size, and SHA-256; the PE reports record hashes
for the binaries they analyze.

On 2026-10-18, the official RK download page's Windows Keyboard Hub Driver
link was downloaded as `RK_Keyboard_Software_Setup_V4.6_20261015.exe` and
statically extracted with `innoextract 1.9`. The installer hash and source URL,
extraction procedure, extracted file counts, and exclusions are recorded in
[`docs/rk-v4.6-package-snapshot.md`](docs/rk-v4.6-package-snapshot.md). The
resulting 1,249-file manifest is metadata only. The installer and extracted
vendor payloads remain outside this repository.

## Included derived data

- `SOFTWARE-DIRECTORY.md` is a dated index of independent public RK projects.
  Its feature and model-support summaries are transcribed from each linked
  project's own documentation; no third-party project source code is copied
  into this directory.
- `docs/rk-official-driver-distribution-audit.md` is a dated transcription
  of the official public download routes and their published support caveats.
  The dynamic selector was sampled, not exhaustively exported.
- `models.json` is generated from `Cfg.ini`, `Dev/*/KB.ini`, and localized
  profile label files. It contains model/profile names, option strings,
  numeric mapping tuples, layout dimensions, and derived capability fields.
- `models-4.6.json` is independently generated from the 4.6 package's
  profile/configuration files. It is versioned separately from the 4.06
  baseline; the catalog delta report documents what fields can and cannot be
  compared across versions.
- `docs/rk-profile-driver-family-map-v4.6-projected.csv` applies the static
  4.06 `Fw` routing rule to the 4.6 profile data. This is a comparison aid,
  not evidence that the changed 4.6 binary retains that selector.
- `docs/*.csv` contains package file metadata, decoded profile values,
  extracted resource/localization structure, and static address inventories.
- `docs/*.md` contains original analysis notes about those files and native
  control flow. Every report separates evidence from inference and open
  questions.
- `scripts/` contains local analysis tools for rebuilding profile metadata,
  schema tables, and the dated model-name crosswalk. They read package/source
  files and write only derived outputs; they never open a device.
- `docs/rk-public-storefront-models.csv` is a dated transcription of model
  labels in RK's public storefront navigation, not a complete global or
  historical inventory. `scripts/compare_storefront_models.py` compares those
  labels with `models.json` profile names and produces a candidate-name
  crosswalk; string matches are not compatibility claims.
- The 2026-10-18 Windows PnP note in
  `docs/rk-firmware-readback-audit.md` records only device class, friendly
  name, and the presence/absence of a USB VID match. Unique Bluetooth child
  IDs are omitted. The observation used Plug-and-Play metadata only; no HID
  interface, report, or GATT data was opened or read, and PnP presence alone
  does not prove an active data path.

## Excluded material

This repository does not redistribute the vendor's executable or library
files, installer, `.upf` firmware package, image/font/audio files, or captured
keyboard reports. The package manifest identifies files by hash without
including their contents. No personal device serial, private key, or account
credential is part of the research dataset.

The MIT license covers this repository's original scripts and written
research. Extracted names and configuration values originate in RK's package
and remain associated with RK products; their inclusion does not imply RK
authorization, endorsement, or a grant of rights in RK trademarks or
third-party material. Consult applicable terms before redistributing vendor
assets or using this data commercially.
