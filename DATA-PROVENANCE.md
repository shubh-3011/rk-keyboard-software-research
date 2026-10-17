# Data provenance

## Vendor package snapshot

The baseline was read from the RK Keyboard Software 4.06 installation at
`C:\Program Files (x86)\RK Keyboard Software`. The inventory contains 810
files totaling 78,070,176 bytes. `docs/rk-installed-package-manifest.csv`
records each relative path, size, and SHA-256; the PE reports record hashes
for the binaries they analyze.

## Included derived data

- `models.json` is generated from `Cfg.ini`, `Dev/*/KB.ini`, and localized
  profile label files. It contains model/profile names, option strings,
  numeric mapping tuples, layout dimensions, and derived capability fields.
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
