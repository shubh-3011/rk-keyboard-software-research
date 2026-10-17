# Contributing findings

Contributions that add package versions, profile coverage, source references,
or independently verified static call paths are welcome.

- Identify the RK utility version and hash the analyzed files. Keep separate
  snapshots separate; do not merge unlike profile versions into one assumed
  universal catalog.
- Link each conclusion to a package file, profile row, resource, PE address,
  or primary public source. Label whether it is proven statically, inferred,
  or unresolved.
- Preserve raw values where their semantics are not established. Do not turn
  a profile name, product page, import, or byte match into a confirmed device
  capability without supporting evidence.
- Do not submit RK executables, firmware images, private logs, device serials,
  credentials, or personal information.
- Do not test protocol hypotheses by sending reports or commands to a
  keyboard, running firmware tools, or entering bootloader mode. Keep this
  repository's protocol work static and reproducible.

For a new model family, include the exact supporting software package and
profile code, then record any uncertainty about receiver identity, firmware
revision, or shared identifiers in the same change.
