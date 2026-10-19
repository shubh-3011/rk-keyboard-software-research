# Open-source Royal Kludge keyboard software directory

This page is a community starting point for finding open-source software for
Royal Kludge (RK) keyboards. Project capabilities and model support come from
each project's own documentation, checked on 2026-10-18. They are independent
projects; inclusion here is not an endorsement by their maintainers or RK.

## Projects

| Project | Platform and purpose | Documented scope |
| --- | --- | --- |
| [Keydeck RK Studio](https://github.com/shubh-3011/keydeck-rk-studio) | Web app and standalone Windows profile editor | Identifies authorized device metadata and edits local model, keymap, lighting, screen, and macro profiles. It does not open HID reports or write to a keyboard. |
| [Rangoli](https://github.com/rnayabed/rangoli) | Cross-platform desktop configurator | Documents custom keymaps, built-in lighting modes, per-key RGB, and per-key LED settings. Its own support list describes VID `0x258A` devices and warns that same-name models can differ. |
| [Royal Kludge Configurator](https://github.com/Ripwords/royal-kludge-configurator) | Tauri desktop configurator | Documents key mapping, lighting, local profiles, and keyboard detection. Its README says it reimplements protocol work from Rangoli and does not guarantee support for every RK model. |
| [KludgeKnight](https://github.com/vinc3m1/kludgeknight) | Browser configurator using WebHID | Documents key remapping and lighting controls. Its README says tested hardware is limited, current mappings cannot be read from keyboards, and edits write key mappings to hardware. |

## Other public references

[RKCU](https://github.com/oddlyspaced/rkcu) is a public RK61-focused USB
configuration implementation. GitHub did not identify a license for that
repository when this directory was checked, so it is listed as a research
reference rather than as an open-source project. Check its repository for
current licensing and support details before reusing its code.

## How this archive fits

The companion [RK software research archive](https://github.com/shubh-3011/rk-keyboard-software-research)
documents the installed RK Keyboard Software 4.06 package, an extracted
official 4.6 Hub Driver, and four current product-specific Windows packages.
It includes bounded model/profile catalogs, package hashes, resource and
localization inventories, static API and device-path audits, reproducible
scripts, and a source-built Windows research workbench. The workbench provides
local profile editing; it is not a hardware-compatible clone of the vendor
utility.

The first project, [Keydeck RK Studio](https://github.com/shubh-3011/keydeck-rk-studio),
is the user-facing web and Windows profile editor. This archive is the
research and documentation project. Neither project's executable is the
official RK application.

## Choosing a project

- For local profile editing without device writes, use Keydeck.
- For hardware configuration, compare each project's supported-device list
  and read its current usage instructions before selecting a tool.
- For evidence about the installed RK 4.06 Windows package, start at
  [`COVERAGE.md`](COVERAGE.md) and the [audit index](docs/README.md).

Support varies by model, hardware revision, connection mode, and firmware.
This directory does not make cross-project compatibility claims. Check the
linked source repositories for current releases, support lists, and cautions.
