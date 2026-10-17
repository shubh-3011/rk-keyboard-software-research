# Public product names compared with the installed 4.06 profile catalog

The native/profile audit covers all model names present in one RK Keyboard
Software 4.06 installation. To make the model boundary visible, this note
compares exact model-name tokens in that catalog with a few product families
on RK's public storefront. It does not infer protocol compatibility from a
product title or a similar model number.

The comparison is a dated discovery check, not a full world-wide or historical
catalog. RK's product pages can change, regional names differ, and items may
use another utility or QMK/VIA instead of the audited Windows package.

## Example exact-name gaps

| Public product family | Example official title | Exact family token in 4.06 profile names? | Finding |
| --- | --- | --- | --- |
| C98 | C98 96% Hall Effect Magnetic Switch Keyboard | No | No exact C98 profile name was found; package support is unknown. |
| C87 | C87 80% TKL Magnetic Hall Effect Keyboard | No | No exact C87 profile name was found; package support is unknown. |
| C96 | C96 96% Hall Effect Magnetic Switch Keyboard | No | No exact C96 profile name was found; package support is unknown. |
| C68 | C68 65% Hall Effect Magnetic Switch Keyboard | No | No exact C68 profile name was found; package support is unknown. |
| R99 | R99 RGB Wireless Mechanical Keyboard | No | No exact R99 profile name was found; package support is unknown. |
| S104 | S104 Wireless Full Size Mechanical Keyboard | No | No exact S104 profile name was found; package support is unknown. |
| X104 | X104 Wired Full Size Mechanical Keyboard | No | No exact X104 profile name was found; package support is unknown. |

“No exact family token” is a string/catalog result only. It does not prove the
keyboard cannot use a related driver, a later utility, a web configurator, or
another firmware family. These entries remain unmatched until a matching
software package and reliable device identity evidence are analyzed.

## Sources and method

Checked on 2026-10-18 against RK's [keyboard product collection](https://rkgamingstore.com/collections/rk-keyboard)
and [gaming keyboard collection](https://rkgamingstore.com/collections/gaming-keyboards).
The current product pages show the titles above and list Hall Effect models
alongside ordinary mechanical and QMK/VIA products. For the installed-side
comparison, searched the 188 names in the `models` array of
[`models.json`](../models.json) after case-insensitive punctuation removal.
This is not an HID descriptor match, protocol match, or test on a physical
keyboard.

## Extending this map

Add product names from other official/regional catalogs as dated source rows,
then compare them with separately hashed software snapshots. Record multiple
candidate profiles when names are ambiguous. Do not assign a product page to a
profile solely because the model numbers look similar.
