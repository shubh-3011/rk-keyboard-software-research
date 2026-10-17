# Public RK model listing compared with the installed 4.06 profile catalog

The native/profile audit covers all model names present in one RK Keyboard
Software 4.06 installation. To make its model boundary visible, the
[`rk-storefront-model-crosswalk.csv`](rk-storefront-model-crosswalk.csv)
compares model tokens in RK's current storefront navigation with profile-name
tokens in that catalog. It does not infer protocol compatibility from a
product title or a similar model number.

The comparison is a dated discovery check, not a full worldwide or historical
catalog. The storefront page lists many SKUs and regional variants; this
crosswalk records the model entries in its keyboard navigation, not all 79
products or every color/layout SKU. RK's product pages can change, regional
names differ, and products may use another utility, a web driver, or QMK/VIA
instead of the audited Windows package.

## Findings

The dated navigation snapshot contains 43 distinct listed product variants
across 33 model tokens. The crosswalk records exact token matches against all
188 named profile rows and the resulting candidate profile names. A token
match is only a string match; it is not proof that the 4.06 device-selection
logic accepts the model, that the product shares a hardware revision, or that
its controls use the same protocol. Variants with no exact token match remain
unmapped to this package. Variants with matches remain candidates for separate
profile and hardware-identity analysis.

The current official downloads page makes clear that RK's software surface is
not one universal Windows suite: it has separate Web Driver and Hub Driver
sections, plus product-specific driver, firmware, and QMK selectors. The page
advertises the web driver for Chrome, Edge, and Opera on Windows, macOS, and
Linux, while explicitly excluding M75 HE, X87 HE, and RK68 HE from that
general web-driver entry. RK's separate [official web app](https://drive.rkgaming.com/)
describes wired and 2.4 GHz receiver connection modes. These are statements
about the current vendor pages, not compatibility evidence for the archived
4.06 Windows binary or for every revision carrying a matching product name.

The public page's static content does not expose a complete machine-readable
model-to-driver matrix. This report therefore does not assign the Web, Hub,
legacy client, firmware, or QMK routes to every model. Check the exact product
version, connection mode, lighting variant, operating system, and driver type
on the vendor's [official downloads page](https://en.rkgaming.com/download/)
before drawing a compatibility conclusion.

## Sources and method

Checked on 2026-10-18 against RK's [official storefront keyboard navigation](https://rkgamingstore.com/collections/all),
[official driver downloads page](https://en.rkgaming.com/download/), and
[official web app](https://drive.rkgaming.com/). The downloads page presents
distinct Web and Hub driver categories and a product-specific selection flow;
the web app describes wired and 2.4 GHz receiver modes. The storefront
navigation includes standard mechanical, Hall Effect, QMK/VIA, display/knob,
and regional-layout product entries. The crosswalk input preserves the exact
model token and linked navigation label. The generator uses a
case-insensitive alphanumeric token boundary over the `name` and `family`
fields of the 188 entries in [`models.json`](../models.json), then records
every candidate profile's code and name. It does not strip punctuation or
compare USB IDs here. This is not a device-descriptor match, protocol match,
or test on a physical keyboard.

## Extending this map

Add product names from other official/regional catalogs as dated source rows,
then compare them with separately hashed software snapshots. Record multiple
candidate profiles when names are ambiguous. Do not assign a product page to a
profile solely because the model numbers look similar. To extend this beyond
the storefront snapshot, collect regional and historical RK product names,
official driver downloads and package hashes, then inspect each software
version's own model catalog and selection path.
