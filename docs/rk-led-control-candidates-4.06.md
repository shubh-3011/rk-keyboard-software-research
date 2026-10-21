# RK 4.06 LED label and control candidates

This static crosswalk combines the installed 4.06 profile INIs with localized
LED dictionaries and a hash-pinned trace of `DeviceDriver.exe`. It generates
one row for each of 24 indexed label candidates per profile. The generated
[English crosswalk](rk-led-control-candidates-4.06-en.csv) covers 189
profiles and can be reproduced with
[`scripts/audit_rk_led_control_candidates.py`](../scripts/audit_rk_led_control_candidates.py).

## Static rules recovered

- The driver loads profile `Fw` into `0x00611760`, `RGBKb` into
  `0x006117C4`, `ShowSleepTime` into `0x0061178C`, and `LedMask` into
  `0x00611798`.
- The label family builder tests `Fw` first. A nonzero value selects
  `tc_eft1`–`tc_eft24`. When `Fw` is zero, nonzero `RGBKb` selects
  `tc_led_mode1`–`tc_led_mode24`; zero selects `tc_led1`–`tc_led24`.
  `ShowSleepTime` does not participate in this family selection.
- The builder tries `Dev\\<profile>\\<locale>\\led.xml`, then falls back to
  `Dev\\<locale>\\led.xml`. The generic dictionaries do not contain every
  probed suffix.
- The control builder iterates the 24 candidates and tests `1 << slot` against
  `LedMask`. A set bit skips the candidate-control construction path. The
  profile loader gives an omitted `LedMask` a value of zero.

## Limits of this result

Passing this branch only shows that the static code reaches a control factory
path with a localized string pointer. It does not prove that a visible widget
was created, that an empty label renders, how the control is positioned, which
message handler receives its events, or which serializer/writer a selection
reaches. Label suffixes are not established as firmware mode IDs or `LedOptN`
slots. The CSV is evidence for profile-driven candidates, not proof that a
keyboard exposes every candidate.

The script refuses to apply these 4.06 rules to a different `DeviceDriver.exe`
hash unless an alternate expected hash is supplied. It reads installed files
only; it does not launch RK software or access a keyboard.
