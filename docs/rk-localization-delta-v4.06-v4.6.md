# RK localization XML delta: installed 4.06 vs V4.6-labeled package

## Scope and method

This offline comparison covers all seven `Text/<locale>/text.xml` files, all
generic `Dev/<locale>/led.xml` files, profile-local `Dev/<code>/<locale>/led.xml`
files, and profile side-light files at
`Dev/<code>/SideLed/<locale>/led.xml`. Inputs were the installed package at
`C:\Program Files (x86)\RK Keyboard Software` and the extracted application
tree `.research/rk4_6_official_extract_20261015/app`. The package setup and
catalog record that this is a V4.6-labeled extract whose `Cfg.ini` still says
`Ver=0x406`; this report therefore does not assert a distinct software version.

The comparison script [compare_localization_delta.py](../scripts/compare_localization_delta.py)
parses XML leaf values by element path, trims only surrounding XML formatting
whitespace, and records per-file hashes and parse status on every CSV row. It
does not modify inputs. Substitute the paths to your local snapshots in this
reproducible command:

```powershell
python scripts/compare_localization_delta.py `
  --installed-root 'C:\Program Files (x86)\RK Keyboard Software' `
  --candidate-root 'C:\path\to\rk4_6_official_extract_20261015\app' `
  --output docs/rk-localization-delta-v4.06-v4.6.csv
```

The [row-level CSV](rk-localization-delta-v4.06-v4.6.csv) has **2,336 rows**
across 22 installed and 32 candidate XML resources: 2,105 unchanged keys,
69 added keys in files present on both sides, 8 changed values, 128 keys in
new files, and 26 keys whose old files are absent from the candidate. `added_file_key`
and `removed_file_key` mean file presence changed; they do not mean those label
strings are new/removed from the wider package.

## Proven string and resource changes

- Each of the seven UI text files has 247 parsed leaf keys in the installed
  package and 254 in the candidate. The seven added keys per locale are
  `tc_knob1`–`tc_knob4`, `tc_adv_str44`, `tc_screen22`, and `tc_screen23`.
  English labels describe four knob actions: volume, keyboard brightness,
  mouse wheel, and arrow keys. The two screen strings name a preset GIF and
  ask whether to download it to the keyboard. This proves the strings are
  shipped; it does not prove that a control is reachable or what device accepts
  an action.
- `tc_adv_str12` changes from `AUTORUN` to `Start on Boot` in English. `tc_msg1`
  changes its copyright year from 2025 to 2026 in all seven locales. These are
  the only eight changed string values. No UI text keys are removed.
- The English and Simplified Chinese generic LED tables each gain
  `tc_side_led1`–`tc_side_led10`. They label side-light effects. All existing
  generic LED keys are unchanged. Japanese, Korean, and Traditional Chinese
  generic LED tables are unchanged and contain no added side-light keys; neither
  package has generic Russian or Turkish `led.xml` files.
- Four profile LED label pairs are present only in the candidate:
  `023E`, `0251`, `028D`, and `02B2` (English and Simplified Chinese, 13 keys
  per file). These profile codes are also new relative to the installed
  profile corpus. The candidate no longer has the old `01C7` English and
  Simplified Chinese label files; `01C7` is the unregistered profile noted in
  the baseline inventory. Four common profile pairs (`014E`, `015B`, `020B`,
  `023D`) are unchanged. Added-file rows mostly reuse strings already present
  in the package; they are not 104 new distinct effect labels.
- The candidate adds four profile-specific side-light dictionaries for `02B4`
  (`en`, `Japanese`, `sc`, `tw`), each with five `tc_side_led*` labels and
  `tc_side_title`. Its `KB.ini` declares `ShowSideLED=1`, `DefSideLedIndex=1`,
  and `SideLedOpt1`–`SideLedOpt5`. A second profile, `0258`, also declares
  `ShowSideLED=1` but has no `SideLed/<locale>/led.xml` in this package. Whether
  it falls back to the generic labels or uses another UI path is unresolved.

## Strings that did not change

The 34 English text keys beginning `tc_macro` or `tc_mac_` and their locale
values are unchanged across the two trees. The existing `tc_adv_str43` string
(`Touchpad(Open browser manually on MAC)`) is also unchanged. Thus this XML
comparison finds no added macro or touchpad text. Profile fields such as
`KnobDef`, `KnobIndex`, `TouchWeb`, `ShowSideLED`, and `SideLedOpt*` are separate
configuration evidence; field names plus localized strings do not establish
their numeric semantics, control-to-profile mapping, command encoding, or
working hardware support. See the [profile catalog delta](rk-profile-catalog-v4.6-delta.md)
and [native binary delta audit](rk-v4.6-native-binary-delta-audit.md) for
independent profile and binary observations.

## Malformed XML handling and limits

Both installed and candidate `Text/Japanese/text.xml` are malformed on disk at
the same `tc_screen1` text: the closing token is `/tc_screen1>` instead of
`</tc_screen1>`. The candidate line number differs because added strings shift
later rows. The script records each raw parse error and hash, then applies that
single exact replacement in memory to compare the remaining keys; it writes
neither source file. The normalized trees each yield 254 keys. All other
compared XML files are well-formed.

This is a file-level localization comparison of one installed snapshot and one
installer extract. It does not analyze UI control reachability, translation
quality, resource fallback at runtime, or device behavior. No vendor program,
updater, or keyboard interface was opened, and no device data was sent or
changed.
