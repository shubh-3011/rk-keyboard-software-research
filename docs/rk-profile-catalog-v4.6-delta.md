# RK Keyboard profile catalog delta: V4.6-labeled package

## Scope and version identity

This is an offline comparison of the extracted package named RK_Keyboard_Software_Setup_V4.6_20261015.exe with the installed 4.06 corpus represented in this repository. The package filename says V4.6, but its extracted app/Cfg.ini says Ver=0x406; the installed baseline Cfg.ini also says Ver=0x406. Both application configs therefore identify as 4.06. This report calls the candidate the V4.6-labeled package to preserve that distinction; the evidence does not establish whether the filename is a new release label or a repackaging.

The candidate catalog was regenerated with scripts/extract_rk_catalog.py against the extracted app directory. It reads Cfg.ini, named DevName/PID rows, Dev/*/KB.ini, keyboard layout tuples, and profile-local LED labels. No RK application or updater was launched, no device interface was opened, and no vendor executable, firmware, or image was copied into the repository.

## Catalog and profile-code delta

| Measure | Installed 4.06 baseline | V4.6-labeled extracted package |
| --- | ---: | ---: |
| Configured DevName / PID rows | 188 / 188 | 265 / 265 |
| Dev/*/KB.ini files | 189 | 265 |
| Named profiles in catalog | 188 | 265 |
| Unregistered profile files | 1 (01C7) | 0 |
| Unique layout records | 90 | 140 |
| Direct-profile map rows | 188 | 265 |

Among registered codes, 188 are shared, 77 are newly present in the candidate, and 0 baseline registered codes are absent. The old unregistered file 01C7 is absent from the candidate KB.ini corpus; it was not a registered model code in 4.06. All candidate profile codes appear in the extracted configured PID list.

### Newly present profile codes

These are newly present configuration codes relative to this one installed 4.06 snapshot. A code in configuration is not proof that a physical model exists, is currently sold, or was tested.

| Code | Name in extracted configuration |
| --- | --- |
| 01EA | RK R65 Keyboard |
| 0208 | M20 |
| 0216 | RK A72 Keyboard |
| 021E | RK-S98 Keyboard |
| 021F | 756 keyboard |
| 0221 | RK N80 RU Keyboard |
| 022E | RK Air61 Keyboard |
| 023B | RK M100 DE Keyboard |
| 023E | RK100 Keyboard |
| 023F | RK-S98 Keyboard |
| 0240 | RK-S98 Keyboard |
| 0241 | RK-S98 FR Keyboard |
| 0242 | RK-R87S Keyboard |
| 0245 | RK M70 RU Keyboard |
| 0249 | RK L75 RU Keyboard |
| 024A | RK L75 TH Keyboard |
| 024B | RK M65 RU Keyboard |
| 0251 | RK X104 Keyboard |
| 0256 | RK X104 three-mode |
| 0257 | RK G87 |
| 0258 | RK K99 |
| 025A | RK S104 Keyboard |
| 025E | RK N99 TH Keyboard |
| 025F | RK N99 RU Keyboard |
| 0263 | RK-S85 RU Keyboard |
| 0264 | RK-S85 TH Keyboard |
| 0265 | RK S85 ES Keyboard |
| 0266 | RK M100 FR Keyboard |
| 0267 | RK Ultra65 |
| 026B | RK M100 Keyboard |
| 026E | RK L75 Keyboard |
| 0272 | RK M87 FR Keyboard |
| 0273 | RK M87 ES Keyboard |
| 0274 | RK M87 TH Keyboard |
| 0275 | RK M87 RU Keyboard |
| 0276 | RK M87 DE Keyboard |
| 027A | RK AS68 |
| 027C | R98Pro ES Keyboard |
| 028D | R104 |
| 0298 | RK R108Pro |
| 029A | X87 DE |
| 02A0 | R98Pro |
| 02A2 | RK L75Pro |
| 02A6 | RK84 Keyboard 2.0 |
| 02A7 | RK61 FR Keyboard |
| 02A8 | RK61 JP Keyboard |
| 02A9 | RK84 DE Keyboard 2.0 |
| 02AA | RK84 FR Keyboard 2.0 |
| 02AB | RK84 ES Keyboard 2.0 |
| 02AC | RK68 Keyboard 2.0 |
| 02B0 | R98Pro RU Keyboard |
| 02B1 | RK M100 Keyboard |
| 02B2 | RK-R87 Wired Keyboard |
| 02B3 | RK61 Keyboard |
| 02B4 | K71R Pro |
| 02B8 | R98Pro V2 |
| 02BA | RK N99 ES Keyboard |
| 02C0 | RK-M75 ES Keyboard |
| 02C2 | R75Pro V2 |
| 02C3 | RK-M75 POR Keyboard |
| 02D1 | RK S104 Keyboard |
| 02D4 | RK61 Keyboard 2.0 |
| 02D5 | R87PRO Keyboard |
| 02DA | RK S104 FR Keyboard |
| 02DB | RK S104 ES Keyboard |
| 02E5 | RK-M75 FR Keyboard |
| 02E6 | RK-M75 DE Keyboard |
| 02EB | RK R104Pro |
| 02EC | RK R104Pro |
| 02ED | RK R104Pro |
| 02F0 | CB68 |
| 02F1 | CB75 |
| 02F2 | RK R104Pro |
| 02F4 | RK R104Pro |
| 02F6 | RK S104 Keyboard |
| 02FE | RK L75 |
| 0300 | RK L75 |

### Changed names on retained codes

| Code | 4.06 catalog name | Candidate catalog name |
| --- | --- | --- |
| 0201 | RK L75 ISO Return Keyboard | RK L75 Keyboard |
| 0202 | RK M65 ISO Return Keyboard | RK M65 Keyboard |
| 0203 | RK M70 ISO Return Keyboard | RK M70 Keyboard |

For these retained codes, the catalog profile options, base/Fn mappings, layout ID, and derived feature data match. Only the name and name-derived region label differ (ISO to ANSI). This is a configuration-label change; the physical layout or regional variant has not been independently identified. No same-name code replacement was found among the added/removed registered-code sets.

Fourteen other retained profiles have changed OPT values; their mapping rows and layout IDs are unchanged:

| Code | Changed option fields |
| --- | --- |
| 00A1 | ShowSleepTime |
| 01A2 | ShowHourFormat |
| 01AF | ShowHourFormat |
| 01D6 | ShowHourFormat |
| 01D9 | ShowSleepTime |
| 01F5 | MouseInsert, ShowHourFormat |
| 0207 | TsDefault, TsOffset |
| 020C | CmdReset |
| 020F | LightHW, LightUI, SpeedParam, TsOffset |
| 0210 | CmdReset |
| 0220 | ShowSleepTime |
| 0222 | CmdReset |
| 0225 | CmdReset |
| 0229 | ShowSleepTime |

Of the 188 common model JSON records, 171 are exactly equal as parsed JSON values. The remainder are the three name/region changes above plus the option-value changes listed above. No common model's base mapping, Fn mapping, or layout reference changed.

## Profile schema and declared capabilities

The catalog keeps schema version 3 and the same top-level and per-model object fields as models.json. The profile-data sections remain options, baseMappings, fnMappings, sectionNames, and lightingLabels. No 4.06 option field disappears; 25 additional profile option keys are present:

| New option key | Profiles containing it |
| --- | ---: |
| DefSideLedIndex | 2 |
| KnobDef | 8 |
| KnobIndex | 8 |
| MouseInsert | 1 |
| OpenWebIndex | 5 |
| ShowHourFormat | 14 |
| ShowLED | 1 |
| ShowSideLED | 2 |
| SideBri | 2 |
| SideLedOpt1 | 2 |
| SideLedOpt10 | 1 |
| SideLedOpt2 | 2 |
| SideLedOpt3 | 2 |
| SideLedOpt4 | 2 |
| SideLedOpt5 | 2 |
| SideLedOpt6 | 1 |
| SideLedOpt7 | 1 |
| SideLedOpt8 | 1 |
| SideLedOpt9 | 1 |
| SideSpeed | 2 |
| TouchWeb | 5 |
| TsDefault | 3 |
| TsOffset | 5 |
| Wired | 7 |
| kLayerMask | 1 |

Names such as KnobDef, SideLedOpt*, and TouchWeb suggest additional control categories, but field names alone do not establish their units, UI behavior, command encoding, or device compatibility.

| Catalog-derived measure | 4.06 | Candidate |
| --- | ---: | ---: |
| Distinct profile option keys | 88 | 113 |
| Option assignments across named profiles | 6,481 | 10,134 |
| Base mapping rows | 15,841 | 22,788 |
| Profiles with FN1 / rows | 63 / 2,278 | 132 / 4,774 |
| Profiles with FN2 / rows | 17 / 603 | 26 / 917 |
| Base mapping tuple widths | 8, 9, 10 | 8, 9, 10 |
| Fn mapping tuple widths | 3, 4 | 3, 4 |
| RGBKb-enabled profiles | 156 | 226 |
| Profiles with screen declarations | 15 | 37 |
| Profiles with nonzero macro buffers | 3 | 10 |
| Profiles with wireless VID/PID values | 7 | 23 |

These are declarations extracted from configuration, not confirmed features on attached keyboards. The catalog derives family and region labels from names; those convenience labels are not explicit vendor schema fields.

## Layout and profile-local resource differences

The catalog's layouts collection grows from 90 to 140 unique keyboard geometry records. All 90 shared layout IDs have identical geometry; the candidate adds 50 IDs and removes 0. These records are rectangles projected from KB.ini key rows, not copied keyboard artwork.

Profile-local resource presence was counted only within directories containing a KB.ini:

| Resource presence/count | 4.06 | Candidate |
| --- | ---: | ---: |
| Profiles with keyimg.png | 102 | 169 |
| Profiles with kbled.png | 102 | 169 |
| Profiles with any GIF | 2 | 2 |
| Profiles with profile-local led.xml | 5 | 9 |
| Profiles with files under ET | 33 | 76 |
| Profiles with files under Cartoon | 34 | 75 |
| Profiles with .upf file | 1 | 1 |

The catalog extractor retained usable LED-label lists for 4 named models in the baseline and 8 in the candidate. Some on-disk XML files do not yield parsed labels. Resource presence does not establish which assets the UI selects or whether a physical keyboard supports them. Images and other vendor assets were not copied.

## Family-routing counts and interpretation

The 4.06 handler map has 188 direct-profile rows: 125 assigned to CDevRKKB and 63 to CDevG5KB. Its profile Fw values are (omitted; loader default 0): 124, 0: 1, 1: 53, 2: 10. All 188 shared profile codes retain the same handler grouping in the candidate map.

For the V4.6-labeled package, raw Fw counts are (omitted; loader default 0): 132, 0: 1, 1: 113, 2: 18, 3: 1. Applying the previously analyzed 4.06 zero/nonzero selector projects 133 CDevRKKB and 132 CDevG5KB rows. The candidate CSV's static_handler column is generated from that 4.06 rule; it is not proof that the candidate binary uses the same selector, especially for the new Fw=3 case. The extracted candidate DeviceDriver.exe has a different hash and size from the installed executable, and this task did not statically analyze its routing code.

The resulting rows are published in the
[4.6 projected profile-to-family map](rk-profile-driver-family-map-v4.6-projected.csv)
so each profile's USB IDs, raw selector value, and projected handler can be
reviewed directly. Treat `static_handler` as a projection from the 4.06 rule,
not a recovered 4.6 code path.

The 23 configured wireless VID/PID pairs in the candidate are profile data, not validated receiver matches. The baseline contains 7 such rows.

## Evidence and reproducibility

| Evidence | 4.06 installed baseline | V4.6-labeled extracted package |
| --- | --- | --- |
| Cfg.ini SHA-256 / bytes | 1a9796e706fa64b1821417efda080d481e202ffcf941aa97e6a78efe3a32badd / 16,678 | ab9c84bb951bcfec99e18e0c6a77ece913e14376265c33276e3b176c030b6cc5 / 22,410 |
| Cfg.ini version value | Ver=0x406 | Ver=0x406 |
| Sorted Dev/*/KB.ini corpus manifest SHA-256 | 7110dfd8c0992551d7427895be64df8ade5624857656e4655fba9a6d76170b07 (189 files) | c19ab8908ecf96beb12e43d947c0d3891ed6d9344b0bc886a06524cd00858338 (265 files) |
| DeviceDriver.exe SHA-256 / bytes | c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6 / 2,326,528 | 8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9 / 2,418,176 |

The candidate installer file is .research/RK_Keyboard_Software_Setup_V4.6_20261015.exe (96,720,579 bytes; SHA-256 47a1fc21c3af548b93fa40d499584abecb3341e62b15948ae537b78ca987aad8). The extracted source tree is .research/rk4_6_official_extract_20261015/app. The KB manifest digest is SHA-256 over sorted relative paths, a NUL byte, each file's SHA-256 text, and a newline. The repository generator is scripts/extract_rk_catalog.py; rerun it with --rk-root set to the extracted app path to reproduce the catalog and profile map.

## Limits

- This is one installed 4.06 snapshot compared with one V4.6-named setup extract. It is not an exhaustive catalog of all Royal Kludge keyboards or releases.
- The setup label and embedded Ver=0x406 disagree in apparent versioning; no vendor release notes were used to resolve that naming.
- Cfg.ini and profile declarations establish what this package contains, not successful device detection, firmware identity, or feature operation.
- The candidate driver executable differs from the installed binary. Its UI event handling, native API paths, and model-routing code remain unexamined here; candidate handler counts are projections only.
- Family and region labels are generated heuristically from model names. Name changes can alter those labels without profile-data changes.
- No keyboard communication, firmware readback, write, updater run, or hardware validation was attempted.
