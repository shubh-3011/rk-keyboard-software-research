# F99 3.2.2 `background.js` cross-platform comparison

**Scope:** static comparison of the common Electron ASAR member `background.js` from the hash-pinned Windows and macOS F99 3.2.2 packages. This report does not claim a complete semantic explanation of every bundle change.

## Inputs and identity

| Artifact | Size | SHA-256 |
|---|---:|---|
| macOS source DMG, `RK-3.2.2-universal.dmg` | 235,050,258 bytes | `d0f624aab5caf23c008c0024a63c3c438c9d5c3340503dc770f4957bae2e1951` |
| macOS ASAR extent at APFS physical offset 23,875,584 | 30,217,234 bytes | `a6b3783602040407932e95e9237cbabb774690bad515d51c21fd59c9f74279db` |
| Windows `resources/app.asar` | 30,252,260 bytes | `38ebbf1416050d9ab36eee4910ec86130a0919b69334ec3751378f7f00ff2bdf` |
| macOS `background.js` member | 2,835,847 bytes | `7d24ec44fde96911790ed9578bdec76943868a30b5b2a0b63dbe23bad6c5ab30` |
| Windows `background.js` member | 2,835,093 bytes | `8db60b45ce93fc20f68950ebb97db0640d6384c3808b06e43c332d8ef4183277` |

The ASAR package metadata on both sides identifies `name=RK`, `version=3.2.2`, and `main=background.js`. The macOS ASAR was carved from the APFS image by extent; its original filesystem pathname was not recovered. The input files are the existing `.research/rk-selector-software-2026-10-19/RK-3.2.2-universal.dmg` and `.research/F99_3.2.2_static/selected/resources/app.asar` snapshots adjacent to this repository.

## Proven static findings

- The top-level Webpack factory array has 608 positional entries on each platform. Entry factory 338 is byte-identical in both builds (33 bytes; SHA-256 `95fefd03d2e5541f871384bab3084387c312e354d592ea51556c09f5981c4430`) and statically requires factory 607 in both.
- Factory 607 is therefore the same entry-reachable slot in both builds, though its contents differ (macOS 1,348,337 bytes, SHA-256 `efa5069474f6aebe5caa11ed6a0e2a26f0dd20969e77eb59137429f9b80ae65f`; Windows 1,347,583 bytes, SHA-256 `57452897def8733d88b80100dc14a075f046a44d8bf6001587d1e05b7a001147`). The bounded token-anchor ledger records 1,409 changed spans within this directly imported factory; the offsets and SHA-256 values are in `rk-f99-background-js-change-blocks-2026-10-20.csv`.
- Factory 607 statically requires factory 88 in both builds. Factory 88 is identical (42 bytes; SHA-256 `dd6f5ab0ece3d6063f147290b0c65205da32457dbbc4ac68a2de1470f8e2af5c`) and its complete 42-byte body is `function(e,t){e.exports=require("mi-hid")}`. This is the visible JavaScript-to-package wrapper boundary.
- Factory 607 contains the same packaged HID path expression in both builds: development uses the module name `mi-hid`; packaged mode joins Electron's `resourcesPath` with `/node/hid/mi-hid.node`. The minified variable names and surrounding bundle offsets differ. The `mi-hid` string starts at absolute `background.js` offsets 2,181,158 (macOS) and 2,180,199 (Windows); the `node/hid` portion starts at 2,181,197 and 2,180,238, respectively. Full occurrences and module hashes are in `rk-f99-background-js-static-boundary-markers-2026-10-20.csv`.
- In both factories, the computed HID name and the device identifier are placed in a worker's `workerData`. The worker source is one escaped JavaScript string token, byte-identical across platforms (826 raw bytes; SHA-256 `e768f62585cbac268cbd24c4d0dce7dadc935dc80a53ec9068471e531a74a39b`). Statically, that script reads `workerData.hidName`, dynamically requires it, constructs `HID.HID` with `workerData.hidPath`, and catches construction errors. The raw token offsets are 2,187,173 (macOS) and 2,186,214 (Windows); the ledger records the same-token hash on both sides.
- The static require list of factory 607 differs at two IDs: macOS references 125 and 456 where Windows references 123 and 430. The rest of the numeric list is equal. These are Webpack IDs, not stable package names; the associated factories have no exact cross-platform content match in the hash map, so this report does not assign them a semantic name.

## Module-index alignment caveat

Comparing only equal numeric slots would mark 379 of 608 slots as different. That overstates divergence because module IDs are positional and many exact factory byte strings moved to another array index:

- The content map finds 477 SHA-256 groups present on both sides, with a lower bound of 479 exact-content pairs.
- 229 exact matches remain at the same numeric ID; at least 250 exact-content pairs may be relocations. Two shared hash groups contain duplicate factories, so their module-ID pairing is ambiguous.
- 129 module hashes appear only in the macOS array and 129 only in the Windows array. This means no exact byte-content peer was found for those factories; it does not establish which features were added, removed, or changed.

See `rk-f99-background-js-content-identity-map-2026-10-20.csv` for every hash group and `rk-f99-background-js-module-diff-2026-10-20.csv` for the raw slot ledger. The identity map deliberately reports byte identity rather than asserting semantic module identity.

## Native boundary evidence and limits

The Windows package snapshot contains `resources/node/hid/mi-hid.node` (SHA-256 `fe68309021c9640f16a2bbd550738cf8904b3d18a1cc3a4e8b2d22ec2a2d5ee4`). Existing static import evidence for that file includes Windows file and HID-related APIs; see `rk-f99-native-hid-imports-2026-10-19.csv`. The macOS package analysis records Darwin `mi-hid` prebuild members and a separate Mach-O bundle candidate with IOKit/HID imports; the candidate's original APFS pathname and its relationship to the JavaScript package remain unresolved in `rk-f99-macos-static-findings-2026-10-20.md`.

These facts establish a static loading path and native HID boundary, not successful loading or runtime reachability. No app was started and no HID interface was opened. The `background.js` bundles contain no `sourceMappingURL` reference and neither ASAR has a member named `background.js.map`. Each ASAR has 363 other `.map` members, but this pass did not establish that any of those maps describe this bundle.

## Unresolved semantic delta

Factory 607 is large and contains 1,409 token-anchor change spans. The scanner gives exact member offsets, lengths and hashes, plus containing classic-function candidates where its lexer can identify them. Its ten-token unique anchors are intentionally conservative and can merge repeated or divergent text into coarse spans; these are not a minimal edit script. The minified symbols, unmatched factories, absent bundle map and lack of runtime evidence prevent attribution of all changes to named functions or user-visible behavior. The unchanged HID worker source and same path-construction pattern show no HID-worker implementation change at this boundary, but do not prove the surrounding application changes are semantically equivalent.

## Reproduction

From the repository root, with the two pinned `.research` snapshots in their recorded locations:

```powershell
python scripts\compare_rk_f99_background_js.py
```

The scanner verifies the source hashes, ASAR extent/member hashes, package metadata, module count, and bundle entry; reads members in memory; writes the four CSV ledgers above; and prints a JSON summary. It uses Python's standard library and existing local ASAR/APFS audit helpers. It does not run packaged JavaScript, an app, or HID code, and it does not write extracted source members.
