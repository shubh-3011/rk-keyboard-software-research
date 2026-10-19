# RK installer and uninstaller script audit

This audit covers the compiled PascalScript records embedded in the installed
Inno Setup uninstaller log. It is static bytecode analysis only. Neither the
uninstaller nor the RK application was launched; no script or helper function
was executed, and no keyboard interface was opened.

## Inputs and method

The input was the installed `unins000.dat` log (261,476 bytes; SHA-256
`584440eb2154bcc6881846d824c45b2c3074929d653bb0f5e3f306a746aa8f20`). The
log's 65 integrity-checked blocks and 1,651 records were decoded locally. Two
embedded Unicode IFPS bytecode payloads were extracted to temporary research
files outside this repository and disassembled with the v2.0.5 open-source
[IFPSTools.NET disassembler](https://github.com/Wack0/IFPSTools.NET). The
payloads were not run. No original proprietary binaries, bytecode, or personal
file paths are included in this repository.

The two payloads are 1,946 bytes (SHA-256
`1047f0b399c7b7e8d0989ee6c0b312c25dd2378f79bf4cc2acba50b316ebf117`) and
2,130 bytes (SHA-256
`db39a413e7ca801a4040b7be4eb7d4023209338ff7d428ed55bf913ee0c57d98`). Both
identify IFPS format version 23 and have the same callback set. The second is
184 bytes larger and adds three language cases. The uninstaller log contains
both records, but static evidence does not establish why both snapshots are
present, which one is selected by the Inno engine, or which callbacks actually
ran during install or uninstall.

## Callback findings

| Callback | Static bytecode | Status and limits |
| --- | --- | --- |
| `InitializeSetup` | Looks up top-level windows named `RK Keyboard` and `RK RGB Keyboard`. For each nonzero handle it calls `SendMessage` with `wParam=0`, `lParam=0`, and message `16`, then sleeps 1,000 ms. Returns true. | The names, constants, and calls are proven in bytecode. Interpreting message `16` as `WM_CLOSE` follows the Windows message constant; actual window matching, message delivery, and setup-engine callback execution were not observed. |
| `MyAfterInstall` | Expands `{localappdata}\RKKB` and passes that path to the delayed `InitSetup.dll!SetupInit` import. | The callback-to-helper call and path are proven in bytecode. The separate `InitSetup.dll` analysis shows recursive enumeration and deletion of files and child directories at the supplied path. Whether the callback runs, whether loading succeeds, and which files would be removed at runtime are unverified. |
| `MyAfterInstall2` | Reads `ActiveLanguage`, selects a numeric value, expands `{localappdata}\RKKB\lang.ini`, and calls `SetIniInt` for section `OPT`, key `LangIndex`. | The calls, strings, and branch values are proven. Actual language selection and INI write are unverified. |
| `CurUninstallStepChanged` | Immediately returns. | No callback-specific operation is present in either disassembly. |
| `InitializeUninstallProgressForm` | Repeats the two title lookups, conditional `SendMessage(..., 16, 0, 0)` calls, and 1,000 ms sleeps. | Same static/runtime distinction as `InitializeSetup`. |
| `!MAIN` | Immediately returns; neither payload has an intra-script call from this entrypoint to an exported callback. | The bytecode proves callback bodies and export markers, but not the Inno engine's event-dispatch table, callback reachability, or event order. |

The import table declared by the script also includes `FindWindowByWindowName`,
`SendMessage`, `Sleep`, `ActiveLanguage`, `ExpandConstant`, and `SetIniInt`.
The helper `SetupInit` is a delayed import from the installed `InitSetup.dll`.
Those declarations are script-level imports; the native uninstaller PE import
table is a separate inventory in
[`rk-native-api-imports.md`](rk-native-api-imports.md).

## Locale-index variants

Both scripts initialize `LangIndex` to `0` and map the observed language
strings as follows:

| Language string | Stored index |
| --- | ---: |
| `sc` | 0 |
| `en` | 1 |
| `tw` | 2 |
| `Russian` | 3 |

The larger script additionally maps `Turkish` to `4`, `Japanese` to `5`, and
`Korean` to `6`. For any other string, the initialized value `0` is written.
This is a direct reading of the branches and default assignment; it does not
prove the installer's runtime language identifier or that the callback is
dispatched. See the
[resource and localization audit](rk-resource-localization-audit.md) for the
installed UI language files and their contents.

## Relation to native helper and OS APIs

The script's `MyAfterInstall` path now supplies the missing static link between
the callback and `InitSetup.dll!SetupInit`. The helper accepts one path and,
when it exists, recursively enumerates `path\*.*`, deletes files, and removes
nested directories. That makes `%LOCALAPPDATA%\RKKB` the path named by the
bytecode. The callback name implies an installer event, but actual invocation
and side effects remain unobserved.

The compiled Inno engine is separately covered by the
[system API and call crosswalk](rk-system-api-crosswalk.md) and the main
[reverse-engineering report](reverse-engineering.md). The native uninstaller
has no imported HID, SetupAPI, or Service Control Manager APIs in the reviewed
import tables. Its inspected `DeviceIoControl` use is for file compression;
its conditional reboot path and generic registry cleanup are documented in
the main report. The script disassembly adds no keyboard or firmware operation.

## Open questions

- Which of the two script snapshots corresponds to the active install record,
  and why both are stored in the current log?
- What is the exact event-dispatch order and condition for each callback in
  this Inno Setup version?
- Does the delayed helper load and execute on the installed machine, and what
  filesystem state exists when it is called?
- Under what runtime condition does the uninstaller reach its reboot path?
- What additional behavior exists in the generic Inno Setup engine beyond the
  selected native call paths already documented?

These questions require more static engine analysis or controlled runtime
observation. Runtime work is outside this offline audit and must not open or
write to the keyboard.

## Related reports

- [Main reverse-engineering report](reverse-engineering.md)
- [System API and static call crosswalk](rk-system-api-crosswalk.md)
- [Native API imports](rk-native-api-imports.md)
- [Native API IAT references](rk-native-api-xrefs.csv)
- [Dynamic API lookup candidates](rk-dynamic-api-targets.csv)
- [Profile catalog and schema audit](rk-profile-schema-audit.md)
- [Resource and localization audit](rk-resource-localization-audit.md)
