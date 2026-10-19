# RK Keyboard Software 4.6 installer callback recovery

**Status:** static recovery complete for the callback bytecode embedded in the
4.6 installer. Installer execution, generated 4.6 uninstaller behavior, and
runtime side effects remain unresolved.

## Scope and method

The target was the copied RK Keyboard Software 4.6 setup package, not an
installed uninstaller snapshot. The installer was parsed with innounp in
static extraction mode for only `embedded\\CompiledCode.bin` and its generated
`install_script.iss` descriptor. The extracted PascalScript bytecode was
disassembled with IFPSTools.NET `ifpsdasm`. Neither the installer, RK software,
updater, nor any vendor binary was launched. No registry was touched, and no
keyboard/HID interface, report, or bootloader was used.

The script [audit_rk46_installer_callbacks.py](../scripts/audit_rk46_installer_callbacks.py)
repeats the extraction in a temporary directory, checks the inputs and
intermediate files against SHA-256 pins, parses exported callback bodies and
the generated Inno descriptor, and emits two row-level ledgers:

- [Callback evidence](rk-v4.6-installer-callback-evidence-2026-10-20.csv)
- [Installer action evidence](rk-v4.6-installer-action-evidence-2026-10-20.csv)

Run from the repository root:

```powershell
python scripts/audit_rk46_installer_callbacks.py
```

The default inputs live under ignored `.research` folders. They are not
redistributed with this repository. Use `--setup`, `--nupkg`, `--innounp`, and
`--ifpsdasm` when those exact pinned files are kept elsewhere. The script
exits if any required SHA-256 differs.

## Provenance and hashes

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| RK 4.6 setup package | 96,720,579 | `47a1fc21c3af548b93fa40d499584abecb3341e62b15948ae537b78ca987aad8` |
| Extracted `CompiledCode.bin` | 2,129 | `14289e06e226ea346521af11519286a38482a58eac11e9cc36b556144e50b981` |
| IFPSTools disassembly `CompiledCode.txt` | 7,810 | `778c9641535017fbc735f8a3647f4a2b942ab7303616f2a310c54c69a22b65f9` |
| innounp Chocolatey package `.nupkg` | 263,123 | `c8dc71bfdda39c44a8c962721a32f09339b0095f29e8fe619f5627f287e8c26d` |
| innounp 0.50 executable from that package | 665,088 | `9b72ad9f93d167652a0e2bf3921abdfd3e6747c5e718461a2e58b9dfacd31f4c` |
| IFPSTools.NET `ifpsdasm.exe` | 5,632 | `115b85d2bcea1b2c41199e3fda686de0bb87a62c6cba59208abe28e71b635773` |
| innounp-reconstructed `install_script.iss` | 142,923 | `c1d3d2dcea25790cd8264f19d60c39a4c12d122f6b1799a1a878d647ed8a98a1` |

The setup identifies Inno Setup `5.3.3 (Unicode)` in the generated descriptor.
innounp reported version `0.50`; IFPSTools.NET is the locally available 2.0.5
build, from source commit
[`4389f35dabbaa57d87e1779bf4aece9523967cc5`](https://github.com/Wack0/IFPSTools.NET/commit/4389f35dabbaa57d87e1779bf4aece9523967cc5).

The innounp project page is [innounp.sourceforge.net](https://innounp.sourceforge.net/).
The exact primary release URL named by the package's included
`legal/VERIFICATION.txt` is
[`innounp050.rar`](https://sourceforge.net/projects/innounp/files/innounp/innounp%200.50/innounp050.rar/download).
That verification note says to compare the packaged `innounp.exe` with the
binary from that release. A direct fetch in this environment returned a
139,276-byte HTML page (SHA-256
`fc1b50fc37fbe27a8ae42dadc1c9f73a0ede41dbd5de5023f2205ddb67af91ee`), not the
RAR. Therefore, the primary SourceForge release binary could not be
independently hash-compared, and no vendor signature/checksum was available in
the local snapshot. The used executable is identity-pinned to the
Chocolatey `.nupkg`, and the included verification note supplies the upstream
release URL, but this is a repack provenance chain rather than direct proof
that the tool binary matches the SourceForge release. The generated descriptor
and bytecode hashes are pinned so that the extraction result can still be
checked exactly.

## Recovered callback behavior

The disassembly marks these names as exported callback entries. The bytecode
proves the bodies and constants; it does not establish that the Inno engine
dispatched them during any particular install or uninstall.

| Callback | Static finding | Confidence and limit |
| --- | --- | --- |
| `!MAIN` | Contains only `ret`. | Proven body. Event dispatch is outside the bytecode body. |
| `INITIALIZESETUP` | Searches for top-level windows titled `RK Keyboard` and `RK RGB Keyboard`. For each nonzero window result, it calls `SENDMESSAGE` with the handle and message value `16`, with two zero values, then sleeps 1,000 ms. It returns `BOOLEAN(1)`. | The strings, branch conditions, values, calls, delay, and return are proven. Message `16` is the Win32 `WM_CLOSE` value. Actual window matches, message delivery, and callback dispatch were not observed. |
| `MYAFTERINSTALL` | Expands `{localappdata}\RKKB` and passes the resulting path to delayed import `InitSetup.dll!SetupInit`. | The call and argument are proven. The separate [helper audit](rk-installer-helper-no-direct-call-import-followup.md) and [main report](reverse-engineering.md#installer-and-uninstaller-components) statically identify recursive file and nested-directory deletion beneath an existing supplied path. Whether the callback runs, the helper loads, or files are removed is not observed here. |
| `MYAFTERINSTALL2` | Initializes the numeric index to `0`; maps `en→1`, `sc→0`, `tw→2`, `Russian→3`, `Turkish→4`, `Japanese→5`, `Korean→6`; expands `{localappdata}\RKKB\lang.ini`; calls `SETINIINT` for section `OPT`, key `LangIndex`, and the mapped value. | The default, branches, strings, and call are proven. The selected runtime locale and resulting INI state are unknown. |
| `CURUNINSTALLSTEPCHANGED` | Contains only `ret`; the event argument is unused. | Proven body. Uninstaller engine behavior is not covered. |
| `INITIALIZEUNINSTALLPROGRESSFORM` | Repeats the two title lookups, conditional message value `16` calls with two zero values, and 1,000 ms sleeps. | Proven body. Window state, message delivery, and event dispatch are unobserved. |

The exact callback evidence anchors are in the callback CSV, using line
numbers from the pinned disassembly. The script's imports also declare
`FindWindowByWindowName`, `SendMessage`, `Sleep`, `ActiveLanguage`,
`ExpandConstant`, and `SetIniInt`.

## Reconstructed installer descriptor

innounp reconstructed an `.iss` descriptor from the installer metadata; this
is not the original authoring source. The action ledger contains 1,271 rows:
1,249 `[Files]` records, 13 `[Setup]` directives, one `[Dirs]` entry, one
`[Run]` entry, three `[Icons]` entries, and four bounded absence observations.
The recovered section names are `[Setup]`, `[Files]`, `[Dirs]`, `[Run]`,
`[Icons]`, `[CustomMessages]`, and `[Languages]`.

Relevant rows, identified by source line in the reconstructed descriptor:

- Lines 1266–1267 associate `DeviceDriver.exe` with `MyAfterInstall` and
  `{localappdata}\RKKB\lang.ini` with `MyAfterInstall2`; both carry
  `ignoreversion`.
- The three `{fonts}` records (lines 19–21) have
  `uninsneveruninstall onlyifdoesntexist`; the remaining 1,246 file records
  have `ignoreversion`.
- `[Dirs]` line 1270 names `{localappdata}\RKKB`.
- `[Run]` line 1273 describes `{app}\DeviceDriver.exe` with `postinstall`,
  `skipifsilent`, and `nowait` flags. This records an optional post-install
  launch entry; it does not prove a user selected it or the driver started.
- `[Icons]` lines 1276–1278 describe the program shortcut, uninstall shortcut,
  and user-desktop shortcut.
- `[Registry]`, `[InstallDelete]`, `[UninstallDelete]`, and `[UninstallRun]`
  are not present in the recovered descriptor. These are bounded negative
  observations about this reconstructed script only, not proof that the Inno
  engine creates no registry/uninstall state or that unrecovered data has no
  further behavior.

The action CSV preserves every file row and its flags/metadata for line-level
review. `AfterInstall` there means the generated descriptor attaches a named
callback to that file entry; it is not evidence that callback execution
occurred. The source order is visible in the descriptor; runtime sequencing
and error handling were not exercised.

## Proven, inferred, and unresolved

**Proven by hash-pinned static artifacts:** the six exported callback bodies;
the two app-window title strings; message value `16`; zero values and delay;
`INITIALIZESETUP`'s true return; the setup-helper argument; the language map and
INI arguments; the callback-to-file associations; and the recovered action
rows described above.

**Interpretation from established Windows/Inno conventions:** message value
`16` denotes `WM_CLOSE`. `MyAfterInstall` calls a helper whose analyzed body
recursively deletes files and directories under the named `%LOCALAPPDATA%`
path if the helper is loaded and that path exists. These explain likely
effects; neither was dynamically observed during setup.

**Unresolved:** actual Inno callback dispatch order and conditions; whether
any callback ran; whether the title lookups found a window; whether Windows
delivered/processed the close request; delayed DLL load success; the exact
filesystem state and failure behavior during helper deletion; actual locale
selection and `lang.ini` writes; whether the optional post-install app ran;
generated 4.6 `unins000.exe`/`.dat` behavior; and the full uninstall registry,
rollback, cleanup, and reboot conditions. The copied 4.6 package does not
contain the generated `unins000.exe`/`.dat` from an installed 4.6 machine.

This recovers the installer callbacks embedded in the exact 4.6 setup image.
It does not amount to a complete reverse engineering of the native Inno engine
or generated uninstaller, and it provides no physical-keyboard behavior
evidence.
