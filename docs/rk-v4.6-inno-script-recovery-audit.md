# RK 4.6 Inno Setup script recovery audit

## Result

The 4.6 installer’s compiled PascalScript callbacks were not recovered. This
is a bounded negative result for the available static extraction and literal
search paths; it is not proof that the installer contains no script code. No
installer, uninstaller, RK application, updater, keyboard interface, or
bootloader was run or opened.

## Hash-pinned input and procedure

The target is the official Windows Hub Driver setup named
`RK_Keyboard_Software_Setup_V4.6_20261015.exe`, 96,720,579 bytes, SHA-256
`47A1FC21C3AF548B93FA40D499584ABECB3341E62B15948AE537B78CA987AAD8`. Its
provenance is recorded in the [4.6 package snapshot](rk-v4.6-package-snapshot.md).

The offline procedure used `innoextract 1.9` against that exact file:

```powershell
innoextract.exe --info "C:\path\to\RK_Keyboard_Software_Setup_V4.6_20261015.exe"
innoextract.exe --list "C:\path\to\RK_Keyboard_Software_Setup_V4.6_20261015.exe"
python scripts/audit_rk46_inno_script_literals.py `
  "C:\path\to\RK_Keyboard_Software_Setup_V4.6_20261015.exe"
```

`--info` identifies Inno Setup 5.3.3 Unicode, the seven package languages
(`en`, `sc`, `tw`, Korean, Japanese, Turkish, and Russian), and that the
setup is not passworded. `--list` enumerates payload files. Neither output
provides the compiled setup callbacks, event-dispatch table, or a generated
uninstaller log.

The companion literal scanner checks the setup’s SHA-256, then searches raw
bytes for selected callback, helper, language, and title identifiers from the
4.06 baseline, in both ASCII and UTF-16LE. It found no occurrences of
`InitializeSetup`, `InitializeUninstall`, `MyAfterInstall`, `MyAfterInstall2`,
`CurUninstallStepChanged`, `InitializeUninstallProgressForm`, `SetupInit`,
`LangIndex`, `RK Keyboard`, or `RK RGB Keyboard`. The bytes `RKKB` occur once
at `0x04D18F54`, within this non-text context:
`91 89 6C 7C 5C 91 F7 2D 72 6B 6B 42 9C E9 6A E6`. That isolated byte sequence
is not evidence of a script path or callback.

Literal searching cannot identify compressed or encoded script data, parse
Inno’s compiled script structures, or rule out dynamically constructed names.
`innoextract --info`/`--list` and this scanner therefore establish only that
these bounded routes did not disclose the callback bodies. A route from this
setup-data output to the compiled callbacks remains unresolved, and no
separately generated 4.6 uninstaller log is present in the snapshot.

## Concrete package operations and boundaries

The hash-verified extracted payload contains 1,249 files totaling
104,009,969 bytes: 1,245 under `app/`, three under `fonts/`, and one under
`localappdata/`. These are the extractor’s expanded package paths, not proof
of the final absolute install directory or install conditions. The sole
`localappdata/` entry is `RKKB/lang.ini`, 18 bytes, with `[OPT]` and
`LangIndex=0`; this proves the packaged initial file content, not that a
callback writes a selected language.

The packaged `InitSetup.dll` SHA-256
`59DB7BFD9A92CC9A0998260807F17C536EC71159B727DF10D08B998BC94DE301` and
`uninstall.dll` SHA-256
`9CA1EBC49998B8B2971DEBC1776E7AFF6086AEB86ADCCA6CFB95E9FB399EB03C` match
the installed 4.06 files byte-for-byte. Static analysis of the shared
`InitSetup.dll!SetupInit` export shows recursive file and child-directory
deletion at a supplied path. The corresponding 4.06 callback supplies
`%LOCALAPPDATA%\RKKB`, but the 4.6 callback and whether it calls this helper
are unknown. The shared helper’s capability must not be treated as proof that
the 4.6 setup invokes it.

The 4.06 comparison evidence comes from its installed, generated
`unins000.dat` log, not from the 4.6 setup executable. It contains two
IFPS-v23 script snapshots (1,946 and 2,130 bytes) with the same exported
callback set. Their decoded bodies include setup-window close checks, a
`MyAfterInstall` call to `SetupInit`, language-index mapping/writing, and an
empty `CurUninstallStepChanged`. The larger snapshot adds Turkish, Japanese,
and Korean cases. The 4.6 package has no generated `unins000.exe` or
`unins000.dat`; the 4.06 callback findings and uninstaller behavior are
baseline-only and cannot establish the 4.6 install or uninstall flow. See the
[4.06 script audit](rk-installer-uninstaller-script-audit.md).

Accordingly, the available 4.6 evidence does not resolve registry writes,
shortcut creation, install/uninstall directory rules, overwrite/delete
conditions, generated uninstaller actions, callback dispatch/order, or actual
runtime side effects. No keyboard-specific operation is established by this
installer analysis.

## Reproducible scanner

Run the literal scanner from the repository root:

```powershell
python scripts/audit_rk46_inno_script_literals.py `
  "C:\path\to\RK_Keyboard_Software_Setup_V4.6_20261015.exe"
```

It refuses input whose SHA-256 differs from the official snapshot hash and
reports offsets for the explicitly enumerated literal encodings. A miss is
not an absence proof for compiled or transformed script data.
