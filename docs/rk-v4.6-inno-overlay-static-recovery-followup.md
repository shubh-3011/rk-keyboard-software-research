# RK 4.6 Inno overlay and PascalScript recovery follow-up

## Scope and result

This follow-up checks whether the exact 4.6 setup file exposes recoverable
compiled Inno PascalScript through the local extractors and source tools. It
also parses the setup executable's PE sections and appended data. This was
offline static analysis only: the vendor setup, uninstaller, RK app, and
updater were not launched; no HID interface or bootloader was accessed.

No compiled callback was recovered. The PE section/resource inventory and
overlay scans identify the Inno Setup loader and its bundled setup data, but
do not decode that data into the script structure accepted by IFPSTools.NET.
Failure to find an exposed script is not proof that no script is embedded in
compressed or transformed data.

## Hash-pinned target and tools

Target: `RK_Keyboard_Software_Setup_V4.6_20261015.exe`, 96,720,579 bytes,
SHA-256 `47A1FC21C3AF548B93FA40D499584ABECB3341E62B15948AE537B78CA987AAD8`.
This is the official Hub Driver package already recorded in the
[4.6 package snapshot](rk-v4.6-package-snapshot.md).

| Local tool | Identity | Relevant capability |
| --- | --- | --- |
| innoextract | 1.9; executable SHA-256 `946BD06D8B3722A791FEA4D84F496139EEF6FAEF61640924CB72F5F1998A68E1` | `--info`, `--list`, and payload extraction; its help lists no PascalScript extraction or disassembly action. |
| GNU objdump | Binutils 2.43.1 | Read-only PE section, import, and disassembly inspection. |
| pefile | 2024.8.26 | Read-only PE header, section, resource, and overlay offsets. |
| IFPSTools.NET | local source commit `4389f35dabbaa57d87e1779bf4aece9523967cc5`; `ifpsdasm.exe` SHA-256 `115B85D2BCEA1B2C41199E3FDA686DE0BB87A62C6CBA59208ABE28E71B635773`; `uninno.exe` SHA-256 `7A672DC8F36ED94EE954F412773ECB7EBF157A8242674F0D2E859071FADCABA8` | Disassembles a supplied compiled IFPS stream; `uninno` creates an uninstaller log from supplied compiled IFPS. It is not an Inno setup-executable extractor. |

The inspected IFPSTools.NET source is available at the
[recorded upstream commit](https://github.com/Wack0/IFPSTools.NET/tree/4389f35dabbaa57d87e1779bf4aece9523967cc5). Its README documents the
`ifpsdasm CompiledCode.bin` interface. `Script.Load` checks that input begins
with the four-byte `IFPS` magic before parsing IFPS version and structures.
`uninno` wraps already compiled IFPS input in a generated uninstaller
configuration; it does not discover or extract script bytes from a setup
executable.

## Inno extractor results

The following local commands were used against the hash-pinned setup:

```powershell
innoextract.exe --info "C:\path\to\RK_Keyboard_Software_Setup_V4.6_20261015.exe"
innoextract.exe --list "C:\path\to\RK_Keyboard_Software_Setup_V4.6_20261015.exe"
```

`--info` reports Inno Setup 5.3.3 Unicode, seven languages (`en`, `sc`, `tw`,
Korean, Japanese, Turkish, and Russian), no GOG ID, and no setup password.
`--list` lists packaged files. Static extraction produced the already
hash-verified 1,249-file tree described in the package snapshot; it did not
produce a PascalScript `.bin`, an `.iss` source file, or a generated
`unins000.exe` or `unins000.dat`. The tool's displayed actions expose no
separate script decompile option.

The local IFPSTools.NET v2.0.5 README says `innounp` does not extract the
uninstaller executable from setup. Its described alternative is to run the
installer under a debugger, break on `CreateProcessW`, and copy the
runtime-created uninstaller from a temporary directory. That runtime route
was not used because this task is limited to offline static analysis.

## PE sections and appended data

`objdump -h/-x` and `pefile 2024.8.26` agree that the outer file is an x86
PE32 image (`pei-i386`, image base `0x00400000`) with entry point RVA
`0x000163C4` (VA `0x004163C4`). The entry point is inside `.itext`; its
disassembly is native loader code. The only sections marked as executable
code are `.text` and `.itext`:

| Section | RVA | Raw file range | Raw bytes | SHA-256 |
| --- | ---: | ---: | ---: | --- |
| `.text` | `0x1000` | `0x400`–`0x147FF` | 82,944 | `1D5AAE4BC6F41B1BD3E9ADE5730DB8051D18572EF8E402107678D84D7EFF584F` |
| `.itext` | `0x16000` | `0x14800`–`0x153FF` | 3,072 | `F2AE11F289056D567C4856FEBCA97253F8E97D3DAA79B17A6229D2AFDBE792DE` |
| `.data` | `0x17000` | `0x15400`–`0x161FF` | 3,584 | `F128330E01595CBD0310D68E9271F5A80437CDE1903594784DEF728ADAE54C84` |
| `.idata` | `0x1E000` | `0x16200`–`0x171FF` | 4,096 | `118B86E5E72A3D5C124BD06F1ED5B6406408FBF0138EC1511769A8C7DC1456C4` |
| `.rdata` | `0x20000` | `0x17200`–`0x173FF` | 512 | `9C8A4B346C5DF43A9F90F5D15227C2DEA3E7DFABFBE8402BCBA85C3B2E9C84AE` |
| `.rsrc` | `0x23000` | `0x17400`–`0x433FF` | 180,224 | `C39E6F07D3C708F5061496746FA7CD4BE499EF4BBB390107382BB20E30AEE3D5` |

`.bss`, `.tls`, and `.reloc` have no raw file bytes in this image. Section
data ends at file offset `0x43400`; the remaining 96,445,123 bytes are an
appended setup-data overlay with SHA-256
`60AA03DB85A5ACCF7C76861570AF23C1332E08272F913AAEFF0646CC8E4D69BC`. The
overlay starts `7A 6C 62 1A 5D 00 00 80 ...`. The visible identifier
`Inno Setup Setup Data (5.3.3) (u)` occurs at `0x5BCA86C`, consistent with
`innoextract --info`.

The PE resource tree contains icon, string, RCDATA, group-icon, version, and
manifest resources. Its RCDATA names are `CHARTABLE`, `DVCLAL`, `PACKAGEINFO`,
and `11111`; no explicit IFPS/script resource was identified. A byte scan found
no raw `IFPS` magic in the overlay. It found many `MZ` byte pairs, but none
validated as an embedded PE header when `e_lfanew`, `PE\0\0`, and PE32/PE32+
optional-header magic were checked. The package contains application
executables in its packaged data; those files need not appear as uncompressed
nested PE headers in the setup overlay.

These observations distinguish the small executable loader sections from the
large appended installer-data area. They do not show that the overlay lacks
script bytecode; that area was not decoded as PascalScript by the tools above.

## Direct IFPS parser attempt

The local `ifpsdasm.exe` source opens the supplied file and calls
`IFPSLib.Script.Load`; it writes a `.txt` file only after successful parsing.
`Script.LoadCoreAttempt` rejects input whose first four bytes are not `IFPS`.
The 4.6 setup begins with the PE `MZ` header, so the whole executable is not a
directly parseable IFPS stream.

For a direct, non-mutating check, `ifpsdasm.exe` was pointed at the exact
hash-pinned setup. It returned `System.IO.InvalidDataException: Found invalid
data while decoding`; the predicted adjacent `.txt` path did not exist before
or after the attempt. No output file was created. This confirms only that the
PE container itself is not an IFPS bytecode file; it says nothing about IFPS
data compressed or embedded within the overlay.

The direct parser command was:

```powershell
ifpsdasm.exe "C:\path\to\RK_Keyboard_Software_Setup_V4.6_20261015.exe"
```

The PE evidence was gathered with `objdump -h`, `objdump -x`, and an entry
point disassembly of `.itext`, plus `pefile` section/resource parsing and a
raw overlay scan for `IFPS` and structurally valid nested PE headers.

The 4.06 scripts disassembled in the
[baseline script audit](rk-installer-uninstaller-script-audit.md) were
separate byte streams extracted from its installed `unins000.dat`. That
baseline has two IFPS-v23 records with callback bodies. The 4.6 installer
snapshot supplies neither such a generated uninstaller log nor an extracted
IFPS stream, so the baseline callback behavior cannot be attributed to 4.6.

## Limits and remaining evidence gap

- The PE/overlay scan, `innoextract`, and IFPSTools.NET do not expose 4.6
  callback bodies or the Inno event-dispatch table.
- No direct `.iss` source, compiled IFPS stream, or generated 4.6 uninstall
  log was recovered from the static package extraction.
- No script-free reconstruction of registry writes, shortcuts, destination
  rules, overwrite/delete conditions, or uninstaller behavior is established
  by the payload file list.
- The `InitSetup.dll` in this package is byte-identical to 4.06 and has a
  recursive cleanup export. Without the 4.6 script-to-helper callsite, its
  presence does not prove the 4.6 installer invokes it.

No runtime interception was attempted. The available local source tool's
described route to obtain the generated uninstaller executable requires
running setup; that route remains outside this offline audit.
