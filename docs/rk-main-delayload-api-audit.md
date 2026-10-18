# DeviceDriver.exe delay-loaded accessibility API paths

## Scope and evidence

This is an offline static follow-up for the three `OLEACC.dll` delay imports
in the installed RK Keyboard Software 4.06 `DeviceDriver.exe`. The installed
file is 2,326,528 bytes with SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`, matching
the [installed package manifest](rk-installed-package-manifest.csv). I checked
the delay-import descriptor and name table with GNU `objdump -s`, the loader
helper with `objdump -d`, and compared the thunk/caller addresses with the
[native API cross-reference](rk-native-api-xrefs.csv). No RK executable was
launched, and no device interface was opened.

## Delay-import descriptor and names

The descriptor begins at VA `0x005F90BC`. With preferred image base
`0x00400000`, its RVA-based fields decode as follows:

| Descriptor field | RVA | VA / value |
| --- | ---: | --- |
| Attributes | `0x00000001` | RVA-based descriptor |
| DLL name | `0x001C7BE0` | `0x005C7BE0`, ASCII `OLEACC.dll` |
| Module-handle slot | `0x00209A48` | `0x00609A48` |
| Import Address Table (IAT) | `0x00203D20` | `0x00603D20` |
| Import Name Table (INT) | `0x001F90FC` | `0x005F90FC` |
| Bound IAT | `0x001F915C` | `0x005F915C` |
| Unload IAT / timestamp | `0` / `0` | Empty |

The INT entries at `0x005F90FC`, `0x005F9100`, and `0x005F9104` point to
hint/name records for `AccessibleObjectFromWindow`, `LresultFromObject`, and
`CreateStdAccessibleObject`, in that order. They correspond to IAT slots
`0x00603D20`, `0x00603D24`, and `0x00603D28`. The on-disk IAT initially points
to resolver stubs `0x0058936F`, `0x0058937F`, and `0x0058934E`, respectively.

## Resolver and transfer path

Each first-call stub loads its own IAT-slot VA and reaches shared entry
`0x00589358`. That entry passes the slot address and descriptor VA
`0x005F90BC` to helper `0x0058938F`; after the helper returns, `0x00589367`
tail-jumps through the returned function pointer. In the helper:

- The descriptor's DLL-name RVA is rebased and saved as the module-name
  argument. At `0x00589485`, the code calls `LoadLibraryA` through IAT VA
  `0x0059E394` with that argument, which resolves to `OLEACC.dll`.
- The helper uses the passed IAT-slot offset to select the corresponding INT
  entry, skips its two-byte hint, and supplies that entry's name as the
  `GetProcAddress` export argument at `0x0058955C` (IAT VA `0x0059E3FC`).
- On successful lookup, `0x005895A3` writes the resulting address through the
  passed IAT-slot pointer. The helper returns it, and the shared stub at
  `0x00589367` tail-jumps to it. Thus the resolved export is invoked by the
  delay thunk's tail transfer, not by the `0x00589580` call through the
  separate function-pointer global `0x00609A50`.

The three API entry paths and statically recorded callers are:

| API | IAT slot | Resolver stub | Resolved IAT thunk | Direct caller(s) in `DeviceDriver.exe` |
| --- | ---: | ---: | ---: | --- |
| `AccessibleObjectFromWindow` | `0x00603D20` | `0x0058936F` | `0x00589379` | `0x005035CD` |
| `LresultFromObject` | `0x00603D24` | `0x0058937F` | `0x00589389` | `0x00477DFB`, `0x00477E23` |
| `CreateStdAccessibleObject` | `0x00603D28` | `0x0058934E` | `0x00589369` | `0x0047348A` |

The caller paths and IAT ordering agree with the three delay-import rows in
the native API cross-reference. These observations identify the static
resolver arguments, slot-to-export mapping, and local dispatch route. They do
not prove that Windows loads the DLL, that a guarded branch runs, or that any
accessibility API executes in a session.

## Import-gap status

The 32 `DeviceDriver.exe` entries in the
[direct-call gap inventory](rk-native-api-callsite-gaps.csv) have no unresolved
invocation row in the existing [indirect-call audit](rk-native-api-indirect-call-audit.md).
This note additionally closes the export-name and returned-pointer route for
the helper's `LoadLibraryA` and `GetProcAddress` calls at `0x00589485` and
`0x0058955C`. Other open dynamic-loader questions are tracked separately in
the [dynamic API resolution audit](rk-dynamic-api-resolution-audit.md); this
does not close every dynamic resolver, callback, or full-program call-graph
question in the main executable.
