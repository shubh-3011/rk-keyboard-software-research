# RK 4.06 language-module loader API follow-up

## Scope and evidence

This static follow-up resolves the generated-name and caller-purpose gap for
the `DeviceDriver.exe` `LoadLibraryW` call at `0x0047F568`. The inspected
installed binary is 2,326,528 bytes with SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
The existing dynamic API audit listed this call as loading a runtime-built
wide string from `[EBP-0x230]`; this note follows its in-image caller chain
and the source of that string.

Evidence is static x86 disassembly and read-only data from that hash-pinned
PE, using GNU `objdump`. It establishes instruction arguments and local data
flow, not that a candidate language branch runs or that any candidate DLL is
present or loaded on a particular system.

## Call path and generated DLL name

The path is:

```text
0x0047FABF -> 0x0047F84E -> 0x0047F4B4 -> LoadLibraryW at 0x0047F568
```

- Method `0x0047FABF` calls imported `GetModuleFileNameW` at `0x0047FAE7`
  with the module handle at object offset `+0x44`, output buffer
  `[EBP-0x220]`, and capacity `0x104` characters. It then calls imported
  `PathFindExtensionW` at `0x0047FAFD` and writes a terminating NUL at the
  extension pointer, leaving a module path stem.
- The method copies the UTF-16 format string at `0x005A2250`, `%s%s.dll`,
  into a local format buffer and calls `0x0047F84E` at `0x0047FB21`, passing
  that format and the path stem. The references to method address
  `0x0047FABF` in read-only data at `0x005A231C` and `0x005A248C` establish
  stored function-pointer references. No direct `CALL`/`JMP` caller for
  `0x0047FABF` was recovered, so the higher-level dispatch edge remains
  unresolved.
- `0x0047F84E` obtains the optional `GetUserDefaultUILanguage` and
  `GetSystemDefaultUILanguage` exports through `GetProcAddress` calls at
  `0x0047F89C` and `0x0047F903`, using the literal names at `0x005A2218`
  and `0x005A21FC`. The nonzero getter results are passed through the
  imported `ConvertDefaultLocale` pointer before being added to a local
  candidate list. If the user-language path is unavailable or returns zero,
  a fallback branch queries the language for `ntdll.dll` resource type
  `RT_VERSION` (integer type 16), resource ID 1, through
  `EnumResourceLanguagesW` at `0x0047F96D`. Its callback `0x0047EF25`
  copies the callback's `wLanguage` into one local `WORD` and returns `TRUE`;
  repeated callbacks overwrite that same word. The precise enumeration order
  and selected value are runtime-dependent.
- After the ordinary language candidates, `0x0047F84E` appends the special
  value `0x800` to the same list at `0x0047F9C7`. It calls `0x0047F4B4` at
  `0x0047FA90` for each candidate, passing the format, path stem, and
  candidate value.
- `0x0047F4B4` calls imported `GetLocaleInfoW` at `0x0047F4FB` for ordinary
  candidates, with `LCID`, `LOCALE_SABBREVLANGNAME` (`0x3`), a four-WCHAR
  output buffer, and capacity 4. Candidate `0x800` takes a separate branch
  that passes the literal UTF-16 text `LOC` at `0x005A2140` through a bounded
  string helper, then through a check/dispatch helper at `0x004058E0` before
  joining the common formatting path. This is consistent with a `LOC` suffix,
  but the helper's return/error semantics have not been fully resolved. For
  ordinary candidates, the format `%s%s.dll` combines the module path stem
  and language abbreviation into `[EBP-0x230]`. The helper rejects a failed
  or over-capacity format result before the loader call.
- `LoadLibraryW` at `0x0047F568` receives the constructed buffer. A
  successful module handle returns to the candidate loop, which stops at
  the first nonzero result; failed candidates allow the loop to try the
  next list entry.

## Interpretation and limits

The proven static behavior is a language-specific module search derived from
the filename of the module handle stored at object offset `+0x44`. Ordinary
candidate names use a locale abbreviation followed by `.dll`. A final
`0x800` candidate takes the separate `LOC` string path described above; its
exact generated name remains less certain because the intervening check/
dispatch helper is unresolved. The source does not prove which candidate is
selected or that any such DLL is shipped with the RK package. This is
consistent with a localized resource-module lookup, but that higher-level
purpose is an inference from the path construction and language enumeration.

The call trace does not establish a HID/device operation, keyboard model,
runtime locale, successful `LoadLibraryW`, resource use after loading, or
cleanup ownership for a returned module handle. The indirect caller of
`0x0047FABF`, resource-enumeration outcomes, and actual candidate path remain
open. No application was launched and no device interface was accessed.
