# RK 4.6 profile-persistence wrappers and toolbar layout writes

This is a bounded static audit of two profile-writing methods and their direct
callers in the hash-pinned `DeviceDriver.exe`. It establishes generic host
profile persistence and selected UI layout keys. It does not identify these
values as keyboard settings or device data.

## Binary and reproduction

- SHA-256: `8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`
- Size: 2,418,176 bytes; PE32 image base `0x00400000`.
- Evidence: [`rk-v4.6-profile-persistence-wrapper-evidence-2026-10-25.csv`](rk-v4.6-profile-persistence-wrapper-evidence-2026-10-25.csv)
- Verifier: [`audit_rk46_profile_persistence.py`](../scripts/audit_rk46_profile_persistence.py)
- Run: `python scripts/audit_rk46_profile_persistence.py`

## Wrapper behavior

The wrappers at `0x00489437` and `0x004894C0` select a registry-backed profile
when `[ECX+0x54]` is non-null; a null field takes the INI branch using
`[ECX+0x68]` as the path passed to `WritePrivateProfileStringW`. The shared
registry helper opens `HKCU\\software`, creates the subkey named by
`[this+0x54]`, then the subkey named by `[this+0x68]`; the caller adds the
section as a final subkey. This flow and its addresses are explicit in the
bytes, while whether either mode is selected at runtime is unknown.

| Wrapper | Parameters on the x86 stack | Registry branch | INI branch |
|---|---|---|---|
| `0x00489437` | section `[+8]`, entry `[+0xC]`, 32-bit value `[+0x10]` | `RegSetValueExW(sectionKey, entry, 0, REG_DWORD=4, &value, 4)`; closes the section key and returns a zero-status test as BOOL. If section-key creation fails, the observed path returns the input value. | Formats the value with `%d` into a 16-byte local buffer, then calls `WritePrivateProfileStringW(section, entry, formattedValue, [this+0x68])`. |
| `0x004894C0` | section `[+8]`, nullable entry `[+0xC]`, nullable string `[+0x10]` | Null entry calls `RegDeleteKeyW(sectionKey, section)` through the profile root helper. Non-null entry plus null string calls `RegDeleteValueW(sectionKey, entry)`. Both non-null call `RegSetValueExW(sectionKey, entry, 0, REG_SZ=1, string, (lstrlenW(string)+1)*2)`. The three registry API status values are converted to success booleans; failure to open/create the section returns 0. | Calls `WritePrivateProfileStringW(section, entry, string, [this+0x68])`, preserving the Win32 API return value. Null entry/value therefore request section deletion using the standard profile API convention. |

The API destinations are imports at IAT addresses `0x005A6000`
(`RegOpenKeyExW`), `0x005A6018` (`RegCreateKeyExW`), `0x005A601C`
(`RegSetValueExW`), `0x005A6024` (`RegCloseKey`), `0x005A6030`
(`RegDeleteKeyW`), `0x005A6034` (`RegDeleteValueW`), and `0x005A6484`
(`WritePrivateProfileStringW`). The report’s verifier checks their import
names and exact wrapper call instructions.

## Direct caller evidence

### Standard profile value

At `0x00486975`, code passes section `Settings` (`0x005A9DDC`), entry
`PreviewPages` (`0x005A9DF0`), and `[this+0x94]` to `0x00489437`. The call is
guarded by a nonzero check on that field. A containing method at
`0x0048697C` calls this helper at `0x004869A5` on one conditional branch. This
proves the literal key/value-source path in the image; it does not establish
that the branch executes or that the field is semantically a page count.

### Toolbar layout state

The aggregate writer at `0x00497E65` receives a caller-provided section prefix.
The direct call at `0x004882AE` supplies a string returned through helper
`0x00434C70`; the exact prefix value is state-dependent. It iterates its
toolbar collection, calling the per-toolbar writer at `0x00496FF4` from
`0x00497EA9` with the prefix and zero-based index.

The per-toolbar writer formats a section as `%s-Bar%d` (`0x005ABC38`), then
calls `0x004894C0` at `0x00497077` with null entry and value to clear that
section before rewriting it. Its 18 direct `WriteProfileInt` callsites record:

| Profile entry | Value source / gate |
|---|---|
| `BarID` | `[bar+0x00]` |
| `Visible` | literal 0, only when `[bar+0x04] == 0` |
| `Horz`, `Floating` | `[bar+0x0C]`, `[bar+0x08]`, when `[bar+0x08] != 0` |
| `XPos`, `YPos`, `MRUWidth` | `[bar+0x14]`, `[bar+0x18]`, `[bar+0x1C]`; omitted at their sentinel values (`-1`, `-1`, `0x7FFF`) |
| `Docking` | `[bar+0x20]`, when nonzero |
| `MRUDockID`, `MRUDockLeftPos`, `MRUDockRightPos`, `MRUDockTopPos`, `MRUDockBottomPos` | `[bar+0x24]` through `[bar+0x34]` in four-byte steps |
| `MRUFloatStyle`, `MRUFloatXPos`, `MRUFloatYPos` | `[bar+0x38]`, `[bar+0x3C]`, `[bar+0x40]` |
| `Bars` | `[bar+0x4C]`, only when greater than 1 |
| `Bar#%d` | one value per item from the collection reached through `[bar+0x44]`; loop runs for `[bar+0x4C]` items |

Those keys are in each `%s-Bar%d` section. The aggregate writer separately
uses `%s-Summary` (`0x005ABC4C`) and writes `Bars` as the number of per-toolbar
writers that returned nonzero, plus `ScreenCX` and `ScreenCY` from the width
and height outputs of helper `0x00497460`. These are host UI layout records;
the exact prefix, runtime collection contents, and actual writes are not
observed. The row-level callsite/value-source evidence is in the CSV.

## Boundary and remaining gaps

These wrappers route the mapped writes to Windows registry/profile APIs. This
slice documents generic desktop configuration and toolbar layout; it does not
establish that these values are keyboard settings or keyboard-device writes.
It also does not exhaust all behavior of the containing UI methods.

The verifier finds 22 relative-call encodings to `0x00489437` and one to
`0x004894C0` in executable sections. This is a bounded static byte census,
not a validated complete call graph, runtime reachability proof, or inventory
of calls made through unresolved function pointers. It does not prove branch selection,
registry/INI configuration, API success, exact prefix contents, serialized
toolbar values, or any device effect.
