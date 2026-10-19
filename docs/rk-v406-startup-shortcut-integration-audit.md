# RK 4.06 Startup shortcut integration audit

## Scope and evidence

This offline static follow-up traces the host startup-shortcut workflow in the
installed RK Keyboard Software 4.06 main executable, `DeviceDriver.exe`,
SHA-256 `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`
(2,326,528 bytes). The installed `Cfg.ini` is SHA-256
`1a9796e706fa64b1821417efda080d481e202ffcf941aa97e6a78efe3a32badd`.
Addresses below are VAs in that exact x86 executable.

The app was not launched. No startup shortcut was created or deleted, no
registry value was read or changed by this audit, and no keyboard, serial,
updater, or firmware interface was opened. **Proven** means present in the
hash-pinned binary or installed data; **inferred** describes a relationship
supported by local static control/data flow; **unresolved** marks behavior
that the static evidence does not establish.

## UI event to host shortcut action

**Proven:** the dialog event routine at `0x00403270` compares its incoming
second argument against the HWND stored at offset `+0x20` in the custom
control object at `this+0x6D4`. The constructor at `0x00402914` initializes
that control object and uses the `check_dn.png`, `check_ov.png`, and `check_nr.png`
assets (string VAs `0x005C7EE8`, `0x005C7F04`, and `0x005C7F20`). The adjacent
HWND field at `this+0x6F4` is used by the window-refresh path at
`0x00401E94`–`0x00401F1A`. The localization registration loop formats
`tc_adv_str%d` and places each localized string in a pointer table; the
`tc_adv_str12` slot is `0x0062B75C`, loaded in the nearby refresh path at
`0x00401EFF`. Installed English `Text/en/text.xml` maps `tc_adv_str12` to
`AUTORUN`. Together, these facts strongly associate the check-style control
and adjacent label with the AutoRun setting. The exact constructor-to-label
field binding is inferred from the adjacent object layout and refresh path.

When that child handle matches, `0x00403270` computes the inverse of the
host-side DWORD at `this+0x77C`, compares it with the control state at
`this+0x6D4+0xA8`, updates the control state if they differ, and invalidates
the control window. It then branches on the original `this+0x77C` value:

| Condition | Call | Static effect |
| --- | --- | --- |
| `this+0x77C != 0` | `0x00404AC0` | Builds and saves a Startup-folder `.lnk` file. |
| `this+0x77C == 0` | `0x00404BB0` | Builds the same `.lnk` path and calls `DeleteFileW`. |

The branch condition and helper targets are proven by direct relative calls
at `0x00403342` and `0x0040334C`. The exact meaning/polarity of the
`this+0x77C` flag, how its initial value is obtained, and whether the check
control's internal state uses conventional checked/unchecked polarity are
unresolved. The installed configuration contains no `AutoRun` key, but that
does not rule out a runtime-derived state or another persistence location.

## Shortcut creation details

**Proven:** helper `0x00404AC0` calls `SHGetSpecialFolderLocation` at
`0x00404ADC` with folder ID `7` (`CSIDL_STARTUP`), then converts the returned
PIDL with `SHGetPathFromIDListW` at `0x00404AF7`. It formats the shortcut
filename with `%s\\%s.lnk` at string VA `0x005C8654`, using the resolved
Startup path and a runtime string at global `0x00611380`. That runtime string
is not identified here as a literal model or product name.

The helper obtains the current executable path using
`GetModuleFileNameW(NULL, ...)` at `0x00404B6A`, and builds an icon path from
the `%sappico.ico` format at `0x005C8668`. It passes the current executable
path to the Shell Link `SetPath` vtable method (`+0x50`) at `0x004049F2`,
passes the literal `-s` at `0x005C8684` to `SetArguments` (`+0x2C`) at
`0x00404A08`, and passes the icon path to `SetIconLocation` (`+0x44`) at
`0x00404A1A`. It queries `IPersistFile` using the IID at `0x005C7374` and
calls `Save` (`+0x18`) with the formatted `.lnk` path and `fRemember=1` at
`0x00404A61`.

The COM setup in this helper calls `CoInitialize(NULL)` at `0x004049CB`,
creates the Shell Link coclass `{00021401-0000-0000-C000-000000000046}`
through `CoCreateInstance` at `0x004049E4`, and calls `CoUninitialize` at
`0x00404A7E`. The embedded interface ID at `0x005C7334` is
`IShellLinkW` `{000214F9-0000-0000-C000-000000000046}`. The `-s` argument's
meaning to `DeviceDriver.exe` is not established by this shortcut path.

## Shortcut deletion details

**Proven:** sibling helper `0x00404BB0` obtains the same `CSIDL_STARTUP`
folder, formats the same `%s\\%s.lnk` path using global `0x00611380`, and
calls the `DeleteFileW` import thunk at `0x00404C2B`. This path deletes the
shortcut file; it does not call a registry deletion API. Static code does not
show whether a missing file or deletion error is surfaced to the user.

The main PE also contains registry APIs for other workflows. This focused
trace establishes a Startup-folder shortcut mechanism for this AutoRun-related
control; it does not prove that the whole program has no other autorun,
registry, scheduled-task, service, or externally installed startup path.

## Finding and limits

- **Proven statically:** the AutoRun-labeled UI region is associated with a
  check-style child control; its handler branches to a `CSIDL_STARTUP`
  Shell Link create/save helper or a sibling helper that deletes the `.lnk`.
- **Inferred:** the created link targets the current `DeviceDriver.exe`,
  includes `-s`, and uses an `appico.ico` path assembled from runtime path
  data. The shortcut file is the persistent host-side artifact of this
  specific create/delete path.
- **Unresolved:** the `this+0x77C` flag's polarity and initialization,
  runtime resolved shortcut filename/path, `-s` command-line semantics,
  actual OS handling of the shortcut, and whether other startup mechanisms
  exist elsewhere in the suite.

This complements the 4.6 COM/OLE activation report. Its address set is from
4.06 and should not be mixed with the 4.6 callsite addresses.
