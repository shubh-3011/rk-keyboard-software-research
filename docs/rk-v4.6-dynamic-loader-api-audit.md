# V4.6 dynamic loader API call paths

## Scope and evidence boundary

This static follow-up maps the direct `LoadLibraryA` and `GetModuleHandleA`
callsites in the 4.6-labeled package's `DeviceDriver.exe` and checks their
roles against the installed 4.06 main driver. The 4.6 PE is 2,418,176 bytes,
SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`; the
4.06 comparison PE is 2,326,528 bytes, SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
Addresses below are virtual addresses in the 4.6 image.

The 4.6 import callsite ledger records three direct `LoadLibraryA` calls and
four direct `GetModuleHandleA` calls. The analysis is static: it does not show
that any branch executes on this PC or that any dynamically resolved API is
used with a connected keyboard. The hash-pinned callsite rows are in
[`rk-v4.6-native-api-call-sites.csv`](rk-v4.6-native-api-call-sites.csv).

## `LoadLibraryA`

| Callsite and callers | Static argument and result flow | Limit |
| --- | --- | --- |
| Wrapper call at `0x0047B2D1`, wrapper starts `0x0047B298`; callers `0x0047E27D` and `0x005552EC` | The first caller passes `hhctrl.ocx`, caches the handle at object `+4`, and resolves `HtmlHelpW`; if export lookup fails, the code frees and clears the module. The second passes `RICHED20.DLL` and caches its handle at object `+0x24`. An adjacent method uses the wide `RichEdit` literal through an object vtable. | The call and export flow are present; a complete activation/ownership path for the RichEdit object is not established. |
| `0x00589870`, caller `0x0057CE8E` | Loads fixed `USER32.DLL`, then resolves `MessageBoxA`, `GetActiveWindow`, `GetLastActivePopup`, `GetUserObjectInformationA`, and `GetProcessWindowStation`. Encoded pointers are cached in globals `0x00620310`–`0x00620320` and decoded by helpers `0x0057D688`/`0x0057D703`; later code consumes the helpers and may call `MessageBoxA`. | The function's window-station checks and potential message-box path are mapped. Its modal/error purpose is an inference; runtime branch behavior is unknown. |
| Delay-load resolver call `0x00590BB1` | The shared helper uses the descriptor at `0x006027F0`, whose DLL-name RVA resolves to `OLEACC.dll`; the INT names `AccessibleObjectFromWindow`, `LresultFromObject`, and `CreateStdAccessibleObject`. The helper resolves and stores the target in the corresponding delay-IAT slot. | This is the descriptor-driven delay-load path, not evidence that the accessibility APIs were called during a run. See the [OLEACC delay-load audit](rk-main-delayload-api-audit.md). |

## `GetModuleHandleA`

| Callsite(s) | Static argument and result flow | Limit |
| --- | --- | --- |
| `0x0047864C` and `0x00478688` | Look up `GDI32.DLL`, then resolve `GetLayout` and `SetLayout`. The first wrapper invokes `GetLayout` with object field `[ESI+4]`; if unavailable it sets error 120 and returns `-1`. The second invokes `SetLayout` with `[ESI+4]` and a caller value. | These are optional GDI layout wrappers. Their use in a particular UI flow is not established. |
| `0x0056EFF4` | Looks up `KERNEL32.DLL`, resolves and calls `GetUserDefaultUILanguage`, masks the result with `0x3ff`, and compares it with `0x11`. The matching branch passes `MS UI Gothic` to a font helper. | Japanese UI-font handling is inferred from the locale comparison and font name; no runtime locale was observed. |
| `0x0058628F` | Looks up `KERNEL32.DLL`, resolves and calls `IsProcessorFeaturePresent` with argument 0. If unavailable, the helper falls back to a local numeric/FPU check; its caller stores the result at `0x0061F7F8`. | The fallback shape is proven statically; the exact runtime CPU path is not. |

## 4.06 comparison and limits

The installed 4.06 driver has matching loader roles at different addresses:
the `hhctrl.ocx`/`RICHED20.DLL` wrapper is at `0x00473B25`, the USER32 helper
is at `0x00582150`, the GDI layout lookups are at `0x00470EE7` and
`0x00470F23`, and the language/processor checks use the same named exports.
The shared OLEACC delay-load helper is at `0x00589485`. In this slice, the
4.6 callsite counts and roles match 4.06; addresses and data locations moved
with the binary. No added loader API or defensible feature delta was found.

These findings are instruction and data-flow evidence, not a complete control-
flow proof. The disassembly is a linear sweep; indirect callers, branch
execution, module lifetime outside the traced objects, operating-system
availability, and actual user-visible effect remain unresolved. No RK
application or keyboard interface was opened and no device data was sent.
