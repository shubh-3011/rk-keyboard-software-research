# 4.6 main-app Windows hook callsites

This is a static callsite and callback audit of the 4.6-labeled package's
`DeviceDriver.exe` (2,418,176 bytes; SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`). The
binary was not run, and no keyboard interface was opened. Addresses below are
specific to this exact image and must not be attributed to the 4.06 driver.

## Hook registrations

| Install callsite | Hook ID | Hook type | Callback | Scope evidence |
| --- | ---: | --- | ---: | --- |
| `0x0047EB09` | `5` | `WH_CBT` | `0x0047E8AA` | Current thread ID from `GetCurrentThreadId`; null module handle |
| `0x00489B62` | `-1` | `WH_MSGFILTER` | `0x004899A7` | Current thread ID from `GetCurrentThreadId`; null module handle |
| `0x004A11D7` | `7` | `WH_MOUSE` | `0x004A106B` | Current thread ID from `GetCurrentThreadId`; null module handle |
| `0x00553F43` | `7` | `WH_MOUSE` | `0x00553E84` | Current thread ID from `GetCurrentThreadId`; null module handle |

The callsite arguments resolve to the hook ID, callback, null `hmod`, and
current thread ID expected by `SetWindowsHookExW`. The five recovered
`CallNextHookEx` sites are `0x0047E8F4`, `0x0047EAA2`, `0x00489A00`,
`0x004A1087`, and `0x00553F0C`.

## Callback and unhook evidence

- The CBT callback at `0x0047E8AA` special-cases `nCode == 3`; its other
  forwarding path reaches `CallNextHookEx`.
- The message-filter callback at `0x004899A7` passes `nCode` and `lParam` to
  an object vtable slot at `+0x70` on a subset of paths (`nCode >= 0` or
  `nCode == 0x8001`); otherwise it forwards to the next hook.
- The mouse callback at `0x004A106B` has a special path for `nCode == 0` and
  `wParam == 0x0200`; other paths forward.
- The mouse callback at `0x00553E84` filters `wParam` values `0x00A1`,
  `0x00A4`, `0x00A7`, `0x0201`, `0x0204`, and `0x0207` before its forwarding
  path.
- Direct `UnhookWindowsHookEx` sites are `0x0047CB92`, `0x0047EAB6`,
  `0x004A11EF`, and `0x00553F60`. The two `+0x28` object-field unhook sites
  cannot yet be paired conclusively with the single recovered CBT
  registration. No direct unhook site for the message-filter registration
  was identified in this pass.

These are code-path observations, not proof that a hook is installed in a
normal session or that a particular user-facing feature triggers it. The
direct hook set contains no `WH_KEYBOARD` (`2`) or `WH_KEYBOARD_LL` (`13`)
registration. That does not prove the program never observes keyboard-related
input: `WH_MSGFILTER` is thread-routed, and the binary also imports key-state
APIs. Callback reachability and the meaning of the `+0x70` dispatch remain
unresolved.

## Reproduction and version boundary

The four `SetWindowsHookExW`, five `CallNextHookEx`, and four
`UnhookWindowsHookEx` transfer candidates are listed in
[`rk-v4.6-native-api-call-sites.csv`](rk-v4.6-native-api-call-sites.csv),
rows 1408–1416 and 1511–1514. The static callsite scan is a candidate ledger,
not a complete control-flow graph. This analysis complements the separate
[4.06 hook audit](rk-406-windows-hook-callsite-audit.md); the two versions'
hook identifiers match, but their addresses and callback bodies are
version-specific.
