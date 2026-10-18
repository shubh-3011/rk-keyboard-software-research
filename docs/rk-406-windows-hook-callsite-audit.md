# 4.06 main-app Windows hook callsites

This is a static callsite audit of the 4.06 snapshot's `DeviceDriver.exe`
(`SHA-256 c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`).
It resolves the four direct `SetWindowsHookExW` references listed in
[`rk-native-api-xrefs.csv`](rk-native-api-xrefs.csv). No executable was run and
no keyboard interface was opened.

## Recovered registrations

| Callsite | Hook ID | Hook type | Callback | Scope / static result |
|---|---:|---|---:|---|
| `0x0047735D` | `5` | `WH_CBT` | `0x004770FE` | `dwThreadId` is obtained from `GetCurrentThreadId`; thread-specific |
| `0x0048244D` | `-1` | `WH_MSGFILTER` | `0x00482292` | `dwThreadId` is obtained from `GetCurrentThreadId`; thread-specific |
| `0x00499CDC` | `7` | `WH_MOUSE` | `0x00499B70` | `dwThreadId` is obtained from `GetCurrentThreadId`; thread-specific |
| `0x0054C7B2` | `7` | `WH_MOUSE` | `0x0054C6F3` | `dwThreadId` is obtained from `GetCurrentThreadId`; thread-specific |

Each recovered callback reaches `CallNextHookEx` to continue hook-chain
processing. The reference inventory reports `UnhookWindowsHookEx` calls at
`0x004753E6`, `0x0047730A`, `0x00499CF4`, and `0x0054C7CF`, plus indirect
references at `0x00482CD0` and `0x004B3BAB`. This audit does not infer a
registration-to-unhook pairing from proximity alone.

## Input-observation limit

Among these four direct registrations there is no `WH_KEYBOARD` (`2`) or
`WH_KEYBOARD_LL` (`13`) registration. `WH_MSGFILTER` can observe messages in
the thread's menu/dialog message-filter context, so it is not accurate to say
that every kind of input observation is absent. The static sites alone do not
establish callback reachability, what messages are accepted, whether key data
is inspected, or whether any hook was active in a normal session. The binary
also imports key-state APIs; see the input-related entries in
[`rk-native-api-imports.md`](rk-native-api-imports.md).

These addresses apply only to the hashed 4.06 binary. They must not be
transferred to the separately hashed 4.6 `DeviceDriver.exe`.
