# V4.6 generated UI labels and knob profile path

## Scope

This static follow-up traces the added knob and screen labels from the 4.6
locale catalog into the main driver's generated UI strings, then follows the
knob profile fields into selected application state and the existing worker
dispatch. The exact main driver is 2,418,176 bytes with SHA-256
`8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
No RK software was launched and no keyboard interface was opened.

## Generated localized labels

The locale comparison records seven added text keys per locale:
`tc_knob1`–`tc_knob4`, `tc_adv_str44`, `tc_screen22`, and `tc_screen23`.
The 4.6 UI builder uses three indexed loops to resolve and create the relevant
items:

| Key family | Loop range | Static code path | Observed English values |
| --- | --- | --- | --- |
| `tc_adv_str%d` | 1–44 | `0x00447AD0`–`0x00447B5A`; format string VA `0x005DCD04` | `tc_adv_str44`: “Enable 24-hour time format” |
| `tc_screen%d` | 1–23 | `0x00447DE0`–`0x00447E7A`; format string VA `0x005DCD84` | `tc_screen22`/`tc_screen23`: preset GIF and download prompt |
| `tc_knob%d` | 1–4 | `0x00447F20`–`0x00447FBA`; format string VA `0x005DCDB4` | Volume; Keyboard brightness; Mouse wheel; Arrow keys |

Each loop formats an indexed key through helper `0x00575B4E`, resolves its
localized text through `0x00405ED0`, and constructs/stores an item through
`0x00443F00` and `0x00405B20`. This establishes that the added strings are
consumed by the V4.6 UI builder. It does not identify a unique visible control
or its MFC message-map owner.

## Knob profile and state flow

The profile parser reads `KnobIndex` (string VA `0x005DEFD8`) into global
`0x0062A274` and `KnobDef` (string VA `0x005DEFEC`) into global `0x0062A278`.
The extracted catalog has eight profiles with these fields:

| Profile | Name | `KnobIndex` | `KnobDef` |
| --- | --- | ---: | ---: |
| `02FE` | RK L75 | 86 | 0 |
| `0300` | RK L75 | 91 | 0 |
| `02EB` | RK R104Pro | 107 | 0 |
| `02EC` | RK R104Pro | 108 | 0 |
| `02ED` | RK R104Pro | 108 | 0 |
| `02F2` | RK R104Pro | 112 | 0 |
| `02F4` | RK R104Pro | 108 | 0 |
| `02F6` | RK S104 Keyboard | 101 | 0 |

At `0x00461798`–`0x00461800`, code compares a selected profile row with
`KnobIndex` and selects one of four knob-related globals based on object byte
`this+0x5EBF`. Method `0x0041CF20` reads the profile fields, copies a 16-byte
row selected by `KnobIndex`, and, when queue gate `0x0062A234` is nonzero,
queues signal value `2` through `0x00401100` before calling profile mutator
`0x0041EC50`. The existing settings-worker audit maps queued signals through
the active device's virtual `ApplySetting` route; see the
[UI-to-worker signal audit](rk-v4.6-ui-setting-signal-audit.md) and
[G5 settings audit](rk-v4.6-cdevg5-settings-and-vtable-audit.md).

## MFC message route into the knob handler

The 4.6 `CKeyDlg` MFC message-map descriptor at `0x005D4CA0` includes private
message `0x477`, signature byte `0x0E`, and handler `0x0041CF20`; the class
identity is `.?AVCKeyDlg@@` at `0x0061A158`. The handler takes the route only
when its second message argument equals `2` and the first argument has a
nonzero `0xFF00` mask. On that branch it copies the `KnobDef` byte to
`this+0x5EBF`, selects the 16-byte record indexed by `KnobIndex`, conditionally
queues signal `2` through `0x00401100`, then calls profile mutator
`0x0041EC50`.

Two functions post message `0x477` through `PostMessageW`:

| Post site | Window / `wParam` / `lParam` source | Limit |
| --- | --- | --- |
| `0x00435A23` in `0x00435A00` | `hwnd=this+0x74`; `wParam` comes from a `0x58`-byte row at `this+0x88`; `lParam=this+0x14D8` | The object and row are not tied to a generated knob control; the posted `lParam` is not proven to equal `2`. |
| `0x00436686` in `0x00436660` | `hwnd=this+0x1E8`; `wParam` comes from a `0x58`-byte row at `this+0x1F8`; `lParam=this+0x1328` | The object and row are not tied to a generated knob control; the posted `lParam` is not proven to equal `2`. |

This closes the `0x477` message-map-to-handler and post-site evidence, but not
the visible knob-control origin. The generated localized labels do not prove
that either sender represents a knob selection, nor which model accepts the
queued settings operation.

## What remains open

The generated item loops do not prove which MFC control owns a knob label, the
exact visible control-to-sender route, or that a particular profile's branch
runs. The package values and worker route do not establish an accepted
keyboard command or a physical knob effect. The locale delta remains the
source for file-level string and package comparisons:
[4.06-to-4.6 localization audit](rk-localization-delta-v4.06-v4.6.md).
