# RK 4.06 forwarded text receivers: five concrete caller paths

## Scope and result

This static follow-up traces five previously unclassified `+0x68` dispatch
sites through their callers. On the paths listed below, their receivers are
local GDI text adapters constructed by `0x0047105C`, whose vptr is
`0x0059F314`. Its slot `+0x68` contains `0x0047111A`, which forwards four
arguments and the object's HDC through IAT `0x0059E6B8` to
`USER32!DrawTextW`, then returns with `ret 0x10`.

The exact input is
`C:\Users\shubh\Downloads\sshorcale\_rk_analysis\inputs\DeviceDriver.exe`,
SHA-256
`C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6`.
All addresses are VAs in that PE. The binary is not distributed here.
The input was read as bytes and disassembled; neither it nor keyboard
software was executed, and no HID/device interface was opened.

These are **caller-scoped resolutions**. The listed direct-call and
message-map/vtable paths establish the target when they supply the examined
adapter. Alternate callers, other receiver types, actual Windows message
delivery, and runtime target choices remain unknown. This report does not
prove a complete call graph or a caller of G5 `GetRealData`.

The [five-row CSV](rk-406-forwarded-text-receivers.csv) records the paths and
limits. The [hash-pinned verifier](../scripts/audit_rk406_forwarded_text_receivers.py)
checks selected exact instruction chains, stack-offset arithmetic, owner RTTI,
vtable slots, MFC map bytes, and the adapter/import mapping. Its straight-line
stack fragments deliberately contain no calls; interprocedural interpretation
also uses the displayed prologues, return cleanup, and conventional preservation
of x86 nonvolatile registers. It is not a general symbolic executor.

## Why the receiver origins were missed

Two dispatches receive the adapter through a custom owner virtual method, one
receives it in a compiler-private `EBX` argument, and two receive it through a
stack argument to a helper. A constructor need not appear in the function
containing the final text call. Raw `[esp+offset]` operands also refer to
different frame locations as arguments are pushed or cleaned up.

In each local calculation below, `S` is ESP at a stated stable point in the
caller. For the helper prologues, `E` is ESP on function entry, pointing to the
return address. These bases must not be mixed.

## Shared paint path: `0x004344FA` and `0x00466F58`

The two owner classes and their static routing evidence are:

- `CMenuSrDlg`: constructor store `0x004341C5` installs vptr `0x005D22AC`.
  Its preceding COL pointer is `0x005E4070`, which links to type descriptor
  `0x0060395C` and the name `.?AVCMenuSrDlg@@`. Owner vtable slot `+0x144`,
  at `0x005D23F0`, contains `0x00434350`. Its message-map accessor at
  `0x00434240` returns `0x005D22A0`.
- `CFrameEditView`: initialization store `0x0046AEC9` installs vptr
  `0x005D9BEC`. COL `0x005E4934` links to descriptor `0x00603C30` and name
  `.?AVCFrameEditView@@`. Owner slot `+0x144`, at `0x005D9D30`, contains
  `0x00466C40`. Its map accessor at `0x00466C30` returns `0x005D9BE0`.

Both own map structures point to base-map getter `0x00455780`. It returns
`0x005D79A8`, whose entry pointer is `0x005D7900`. The first six-DWORD row is
`{0x000F, 0, 0, 0, 0x13, 0x00455790}`: an MFC `WM_PAINT` entry with handler
`0x00455790`. This establishes a static message-map route; message delivery
was not observed.

In the shared handler, `lea ecx,[esp+0x24]` at `0x004557F4` passes the local
adapter to constructor `0x0047105C` at `0x004557F8`. At the owner dispatch:

```text
00455868  push ecx                       ; owner field +0x68
00455869  push edx                       ; owner field +0x64
0045586A  mov edx,[eax+0x144]             ; owner virtual method
00455870  lea ecx,[esp+0x2c]              ; (S-8)+0x2c = S+0x24
00455874  push ecx                       ; first explicit argument = adapter
00455875  mov ecx,esi                     ; owner object
00455877  call edx
```

With the first owner vptr, that slot reaches `0x00434350`. This function has
an EBP frame, loads `EDI=[ebp+8]` at `0x004343B3`, and retains that argument
through the text call. At `0x004344E7` it loads the adapter vptr from `[EDI]`,
then loads slot `+0x68` at `0x004344F5`, sets `ECX=EDI`, and calls at
`0x004344FA`. Its four arguments are text, preceding DWORD count, local
rectangle, and flags `0x8134`.

With the second owner vptr, the slot reaches `0x00466C40`. It loads the first
argument into `EDI` at `0x00466C80`. Before the `GetClientRect` call, two
arguments are pushed and `0x00466C95` stores `EDI` to `[esp+0x2C]`, which is
the stable frame location `S+0x24`, not `S+0x2C`. `0x00466F2D` later reloads
that adapter pointer from `[esp+0x24]`; `0x00466F40` loads its vptr. After
three text arguments are pushed, `0x00466F50` reloads `ECX` from
`[esp+0x30] = S+0x24`. The fourth argument is pushed, slot `+0x68` is loaded
at `0x00466F55`, and `0x00466F58` calls the adapter. Its flags are `0x8135`.

## Compiler-private register argument: `0x00454D4B`

The only decoded direct calls to helper `0x00454C60` in this sweep occur at
`0x00426DFD` and `0x00426EC7`. They belong to the routine whose adapter
constructor call is `0x004267E8`, with `ECX=&[esp+0x34]` set at
`0x004267E4`.

Each caller reserves `0x10` stack bytes for a rectangle by value and pushes a
CString pointer. With `0x14` bytes pending, it sets
`EBX=&[esp+0x48] = S+0x34` at `0x00426DF6` or `0x00426EC0`. Thus `EBX`
supplies the caller's adapter through a private register convention.

The helper never assigns to `EBX` in its decoded body. It loads the vptr from
`[EBX]` at `0x00454D3D`, loads `+0x68` at `0x00454D46`, sets `ECX=EBX`, and
calls at `0x00454D4B`. The flags are chosen as `0x8134` or `0x8114` before
being pushed from `EDI`. Its plain `ret` at `0x00454D86` matches the callers'
explicit `add esp,0x14` cleanup. This resolves the two listed caller contexts;
it does not establish the origin of `EBX` for an untraced indirect invocation.

## Stack-forwarded adapters: `0x0045C60A` and `0x0045DF80`

For `0x0045C60A`, the decoded direct caller is `0x0045BF25` calling helper
`0x0045BFE0`. The caller constructs its adapter at local `S+0x3C` through
`0x0047105C` at `0x0045BDE8`. It pushes a rectangle pointer and a separate
GDI+ wrapper pointer, then computes `EAX=&[esp+0x44] = S+0x3C` at
`0x0045BF1F`. It pushes that adapter pointer, then the owner object, before
the helper call. The adapter is the helper's second explicit stack argument.

The helper's initial pushes and `sub esp,0xC4` make its stable ESP
`E-0xE4`. At `0x0045C586`, `ESI=[esp+0xEC]` therefore means
`[E+8]`, the second argument. The same `ESI` reaches the vptr load at
`0x0045C5F4`, slot load at `0x0045C605`, `ECX=ESI` at `0x0045C608`, and
call at `0x0045C60A`. It passes text/count/rectangle and flags `0x8134`.
The helper returns with `ret 0x10` at `0x0045C6AB`.

For `0x0045DF80`, the parallel caller at `0x0045D8F4` calls helper
`0x0045D9B0`. Constructor `0x0045D7B8` initializes the caller adapter at
`S+0x3C`. After two pointer arguments are pushed, the caller computes
`EAX=&[esp+0x44] = S+0x3C` at `0x0045D8EF` and pushes it as the first
explicit argument. The owner is carried separately in `EDI`.

This helper has one fewer saved nonvolatile register, so its stable ESP is
`E-0xE0`. Its `ESI=[esp+0xE4]` at `0x0045DEFF` therefore means `[E+4]`,
the first argument. That receiver reaches vptr load `0x0045DF6D`, slot load
`0x0045DF7B`, `ECX=ESI`, and call `0x0045DF80`. The arguments again include
flags `0x8134`. Its `ret 0x0C` at `0x0045E007` matches the three arguments.

## Reproduction and remaining limits

From the repository root:

```powershell
python scripts/audit_rk406_forwarded_text_receivers.py `
  --binary 'C:\Users\shubh\Downloads\sshorcale\_rk_analysis\inputs\DeviceDriver.exe' `
  --objdump 'C:\msys64\ucrt64\bin\objdump.exe' `
  --out docs/rk-406-forwarded-text-receivers.csv
```

The checker rejects a different input hash. It reads/disassembles the supplied
file and writes the selected CSV; it does not load the PE into a target process
or communicate with hardware. The five rows are concrete caller-path findings,
not a proof that no alternate call or dynamic receiver exists. Their cleanup
and subsequent staging show no response-buffer consumer on these listed
paths. They do not establish a G5 command-`0x88` caller, firmware export,
physical model support, or observed display behavior.
