# RK 4.6 text-macro command and selection-persistence bridge

## Scope and result

This 2026-10-22 static follow-up closes part of the previously missing
UI-to-text-macro save path. `CKeyFunPickDlg` handles `WM_COMMAND` through a
virtual override, matches the sender HWND of its embedded `CPngBtn` associated
with localization key `tc_apply` (English **Apply**), and, in state `5`, reads
text from a stored control object, copies it into a text-macro
record, and calls the existing local-file writer. A separate `CWelcomDlg`
command path forwards a newly selected device-associated identifier to the
routine that conditionally saves the old partition and loads the new one.

The exact input is the 4.6-labeled `DeviceDriver.exe`, 2,418,176 bytes,
SHA-256 `8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9`.
All addresses are preferred-image VAs in that binary. Evidence consists of
PE bytes, RTTI/vtables, decoded instructions, import mappings, and the existing
[file-format/path audit](rk-v4.6-textmacro-path-audit.md). The executable was
not launched and no HID/device API was invoked.

The [verifier](../scripts/audit_rk46_textmacro_command_bridge.py) and
[evidence CSV](rk-v4.6-textmacro-command-bridge.csv) pin the selected static
links. These checks establish code/data relationships for this exact image;
they do not establish Windows message delivery, the actual rendered caption,
or successful runtime file I/O.

## Command dispatch and owner identity

`CKeyFunPickDlg` has vtable `0x005D530C`, preceded by COL `0x005ED020`.
The COL's TypeDescriptor names `.?AVCKeyFunPickDlg@@`. Its constructor path
stores that vptr at `0x0041F63E`. Vtable slot `+0xF0`, at `0x005D53FC`,
contains `0x00421350`.

This function is not an ordinary row handler in the existing MFC message-map
CSV. The generic dispatcher at `0x0047EC81` explicitly compares the incoming
message against `0x0111` (`WM_COMMAND`) at `0x0047ECA1`; on that branch it
pushes `lParam` and `wParam`, then dispatches owner slot `+0xF0` at
`0x0047ECB1`. This ties `0x00421350` to command handling for this owner.

The override subtracts `0x420` and saves four registers. With entry ESP `E`,
its stable ESP is `E-0x430`; `[esp+0x438]` at `0x004213E1` is therefore
`[E+8]`, the second argument (`lParam`). It compares that HWND to the HWND
at the owner's embedded subobject `+0x204`, field `+0x20`
(`0x004213FE`–`0x00421411`). A mismatch jumps past this branch. The selected
text-macro branch does not independently test a particular notification code
from the high word of `wParam`; a specific observed button-click sequence is
not claimed.

## The sender is a dynamically created `CPngBtn`

The picker constructor initializes its `+0x204` subobject through
`0x0044CDE0` (`0x0041F649` / `0x0041F654`). That constructor installs vptr
`0x005DE06C` at `0x0044CE16`. The preceding COL `0x005ED8B8` links to the
name `.?AVCPngBtn@@`.

During picker setup, `0x00420562` addresses this same `+0x204` subobject in
EDI, loads the caption-source global address `0x00647450` into EAX, and calls
the internal creation helper `0x004520B0` at `0x0042056F`. The helper pushes
creation ID `0`, the parent object, a rectangle pointer, style `0x5000000B`,
and an initial caption pointer, then invokes the child's virtual slot
`+0x13C`. In this vtable that slot targets `0x00482218`. The wrapper supplies
the UTF-16 class literal `BUTTON` at `0x005A8618`, forwards its ID argument,
and calls virtual `+0x54`.

The caption global is statically associated with `tc_apply`. Localization code
pushes the UTF-16 key at `0x005DC220` from `0x0044470C`, calls lookup helper
`0x00443F00` at `0x00444738`, and assigns the returned text to global
`0x00647450` through `0x00405B20` at `0x0044474E`. The creation helper retains
the caption-source address in EBX at `0x004520BB` and dereferences it at
`0x004520D7`. Thus picker setup and localization share the same text global.
The [existing UI-setting localization audit](rk-v4.6-ui-setting-signal-audit.md)
records the packaged English `Text/en/text.xml` entry
`<tc_apply>Apply</tc_apply>`. The new verifier checks the PE key/global link;
the English dictionary mapping is cited from that prior audit, not parsed as
an additional input by this script.

This establishes the sender's compiled type and numeric creation-ID argument.
The save branch chooses it by HWND equality, so its operation does not depend
on treating ID `0` as a unique dialog control identifier. **Apply** is the
static English caption association; the selected runtime locale, actual
rendered caption, final runtime control ID, and appearance were not observed.

## State `5` reads, copies, and persists text

The command override loads `[this+0x11AC]` at `0x0042144C`. Comparison against
`5` at `0x00421540` selects the text branch; other values take different
paths. The numeric state is proven, while its exact displayed selection label
remains unresolved.

At `0x0042154B`–`0x00421560`, the code supplies a `0x200`-WCHAR limit and a
local output buffer to `0x004806D1`, with the stored object from
`[this+0x11A8]` as receiver. In that helper's ordinary-window branch
(`[receiver+0x50]==0`), the text call at `0x004806EE` resolves through IAT
`0x005A677C` to `GetWindowTextW`. The other branch uses a different
COM/interface-based text getter and is not resolved by this follow-up.

An empty first WCHAR takes the error/early-return path. For non-empty text:

1. `0x00421598` calls record lookup/allocation helper `0x0041F480` with the
   allocation flag set. If the existing selected record carries
   `0x0A00005B`, its prior key is reused; otherwise the input key is zero.
2. On a non-null record result, the override writes discriminator
   `0x0A00005B` into its pending selection state and retains the record key.
3. `0x004215C0` advances the returned record pointer by four bytes. The call
   at `0x004215CF` copies the local text to that payload through
   `0x00575E47`, with bound `0x200` and the other copy argument `-1`.
4. It reads the current partition identifier from global `0x0062A1FC` and
   passes it to local-file writer `0x0041F540` at `0x004215DE`.

The existing path audit establishes the writer's wide path shape
`%s%04X\textmacro.dct`. The writer opens with `CREATE_ALWAYS` at
`0x0041F59A`, and, if the handle is valid, writes `0xC8C8` bytes from
`0x0060D3C4` through `WriteFile` at `0x0041F5C1`, then closes at
`0x0041F5C8`. The span contains 50 fixed `0x404`-byte records. Its raw
buffer-to-file relationship is proven; complete key-bit meanings, actual file
contents, and write success remain unobserved.

## Selection change saves the old partition and loads the new one

The `CWelcomDlg` vtable at `0x005E2624` has COL `0x005EDBEC` and slot
`+0xF0` pointing to `0x0046C050`. The same generic command dispatcher therefore
provides its static `WM_COMMAND` route.

This override iterates ten child records starting at owner `+0x508`, stride
`0x184`. It compares the incoming `lParam` HWND against each child's `+0x20`
HWND (`0x0046C146`–`0x0046C15C`). The matching ordinal selects a list entry;
after object-field/virtual checks, the handler assigns the selected holder
to global `0x00647320` at `0x0046C1F1`. If owner field `+0x1440` is non-null,
it supplies that object and a WORD from selected device-associated object
`+0x24E` to `0x00459F50` at `0x0046C211`.

That routine obtains the old identifier from `0x0062A1FC` and the new one
from its second explicit argument. Equal, zero, and special value `0x6461`
take other paths before the save/load sequence. On the examined change path,
provided the old identifier exists, global byte `0x0062B8B3` gates the old
partition's call to writer `0x0041F540` at `0x0045A057`. Later the same byte
gates the new identifier's call to reader `0x004597E0` at `0x0045A0EE`.
The existing profile-loader trace links this byte to `ShowTextMacro`.

This is a concrete static selection-command-to-partition-persistence path.
The actual selected model/revision, list population, child labels, and runtime
identifier values are not established here. The other direct call into
`0x00459F50` at `0x0045C620` occurs within the large setup helper beginning
at `0x0045A950`; its full caller/event ownership remains outside this pass.

## Reproduction and remaining limits

```powershell
python scripts/audit_rk46_textmacro_command_bridge.py --binary .research/rk46-extract-full/app/DeviceDriver.exe --objdump C:/msys64/ucrt64/bin/objdump.exe --out docs/rk-v4.6-textmacro-command-bridge.csv
```

Still unresolved are the absolute runtime configuration path, runtime locale
selection and rendered captions, runtime notification delivery, state-`5`
display label, COM-based text getter, complete record-key grammar, partial-file
handling, and successful load/save results. This trace concerns host-side text
and file state. It does not identify firmware storage, a firmware readback
method, or observed behavior of the connected keyboard.
