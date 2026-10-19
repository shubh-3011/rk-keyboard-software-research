# RK 4.06 `CLedDlg` selector-message sender follow-up

## Scope and evidence

This offline follow-up traces literal message senders for the two
`CLedDlg`-mapped private messages `0x0800` and `0x0801` in the installed
4.06 `DeviceDriver.exe`, SHA-256
`c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6`.
Addresses are image virtual addresses. It uses a full GNU `objdump -d -M
intel` disassembly, the native API IAT ledger, and the RTTI-backed MFC map.
The executable was not run and no HID report or command was sent.

**Proven statically** means the instruction or data-flow edge appears in the
hash-pinned image. **Inferred** marks a likely window relationship not
observed at runtime. **Unresolved** marks a field value, user control, or
device effect not established by this image.

## Literal `PostMessageW` send sites

The `PostMessageW` IAT slot is `0x0059E738`. A full-image search for literal
message pushes followed by calls through that slot found these callsites:

| Message | Callsite | `wParam` source | `lParam` source | Parent-window lookup |
| --- | ---: | --- | --- | --- |
| `0x0801` | `0x0043693D` | `[ESI+EDI*4+0x298]` | `[ESI+0x54]` | `GetParent` at `0x00436918`; wrapper `0x004752FD`. |
| `0x0801` | `0x004372D9` | caller stack argument | `[ESI+0x54]` | `GetParent` at `0x00437277`; wrapper `0x004752FD`. |
| `0x0801` | `0x0044C204` | `EBX` selected value | `[ESI+0x930]` | `GetParent` at `0x0044C1E3`; wrapper `0x004752FD`. |
| `0x0801` | `0x0044DAEC` | caller stack argument | `[ESI+0x9E0]` | `GetParent` at `0x0044DAC7`; wrapper `0x004752FD`. |
| `0x0800` | `0x00436A45` | `[ESI+EDI*4+0x298]` | `[ESI+0x54]` | `GetParent` at `0x00436A20`; wrapper `0x004752FD`. |
| `0x0800` | `0x00437299` | caller stack argument | `[ESI+0x54]` | `GetParent` at `0x00437239`; wrapper `0x004752FD`. |
| `0x0800` | `0x0044C80C` | `EDI` selected value | `[ESI+0x930]` | `GetParent` at `0x0044C7EB`; wrapper `0x004752FD`. |
| `0x0800` | `0x0044D299` | `EDI` selected value | `[EBX+0x9E0]` | `GetParent` at `0x0044D278`; wrapper `0x004752FD`. |
| `0x0800` | `0x0044DAAC` | caller stack argument | `[ESI+0x9E0]` | `GetParent` at `0x0044DA87`; wrapper `0x004752FD`. |

At each site the HWND argument comes from the wrapper's `+0x20` field after
the parent lookup. These are direct message-posting callsites, not
`SendMessageW` calls. **Inferred:** the parent window is the `CLedDlg` that
owns the matching MFC map. The runtime HWND identity is not observed.

## Handler argument meaning

The MFC map sends `0x0800` to `0x00422190` and `0x0801` to `0x00422220`.
Handler `0x00422220` compares its `lParam` with `0x94` and `0x95`. For
selector `0x95`, its `wParam` indexes the `LightUI` byte table at
`0x00611854`, then the value is formatted for display. Handler `0x00422190`
forwards the message arguments to `0x00422220`, copies page state, and can
signal Apply mode `2` under its guards.

This ties the `0x0801` sender families to the selector-message route, but the
sender's `lParam` values are loaded from child-object fields `+0x54`,
`+0x930`, and `+0x9E0`. No static assignment or constructor path in this pass
proves any field contains `0x95`. The `wParam` values are likewise dynamic
values or caller arguments; no specific widget-to-index mapping is recovered.

## Limits

- The literal `PostMessageW` callsites and arguments are proven, while
  computed-message sends or alternate API wrappers are outside this literal
  search.
- The owning `CLedDlg` relationship is inferred from the parent-window path
  and matching map IDs; it is not runtime evidence.
- Which field, if any, supplies selector `0x95`, which child control initiates
  the posts, and what visible label it represents remain unresolved.
- The message path does not prove a brightness adjustment, a family-specific
  serializer selection, or any physical keyboard effect.

## Related evidence

- [Brightness UI handler audit](rk-lighting-brightness-ui-handler-audit.md)
- [Recovered MFC message-map arrays](rk-mfc-message-map-audit.md)
- [UI control-to-command crosswalk](rk-ui-control-command-crosswalk.md)
- [Apply worker and signal paths](rk-settings-apply-worker-audit.md)
