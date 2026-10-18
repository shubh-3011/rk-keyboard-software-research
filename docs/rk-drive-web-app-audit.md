# RK Drive Web App: public bundle and keyboard registry audit

## Scope and collection

This is a dated, static examination of the public [RK Drive Web App](https://drive.rkgaming.com/)
as served on 2026-10-18. The page advertises its self-developed browser driver,
wired and 2.4 GHz receiver connections, and Chrome, Edge, and Opera support.
The page was fetched over HTTPS; its JavaScript was downloaded in memory for
string and metadata analysis. No vendor bundle or image was copied into this
repository. The auditable files are metadata extracts and SHA-256 values only.

The main bundle references six communication modules. The reproducible
[bundle manifest](rk-drive-js-manifest.csv) records all seven discovered JS
files, byte sizes, URLs, and hashes. On this snapshot the entry bundle was
20,417,509 bytes with SHA-256
`ec50777e49f34f24f4564c8624d5c39b52447980199fad43e24734826e6531ee`.
The other chunks are named `communication`, `dongleCommunication`,
`mouseCommunication`, `qiwangCommunication`, `qiwangCommunicationAdaptive`,
and `rongyuanCommunication` in their bundle filenames.

A follow-up rechecked the live HTML's entry reference and recursively reachable
JavaScript URLs on 2026-10-18. The reachable set was exactly the seven manifest
rows; all seven byte sizes and SHA-256 values matched. Re-parsing the live
entry produced 177 keyboard descriptors with the same identity rows as the
saved catalog. This validates that the dated metadata snapshot still matched
the public deployment at that check; it does not expand the registry's product
or hardware-revision coverage. The 96 indexed image URLs were checked with
HTTP `HEAD` and each returned status 200 with `image/png`; image bodies were
not downloaded.

The scanner extracts registered-device metadata and the declarative model
configuration fields from the entry bundle. It does not copy or execute the
bundle, reverse every minified function, or treat strings as proof of a
reachable feature. Recreate the metadata snapshot from the repository root
with:

```powershell
python scripts/extract_rk_drive_catalog.py
```

This refreshes the source manifest, the [177-row keyboard descriptor catalog](rk-drive-keyboard-catalog.csv),
the [specialized RK68 HE profile inventory](rk-drive-specialized-keyboard-profiles.csv),
the [20-row legacy mouse registry plus two CB75 connection rows](rk-drive-mouse-registry.csv),
the photo/layout image URL index, and [`rk-drive-catalog.json`](../rk-drive-catalog.json).
The JSON includes mouse metadata under `mouseModels` and the two distinct
profiles under `specializedKeyboardProfiles`. The script records bundle hashes
and retrieval time. It keeps JavaScript in memory and writes only derived model
fields and public URL references; no vendor code or images are copied.

## Registered keyboard descriptors

The current entry bundle contains **177 keyboard connection descriptors**,
with **96 distinct displayed labels**, and **91 unique image references among
the general descriptor array**. Across the separate HE profiles and image
index, there are **93 keyboard product-photo references**, two HE layout
backgrounds, and one mouse image, for 96 image URLs total. The descriptor
array also has **104 distinct VID/PID pairs**. Of the descriptor rows, 98 identify a USB
connection and 79 identify a 2.4 GHz receiver connection. The source declares
171 entries with protocol family `BeiYing` and six with `QiWang`. These are
official web-app registry entries, not a complete census of every RK product
or every hardware revision.

Each row exposes a displayed model/region name, image basename, VID, PID,
HID usage page and usage, connection type, device type, and protocol family.
The scanner also records the row's declared key layers, Windows/macOS tables,
number of layout groups, and lighting-effect names with their raw `speed`,
`brightness`, `color`, `mixColor`, and `sleep` fields. These are static fields
from the public JS object; no protocol factory or device method is called.

In this snapshot, 158 descriptors list Normal/Fn 1/Fn 2/Tap layers, nine list
Normal/Fn 1/Tap, six list Normal/Fn, two list Normal/Fn 1/Fn 2, and two list
Normal only. 171 list both Windows and macOS tables; six omit a table list.
Each row has two key-layout groups. Of 177 connection descriptors, 106 list
16 lighting-effect entries, 42 list 19, two list 15, and 27 have no entries.
The mode controls are kept as the static effect-object fields found in the
bundle; a name or control flag does not prove it is supported by every
firmware revision.

For **RK-S98**, the bundle has ten displayed label variants and twenty
connection rows. The base-label USB entry is VID `0x258A`, PID `0x01AF`; its
2.4 GHz receiver entry is VID `0x258A`, PID `0x0150`. The receiver PID is shared
by many registered labels, so it cannot uniquely identify an S98. Regional
name, HID collection, and application profile evidence must stay separate;
the catalog does not silently select a model from a shared receiver ID.

The image field `keyboard_rk-s98.png` resolves through the site's own asset
path, for example
[`RK-S98 photo hosted by RK Drive`](https://drive.rkgaming.com/src/assets/images/keyboard_rk-s98.png).
The CSV lists the same official-hosted URL for every referenced image. These
links are not mirror copies, and the image files are not covered by this
repository's source license.

## Separate RK68 HE profiles

The general descriptor array does not contain the two Bytech magnetic-switch
keyboard profiles. The bundle constructs them separately, so they are recorded
in their own CSV and JSON array rather than counted among the 177 descriptors.
Both declare USB-only connection, vendor `0x372E`, HID usage `0xFF60:0x0061`,
protocol `Bytech`, minimum-firmware field `0`, `hasSideLight: false`, and one
hidden keycode (`218169344`). The two variants differ in product ID, UUID,
regional key text, and artwork:

| Profile | Product ID | UUID | Product image | Layout background |
| --- | --- | --- | --- | --- |
| RK68 HE | `0x10BF` | `18691697672194` | [RK-hosted product image](https://drive.rkgaming.com/assets/RK68HE_us-DdalugDh.png) | [RK-hosted layout image](https://drive.rkgaming.com/assets/RK68HE_us_background-BDwhIjPO.png) |
| RK68 HE ES | `0x10C0` | `18691697672252` | [RK-hosted product image](https://drive.rkgaming.com/assets/RK68HE_es-CeZBnEjA.png) | [RK-hosted layout image](https://drive.rkgaming.com/assets/RK68HE_es_background-D_cuWvBv.png) |

These profiles use a UUID check in RK's Web Driver before initialization.
Keydeck compares only the visible VID/PID and HID usage collection and labels
the result a descriptor candidate. It does not read the UUID, open the HID
interface, or infer firmware compatibility. The layout background is an image
reference, not parsed physical key geometry. Product images and backgrounds
are hotlinked and are not redistributed.

## Feature families visible in the public bundle

Static bundle evidence includes menu assets and model fields for key mapping,
lighting, macros, a TFT/screen page, settings, advanced and behavior pages,
and high-performance options whose asset labels include DKS, snap, SOCD,
toggle, mod-tap, and macro. The bundle also contains separate mouse UI assets
and a mouse communication chunk. The keyboard catalog and mouse registry are
separate metadata extracts. The mouse registry covers the 20 legacy descriptor
entries and the two CB75-Mouse connections. See the
[mouse and feature-gate audit](rk-drive-feature-gate-and-mouse-audit-2026-10-18.md)
for the distinction between these records and the site's mouse controls.

The public UI text also exposes key mapping, key-layer/Windows/macOS table
selection, macro recording and editing, lighting modes, TFT image/frame
management, performance settings, advanced-key editing, keyboard settings,
function settings, and mouse DPI/performance pages. Those strings and menu
assets are an inventory of candidate surfaces, not proof that a particular
model supports every control. The derived catalog preserves only the
model-declared layers/tables/layout counts/effect definitions; the rest still
needs page, capability-gate, handler, and transport-path analysis.

The browser app includes WebHID chooser and device-change paths in its bundle.
The entry code also contains report send/receive functions, firmware/boot-mode
paths, and device protocol implementations. Static presence alone does not
establish a safe read-only protocol. In particular, the boot-mode and firmware
routes are not part of Keydeck's local profile editor and must not be called
from this project without a separate, complete safety analysis. No chooser was
opened, no HID interface was opened, and no report, boot-mode command, firmware
operation, or keyboard write was sent during this audit.

## Use in the independent projects

Keydeck can use the derived catalog for model search, connection-ID candidates,
and links to RK-hosted product images. Its existing local keymap, lighting,
macro, and display editors remain local profile data. An official registry row
or a photo link does not supply a verified keyboard layout or make a protocol
implementation safe. Keydeck must preserve ambiguous IDs and must not imply
that all official-app controls are hardware-functional until each control's
data path, model gating, and command format has its own evidence and safe
validation.

| Web Driver feature family in static bundle | Keydeck status | Remaining gap |
| --- | --- | --- |
| Device chooser and USB/2.4 GHz descriptors | Registry metadata, including descriptor-level RK68 HE profile candidates | No report access, RK68 HE UUID confirmation, exact physical revision recognition, or hardware writes |
| Key map, layers, Windows/macOS tables, and layout groups | Native RK Drive editor stages the selected descriptor's declared layer and OS table and supports descriptor-checked local JSON import/export; existing key-label drafts remain separate | The Web Driver layout is not the same as the installed 4.06 profile schema; no compatible command serializer or device apply path |
| Lighting and model-specific effect definitions | Native RK Drive editor stages a declared effect and enables only its listed speed/brightness/color/mix controls; drafts support local JSON import/export | Effect labels and preference values are not device payloads |
| Macro UI and macro-related assets | Local macro sequence/profile data | No recording/playback, persistence format parity, or transfer to device |
| TFT/screen page and media references | Local screen profile and image metadata | No image conversion or transfer to device |
| Performance, keyboard/function settings, advanced keys, DKS, snap, SOCD, toggle, mod-tap | Not implemented as model-gated editing | No verified profile schema or control-to-packet mapping for the web registry |
| Mouse pages and communication module | Separate source-free mouse registry and feature-gate audit are now catalogued; the native keyboard directory excludes mice | Model-specific UI controls and hardware support remain unresolved |
| Firmware and boot-mode paths | Not exposed in Keydeck | Requires a separate updater and firmware safety analysis |
| Native tray, login startup, and Windows UI | Not part of the hosted web app | The new C# WPF rebuild has tray/startup, an RK Drive directory, and descriptor-bound local layer/table/effect drafts, but not full feature parity or hardware access |

The research Workbench remains a separate Python/WebView profile-editor
prototype, not a native rebuild. The native rebuild embeds derived registry
fields and fetches a selected product image from RK's host on demand; it does
not bundle or mirror vendor JavaScript or photos. Neither app reproduces the
complete Web Driver workflows or communicates with a keyboard. See the
[`native rebuild roadmap`](../REBUILD-ROADMAP.md) for current parity gaps.
