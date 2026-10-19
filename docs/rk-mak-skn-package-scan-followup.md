# `mak.skn` package-wide static consumer scan

## Scope and package verification

This follow-up checks only files already installed under
`C:\Program Files (x86)\RK Keyboard Software`. No RK executable or updater was
launched, and no device interface was opened. On 2026-10-19, the installed tree
was rehashed against [`rk-installed-package-manifest.csv`](rk-installed-package-manifest.csv):
810 manifest rows, 810 installed files, and zero missing, extra, or
size/hash-mismatched files.

The five installed PE images scanned for references and loader imports were:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `DeviceDriver.exe` | 2,326,528 | `C03F88BC4E2D78AA4392D7445B0FD62182DC824F97F5D5DB40BD009E547A9AB6` |
| `Dev/01AF/Update.exe` | 2,109,952 | `27894463B0DFE5BC3F5DC19D4D3351D9DFB692C402BF277BDE3889D37E4A206C` |
| `InitSetup.dll` | 69,000 | `59DB7BFD9A92CC9A0998260807F17C536EC71159B727DF10D08B998BC94DE301` |
| `unins000.exe` | 1,316,301 | `B4CA28B192D5A50307D2B28F3323B58B39CB51EDD6682E75706CAC2DD69A4A14` |
| `uninstall.dll` | 146,944 | `9CA1EBC49998B8B2971DEBC1776E7AFF6086AEB86ADCCA6CFB95E9FB399EB03C` |

The installed `skins/mak.skn` is 520 bytes with SHA-256
`F0970E70282F3823B79BD3818D303DF5B479EE994902A49E33DE30901B93FA7D`.
It is the only `.skn` file, only file of that size, and its complete bytes and
first 32 bytes occur nowhere else in this installed package.

## What the binary scan found

ASCII and UTF-16LE searches of all five PE files found no `mak.skn`, `.skn`, or
`*.skn` literal. `DeviceDriver.exe` does contain wide `skins\` path fragments
and image names, consistent with the loader paths documented in the
[skin-loader follow-up](rk-skin-loader-static-followup.md). It imports
`GdipCreateBitmapFromFile`. The other four PE files contain no such GDI+ file
loader import.

`Dev/01AF/Update.exe` does import GDI+ image operations, including
`GdipCreateBitmapFromStream` and `GdipCreateBitmapFromHBITMAP`, along with
Win32 resource and image-list APIs. Its scanned strings contain no `.skn`,
`mak.skn`, `skins/`, `.png`, or `.bmp` path/name. These imports establish
generic image and resource capability only; the static evidence does not tie
them to external skin files or to `mak.skn`. `InitSetup.dll` has generic file
enumeration/open imports but no GDI+ image loader imports. The uninstaller
binaries expose generic UI/resource APIs, not a `.skn` reference. Such imports
alone cannot rule out indirect use through dynamically resolved code or an
unobserved runtime path.

## Blob checks and limits

The blob begins `DE 2D 77 E7 35 84 96 59`; none of the checked common image,
archive, container, or compression signatures matched at offset zero. Standard
zlib, gzip, bzip2, and LZMA stream decoders rejected the complete blob. Its
measured byte entropy is 7.5988 bits/byte, with 206 printable ASCII bytes out
of 520. Those measurements do not identify a format and are not evidence by
themselves of encryption or compression.

No structured parse or consumer for `mak.skn` is supported by this static
evidence. The installed driver has a general GDI+ file loader that could accept
many formats if a suitable path reached it, while the updater has stream-based
image APIs; neither relationship is shown for this blob. The format, any
possible transform, and whether either executable ever reads the file remain
unresolved. The prior manifest-delta record reports the same 520-byte hash in
the 4.06 and 4.6 package inventories, but the 4.6 extracted payload is not
available here for independent rehashing.
