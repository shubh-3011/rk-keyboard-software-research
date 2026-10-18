#!/usr/bin/env python3
"""Verify selected RK Drive keymap, macro, TFT, and display anchors.

The pinned vendor entry bundle is fetched as bytes, checked by SHA-256, and
discarded after static scans. This script never executes the page or opens a
browser device interface.
"""

from __future__ import annotations

import hashlib
from urllib.request import Request, urlopen


URL = "https://drive.rkgaming.com/assets/index-DSCGl9KV.js"
EXPECTED_BYTES = 20_417_509
EXPECTED_SHA256 = "ec50777e49f34f24f4564c8624d5c39b52447980199fad43e24734826e6531ee"


def fail(message: str) -> None:
    raise SystemExit(f"audit failed: {message}")


def find_at(bundle: bytes, needle: bytes, expected: int) -> None:
    actual = bundle.find(needle)
    if actual != expected:
        fail(f"{needle!r}: expected byte {expected}, found {actual}")


def main() -> int:
    request = Request(URL, headers={"User-Agent": "static-rk-research-audit/1.0"})
    try:
        with urlopen(request, timeout=60) as response:
            bundle = response.read()
    except Exception as exc:
        fail(f"could not fetch pinned official bundle: {exc}")

    digest = hashlib.sha256(bundle).hexdigest()
    if len(bundle) != EXPECTED_BYTES or digest != EXPECTED_SHA256:
        fail(
            f"bundle identity changed: bytes={len(bundle)}, sha256={digest}; "
            "review the source snapshot before updating this audit"
        )

    anchors = [
        (b'"IKeymapService"', 18_919_413),
        (b"class LEr", 18_920_738),
        (b'"IMacroService"', 18_937_434),
        (b"class FEr", 18_938_557),
        (b'"IDisplayService"', 19_011_059),
        (b"class QEr", 19_013_069),
        (b'__name:"macro-page"', 19_317_297),
        (b'.macro.setMacros(Cs);const Pa=await fs.macro.getMacros()', 19_327_043),
        (b'const XQs=ko("tftinfo_rk_m87"', 6_702_276),
        (b'__name:"tft"', 6_716_790),
        (b".setTftPic(le,e.value.delay>=25?e.value.delay-25:e.value.delay)", 6_702_983),
        (b".stopTFTPicDownload()", 6_721_826),
        (b'.remapping.getKeymaps({ids:_,layer:v.value,system:F3()})', 19_219_772),
        (b'.remapping.setKeymap({id:Oa,keycode:Gs,layer:v.value,system:F3()})', 19_222_469),
        (b'.remapping.resetKeymaps({layer:wa,system:ho})', 19_225_547),
    ]
    for needle, expected in anchors:
        find_at(bundle, needle, expected)

    keymap_start = bundle.find(b"class LEr")
    keymap_end = bundle.find(b"const ad=IL", keymap_start)
    if keymap_end < 0:
        fail("keymap service class boundary was not found")
    keymap_service = bundle[keymap_start:keymap_end]
    for needle in [b"encode(3,", b"(131,", b"](2,6)"]:
        if needle not in keymap_service:
            fail(f"keymap class lacks expected static sequence {needle!r}")

    macro_start = bundle.find(b"class FEr")
    macro_end = bundle.find(b";class ", macro_start + len(b"class FEr"))
    if macro_end < 0:
        fail("macro service class boundary was not found")
    macro_service = bundle[macro_start:macro_end]
    for needle in [b"(130,0)", b"encode(133,0", b"(5,0,l.concat(d).flat())"]:
        if needle not in macro_service:
            fail(f"macro class lacks expected static sequence {needle!r}")

    service_registry = bundle[19_085_900:19_087_100]
    for needle in [
        b"new LEr(s,a)",
        b"new FEr(s,a)",
        b"new QEr(s,a,o[t(330)](M_))",
        b"get[Jn(360)]()",
        b"get[Jn(336)]()",
        b"get[Jn(322)]()",
    ]:
        if needle not in service_registry:
            fail(f"SDK service registry lacks expected binding {needle!r}")

    if bundle.count(b"get[Jn(322)]") != 1:
        fail("display getter occurrence count changed; review claimed UI bridge gap")

    print(f"Verified official bundle: {len(bundle)} bytes, SHA-256 {digest}")
    print("Verified keymap/macro service serializers and SDK registrations.")
    print("Verified RK68 HE mapping/macro UI and legacy M87 TFT anchors.")
    print("Verified newer display service exists; no UI bridge is asserted.")
    print("No vendor code was written or executed; no HID/device I/O occurred.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
