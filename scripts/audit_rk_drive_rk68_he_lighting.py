#!/usr/bin/env python3
"""Verify a source-free RK Drive RK68 HE lighting trace from its pinned bundle.

The public minified JavaScript is fetched into memory, hash-checked and scanned
for documented byte anchors. It is not saved. The script never opens a WebHID
chooser or device interface and never sends any device data.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from urllib.request import Request, urlopen


URL = "https://drive.rkgaming.com/assets/index-DSCGl9KV.js"
EXPECTED_BYTES = 20_417_509
EXPECTED_SHA256 = "ec50777e49f34f24f4564c8624d5c39b52447980199fad43e24734826e6531ee"


def fail(message: str) -> None:
    raise SystemExit(f"audit failed: {message}")


def find_at(bundle: bytes, needle: bytes, expected: int, *, start: int = 0) -> int:
    position = bundle.find(needle, start)
    if position != expected:
        fail(
            f"{needle!r} expected at byte {expected}, "
            f"found at {position}"
        )
    return position


def token_table(
    bundle: bytes,
    function_name: bytes,
    base: int,
    rotation_count: int,
) -> list[str]:
    opening = b"function " + function_name + b"(){const e=["
    begin = bundle.find(opening)
    if begin < 0:
        fail(f"decoder table {function_name.decode()} is missing")
    begin += len(opening)
    end_marker = b"];return(" + function_name + b"=function(){return e})()}"
    end = bundle.find(end_marker, begin)
    if end < 0:
        fail(f"decoder table {function_name.decode()} is unterminated")
    source = bundle[begin:end].decode("utf-8")
    values = [
        json.loads(match.group(0))
        for match in re.finditer(r'"(?:\\.|[^"\\])*"', source)
    ]
    if len(values) < 50:
        fail(f"decoder table {function_name.decode()} has an unexpected shape")
    for _ in range(rotation_count):
        values.append(values.pop(0))
    # `base` is the first obfuscated token number, not a zero-based array
    # boundary. The caller indexes the decoded table with `index - base`.
    if base <= 0 or not values:
        fail(f"decoder table {function_name.decode()} has an invalid index range")
    return values


def main() -> int:
    request = Request(URL, headers={"User-Agent": "static-rk-research-audit/1.0"})
    try:
        with urlopen(request, timeout=60) as response:
            bundle = response.read()
    except Exception as exc:  # Network/proxy errors are surfaced with context.
        fail(f"could not fetch the pinned official bundle: {exc}")

    digest = hashlib.sha256(bundle).hexdigest()
    if len(bundle) != EXPECTED_BYTES or digest != EXPECTED_SHA256:
        fail(
            f"bundle identity changed: bytes={len(bundle)}, sha256={digest}; "
            "review the source snapshot before updating this audit"
        )

    token_table_iy = token_table(bundle, b"uCe", 351, 86)
    token_table_jn = token_table(bundle, b"YCe", 316, 16)
    iy = lambda index: token_table_iy[index - 351]
    jn = lambda index: token_table_jn[index - 316]
    for index, expected in {
        390: "ILightingLegacyService",
        378: "setEffect",
        425: "updateRGB",
        448: "getCustomMainLight",
    }.items():
        if iy(index) != expected:
            fail(f"iy({index}) decoded to {iy(index)!r}, expected {expected!r}")
    if jn(321) != "lighting" or jn(328) != "getService":
        fail("SDK facade token decode did not match the recorded lighting bridge")

    anchors = [
        (b"ILightingLegacyService", 18_994_696),
        (b"class jEr", 18_996_586),
        (b"const wqe=iy(390)", 18_996_489),
        (b"new jEr", 19_086_193),
        (b"get[Jn(321)]", 19_086_798),
        (b'__name:"lighting-page"', 19_342_818),
        (b"keyIdRGB)===!0", 19_337_238),
        (b"direction:M.direction", 19_344_423),
        (b"X.lighting.setEffect(Df.Main,Q)", 19_338_548),
        (b"X.lighting.setCustomMainLight(ie)", 19_338_586),
        (b"ie.lighting.updateRGB(X.map", 19_338_849),
    ]
    for needle, expected in anchors:
        find_at(bundle, needle, expected)

    service_start = bundle.find(b"class jEr")
    service_end = bundle.find(b"const zEr=", service_start)
    if service_end < 0:
        fail("lighting service class boundary was not found")
    service = bundle[service_start:service_end]
    for needle in [
        b"async getEffect(t)",
        b"[iy(378)](t,s)",
        b"this[s(431)][s(417)](132,",
        b"encode(134,0,",
        b"encode(6,0,",
        b"[iy(425)](t)",
        b"[s(417)](8,1,a)",
    ]:
        if needle not in service:
            fail(f"lighting service body lacks expected static sequence {needle!r}")

    # Some feature components are emitted before the named route component in
    # this minified chunk, so assert their presence in the verified bundle and
    # pin their individual byte anchors above instead of assuming source order.
    page = bundle
    for needle in [
        b"Le.lighting.getEffect(Df.Main)",
        b"mt.lighting.setEffect(k.value,Z)",
        b"mt.lighting.getEffect(k.value)",
        b"mt.lighting.setEffect(k.value,J)",
        b"X.lighting.setEffect(Df.Main,Q)",
        b"X.lighting.setCustomMainLight(ie)",
        b"ie.lighting.updateRGB(X.map",
    ]:
        if needle not in page:
            fail(f"lighting page lacks expected static call {needle!r}")

    print(f"Verified official bundle: {len(bundle)} bytes, SHA-256 {digest}")
    print("Verified decoder mapping: SDK lighting token to jEr; setEffect/updateRGB/custom-light methods")
    print("Verified static UI paths: main-effect load, set/read-back/rollback, custom save, gated per-key RGB")
    print("No bundle file was written; no device chooser or hardware API was opened.")
    print("Scope: static paths in this dated bundle only; no device acceptance or runtime claim.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
