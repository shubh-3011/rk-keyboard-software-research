// Bounded scalar observation only; profile binding is not device identity.
// Host MUST independently SHA-256-check the selected process's installed image,
// then pass that digest to rpc.exports.snapshot(). A supplied digest is an
// attestation, not an in-process hash check. See the companion next-step report.
// One-shot bounded reads only: no hooks, writes, NativeFunction, vendor calls,
// keymaps, macros, paths, handles, device traversal, reports, or UI operations.
'use strict';
const expectedSha = 'c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6';
const image = Process.mainModule;
const preferred = 0x400000;
const at = va => image.base.add(va - preferred);
function readable(p, size) {
    const r = Process.findRangeByAddress(p);
    if (!r || r.protection.indexOf('r') < 0 || p.add(size).compare(r.base.add(r.size)) > 0)
        throw new Error('Required bounded source is not readable');
}
function imageSource(va, size) {
    const p = at(va);
    if (p.compare(image.base) < 0 || p.add(size).compare(image.base.add(image.size)) > 0)
        throw new Error('Required source outside main image');
    readable(p, size);
    return p;
}
// Exact on-disk instruction bytes, with explicit HIGHLOW relocation operand
// offsets. No wildcard operands: each relocated address is checked after rebasing.
const witnesses = [
    [0x4465e0, '8b158e156100', [2]], // distinct constructor-scan scalar
    [0x4513fb, '893d5c176100', [2]], // loader stores active profile scalar
    [0x424aea, '8b0d5c176100', [2]], // lighting UI consumes active scalar
    [0x447941, '891d5c176100', [2]], // active scalar has another mutation site
    [0x451426, 'a360176100', [1]],   // Fw
    [0x4514e8, 'a398176100', [1]],   // LedMask
    [0x4516b5, 'a3cc176100', [1]],   // GaoshouIndex
    [0x4516f2, 'a3d0176100', [1]],   // resolved RGBOFFIndex
    [0x451c2a, 'a350186100', [1]],   // DefBri
    [0x451abe, 'bf54186100', [1]],   // LightUI base
    [0x451bcb, 'bf68186100', [1]],   // LightHW base
    [0x451ab8, '6a14', []],         // byte-table capacity
    [0x451bc8, '6a14', []],
    [0x4530f1, 'bd141a6100', [1]],   // mapping row+4 start
    [0x4531ca, '894dfc', []],        // tuple cell 1 -> row+0
    [0x45323d, '83c53c', []],        // profile table stride
    [0x453242, '81fdb41f6100', [2]], // 24-row end
    [0x41191c, 'b84c1a6100', [1]],   // ordinary first-15 gate
    [0x41192e, '3dd01d6100', [1]],
    [0x42343e, 'a2002b6100', [1]],   // runtime lighting row count
    [0x424b48, 'a188b36200', [1]],   // active config pointer
    [0x411939, '0fb68b3c210000', []],// selected ordinal byte (serializer)
    [0x45a551, '89953c210000', []],  // selected ordinal DWORD (initializer)
    [0x424bca, '8b841144210000', []],// brightness absolute config+2144
    [0x45a4fb, '8d8540210000', []],  // canonical row start
    [0x45a53f, '83c030', []],        // canonical row stride
    [0x411a50, '0fb68968186100', [3]] // brightness -> LightHW
];
function guardInstructions() {
    for (const [va, hex, relocations] of witnesses) {
        const bytes = hex.match(/../g).map(x => parseInt(x, 16));
        for (const offset of relocations) {
            const original = (bytes[offset] | bytes[offset + 1] << 8 |
                bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0;
            const rebased = at(original).toUInt32();
            for (let j = 0; j < 4; ++j) bytes[offset + j] = (rebased >>> (8 * j)) & 255;
        }
        const actual = new Uint8Array(imageSource(va, bytes.length).readByteArray(bytes.length));
        if (bytes.some((b, i) => actual[i] !== b))
            throw new Error('Instruction identity mismatch at preferred VA 0x' + va.toString(16));
    }
}
rpc.exports = {
    snapshot(hostVerifiedSha256) {
        if (Process.arch !== 'ia32' || Process.pointerSize !== 4 ||
            image.name.toLowerCase() !== 'devicedriver.exe' || hostVerifiedSha256 !== expectedSha)
            throw new Error('Requires independently hash-verified installed x86 4.06 image');
        guardInstructions(); // ALL address witnesses before any state source reads
        const loaded = imageSource(0x61175c, 4).readU32();
        const scan = imageSource(0x61158e, 2).readU16();
        if (loaded === 0 || loaded > 0xffff) throw new Error('No valid loaded profile; brightness binding unavailable');
        const config = imageSource(0x62b388, 4).readPointer();
        if (config.isNull()) throw new Error('No selected configuration');
        readable(config.add(0x213c), 4);
        const selected = config.add(0x213c).readU32();
        if (selected >= 24) throw new Error('Selected ordinal outside 0..23');
        const count = imageSource(0x612b00, 1).readU8();
        if (count > 24) throw new Error('Lighting count exceeds 24');
        const mappings = [];
        for (let i = 0; i < 24; ++i)
            mappings.push(imageSource(0x611a10 + i * 0x3c, 4).readU32());
        const brightnessSource = config.add(0x2144 + selected * 0x30);
        readable(brightnessSource, 4);
        const brightness = brightnessSource.readU32();
        const defaultBrightness = imageSource(0x611850, 4).readU32();
        // 20 is the parser destination capacity, NOT an observed valid list length.
        // A value within capacity may still be outside the selected INI's list.
        function translation(index) {
            if (index >= 20) return { index, within_capacity: false };
            return { index, within_capacity: true,
                light_ui_byte: imageSource(0x611854 + index, 1).readU8(),
                light_hw_byte: imageSource(0x611868 + index, 1).readU8() };
        }
        const result = {
            kind: 'bounded_brightness_mapping', binary_sha256_host_attestation: expectedSha,
            instruction_witnesses_checked: witnesses.length,
            loaded_profile_code_hex: loaded.toString(16).padStart(4, '0').toUpperCase(),
            constructor_scan_code_hex: scan.toString(16).padStart(4, '0').toUpperCase(),
            fw: imageSource(0x611760, 4).readU32(),
            led_mask: imageSource(0x611798, 4).readU32(),
            gaoshou_index: imageSource(0x6117cc, 4).readU32(),
            rgb_off_index: imageSource(0x6117d0, 4).readS32(),
            runtime_row_count: count, selected_ordinal: selected,
            mapping_dwords_24: mappings,
            ordinary_gate_sum_signed32: mappings.slice(0, 15).reduce((a, b) => (a + b) | 0, 0),
            selected_brightness: translation(brightness),
            profile_default_brightness: translation(defaultBrightness),
            translation_capacity: 20, valid_translation_length: null,
            device_commands_issued_by_script: 0, vendor_functions_called_by_script: 0,
            limitation: 'Not atomic; equal anchor rereads do not exclude concurrent changes. Loaded scalar does not prove physical model, INI contents or endpoint binding.'
        };
        if (imageSource(0x61175c, 4).readU32() !== loaded || imageSource(0x61158e, 2).readU16() !== scan ||
            !imageSource(0x62b388, 4).readPointer().equals(config) ||
            config.add(0x213c).readU32() !== selected || brightnessSource.readU32() !== brightness)
            throw new Error('Selection changed during snapshot; no result emitted');
        return result; // no raw pointers, process identity, paths, or handles emitted
    }
};
