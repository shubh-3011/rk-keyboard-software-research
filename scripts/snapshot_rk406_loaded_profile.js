'use strict';
// Passive scalar-only observer. No hooks, native calls, device IO or mutations.
// Host must independently hash the actual process image before calling snapshot.
const expected = 'c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6';
const image = Process.mainModule;
const at = va => image.base.add(va - 0x400000);
function source(va, length) {
    const p = at(va);
    if (p.compare(image.base) < 0 || p.add(length).compare(image.base.add(image.size)) > 0)
        throw new Error('Outside main image');
    const range = Process.findRangeByAddress(p);
    if (!range || !range.protection.includes('r') || p.add(length).compare(range.base.add(range.size)) > 0)
        throw new Error('Unreadable scalar/witness');
    return p;
}
const witnesses = [
    [0x4513cb, '8bf957', []], // loader saves ECX profile argument in EDI
    [0x4513d9, '68b44e5d0057681895610068c44e5d00', [1, 7, 12]],
    [0x4513fb, '893d5c176100', [2]], // loader stores same EDI as loaded code
    [0x424aea, '8b0d5c176100', [2]], // lighting UI consumes loaded code
    [0x447941, '891d5c176100', [2]], // separate clearing/mutation site
    [0x4465e0, '8b158e156100', [2]] // distinct constructor-scan scalar
];
rpc.exports = { snapshot(hostSha) {
    if (hostSha !== expected || Process.arch !== 'ia32' || Process.pointerSize !== 4 || image.name.toLowerCase() !== 'devicedriver.exe')
        throw new Error('Requires independently verified installed 4.06 x86 image');
    for (const [va, hex, offsets] of witnesses) {
        const bytes = hex.match(/../g).map(value => parseInt(value, 16));
        for (const offset of offsets) {
            const original = (bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0;
            const value = at(original).toUInt32();
            for (let j = 0; j < 4; j++) bytes[offset + j] = (value >>> (8 * j)) & 255;
        }
        const actual = new Uint8Array(source(va, bytes.length).readByteArray(bytes.length));
        if (bytes.some((value, index) => value !== actual[index])) throw new Error('Instruction mismatch');
    }
    const loaded = source(0x61175c, 4).readU32();
    const scan = source(0x61158e, 2).readU16();
    if (loaded > 0xffff) throw new Error('Loaded profile scalar outside code range');
    if (source(0x61175c, 4).readU32() !== loaded || source(0x61158e, 2).readU16() !== scan) throw new Error('Profile scalars changed');
    return { kind: 'bounded_loaded_profile_scalars', binary_sha256_host_attestation: expected,
        loaded_profile_code_hex: loaded.toString(16).toUpperCase().padStart(4, '0'),
        constructor_scan_code_hex: scan.toString(16).toUpperCase().padStart(4, '0'),
        instruction_witnesses_checked: witnesses.length, device_commands_issued_by_script: 0,
        vendor_functions_called_by_script: 0,
        limitation: 'Non-atomic scalar observation, not proof of physical model, current INI contents or endpoint binding. Loaded scalar also has an independent mutation site.' };
} };
