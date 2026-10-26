// PREPARED ONLY; not executed in the static investigation.
// Host must independently hash the selected process image before attachment.
// RPC argument is an attestation, NOT an in-process digest verification.
// Reads only selected list node -> device -> vtable, and (G5 only) VID/PID/ID.
// No hooks, NativeFunction, writes, handles, paths, child traversal or reports.
'use strict';
const expectedSha = 'c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6';
const image = Process.mainModule;
const at = va => image.base.add(va - 0x400000);
function readable(p, size) {
    const r = Process.findRangeByAddress(p);
    if (!r || r.protection.indexOf('r') < 0 || p.add(size).compare(r.base.add(r.size)) > 0)
        throw new Error('Bounded source not readable');
}
function source(va, size) {
    const p = at(va);
    if (p.compare(image.base) < 0 || p.add(size).compare(image.base.add(image.size)) > 0)
        throw new Error('Source outside main image');
    readable(p, size);
    return p;
}
// Operand offsets below are actual PE HIGHLOW relocation sites, not wildcards.
const witnesses = [
    [0x4011e6, 'a180b36200', [1]],
    [0x401222, '8b30', []],
    [0x401227, '0fb7964a020000', []],
    [0x40122e, '0fb78648020000', []],
    [0x401238, '8b16', []],
    [0x40ece3, 'c7062cba5c00', [2]],
    [0x40f443, '8a56e48b4c24148897d0020000', []],
    [0x40f53c, '66898f48020000', []],
    [0x40f546, '6689974a020000', []],
    [0x40fb27, '0fb680d0020000', []]
];
function guard() {
    for (const [va, hex, relocations] of witnesses) {
        const bytes = hex.match(/../g).map(x => parseInt(x, 16));
        for (const offset of relocations) {
            const original = (bytes[offset] | bytes[offset + 1] << 8 |
                bytes[offset + 2] << 16 | bytes[offset + 3] << 24) >>> 0;
            const rebased = at(original).toUInt32();
            for (let j = 0; j < 4; ++j) bytes[offset + j] = (rebased >>> (8 * j)) & 255;
        }
        const actual = new Uint8Array(source(va, bytes.length).readByteArray(bytes.length));
        if (bytes.some((b, i) => actual[i] !== b))
            throw new Error('Instruction mismatch at preferred VA 0x' + va.toString(16));
    }
}
rpc.exports = {
    snapshot(hostVerifiedSha256) {
        if (Process.arch !== 'ia32' || Process.pointerSize !== 4 ||
            image.name.toLowerCase() !== 'devicedriver.exe' || hostVerifiedSha256 !== expectedSha)
            throw new Error('Requires independently verified installed x86 4.06 image');
        guard(); // No state reads until ALL witnesses pass.
        const anchor = source(0x62b380, 4);
        const root = anchor.readPointer();
        const result = { kind: 'bounded_g5_query_identity',
            binary_sha256_host_attestation: expectedSha,
            instruction_witnesses_checked: witnesses.length,
            selected_root_present: !root.isNull(), root_class: null,
            vid: null, pid: null, report_id: null,
            device_commands_issued_by_script: 0, vendor_functions_called_by_script: 0,
            limitation: 'Not atomic; matching anchor rereads do not exclude ABA or concurrent changes. No endpoint binding or physical-model proof.' };
        if (root.isNull()) {
            if (!anchor.readPointer().equals(root)) throw new Error('Root changed');
            return result;
        }
        readable(root, 4);
        const device = root.readPointer();
        if (device.isNull()) throw new Error('Selected node has no device');
        readable(device, 4);
        const table = device.readPointer();
        const classes = [[0x5cba2c, 'CDevG5KB'], [0x5cbe0c, 'CDevRKKB'], [0x5ca32c, 'CDev3632']];
        const match = classes.find(([va]) => table.equals(at(va)));
        result.root_class = match ? match[1] : 'unmapped-vtable';
        if (result.root_class === 'CDevG5KB') {
            readable(device.add(0x248), 4);
            readable(device.add(0x2d0), 1);
            result.vid = device.add(0x248).readU16();
            result.pid = device.add(0x24a).readU16();
            result.report_id = device.add(0x2d0).readU8();
        }
        if (!anchor.readPointer().equals(root) || !root.readPointer().equals(device) ||
            !device.readPointer().equals(table)) throw new Error('Selection changed');
        if (result.root_class === 'CDevG5KB' &&
            (device.add(0x248).readU16() !== result.vid ||
             device.add(0x24a).readU16() !== result.pid ||
             device.add(0x2d0).readU8() !== result.report_id)) throw new Error('Identity changed');
        return result; // No pointers, handles, paths, keymaps or configuration data.
    }
};
