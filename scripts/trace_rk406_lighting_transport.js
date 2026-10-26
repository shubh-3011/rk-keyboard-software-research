// Hash-bound installed 4.06 observation only. No vendor or HID calls are made.
// Captures only lighting commands in known vendor wrapper scopes, never input reports.
'use strict';
const image = Process.mainModule;
if (Process.arch !== 'ia32' || image.name.toLowerCase() !== 'devicedriver.exe') throw new Error('Wrong target');
const at = va => image.base.add(va - 0x400000);
const node = at(0x62b380).readPointer();
if (node.isNull() || !node.readPointer().readPointer().equals(at(0x5cba2c))) throw new Error('Expected observed G5 root; do not infer from VID/PID');
const listeners = [], depths = {}, handles = new Set();
let phase = 'baseline', emitted = 0, dropped = 0;
const counts = {};
function log(payload) {
    if (emitted++ >= 300) { dropped++; return; }
    send(Object.assign({ phase, timestamp_ms: Date.now() }, payload));
}
function bytes(pointer, length) { return Array.from(new Uint8Array(pointer.readByteArray(length))); }
function capture(api, handle, pointer, length, incoming) {
    try {
        if (length !== 20 && length !== 520) return;
        const header = bytes(pointer, 8), command = header[1];
        if (length === 20 && (header[0] !== 0x13 || (command !== 4 && command !== 0x44))) return;
        if (length === 520 && command !== 4 && command !== 0x84) return;
        if (incoming && !handles.has(handle)) return;
        if (!incoming) handles.add(handle);
        log({ kind: 'lighting_report', api, direction: incoming ? 'in' : 'out', length, command,
              // Opaque handles are deliberately not exported.
              bytes: bytes(pointer, length) });
    } catch (error) { log({ kind: 'capture_error', api, message: String(error) }); }
}
function hook(address, callbacks) { listeners.push(Interceptor.attach(address, callbacks)); }
try {
    for (const [name, address] of [['g5_access', 0x40f700], ['g5_lighting_query', 0x40fad0], ['wireless_access', 0x40d7e0]]) {
        hook(at(address), {
            onEnter() { this.thread = Process.getCurrentThreadId(); depths[this.thread] = (depths[this.thread] || 0) + 1; counts[name] = (counts[name] || 0) + 1; },
            onLeave() { depths[this.thread]--; }
        });
    }
    for (const [name, address] of [['lighting_state_copy', 0x425440], ['g5_apply', 0x411b90], ['ordinary_packer', 0x411900], ['firmware2_packer', 0x411700]])
        hook(at(address), { onEnter() { counts[name] = (counts[name] || 0) + 1; log({ kind: 'native_entry', name }); } });
    function exportAddress(name) {
        for (const module of Process.enumerateModules()) { const found = module.findExportByName(name); if (found) return found; }
        throw new Error('Required loaded export missing: ' + name);
    }
    for (const api of ['HidD_SetFeature', 'WriteFile']) hook(exportAddress(api), {
        onEnter(args) {
            if (!depths[Process.getCurrentThreadId()]) return;
            capture(api, args[0].toString(), args[1], args[2].toUInt32(), false);
        }
    });
    hook(exportAddress('HidD_GetFeature'), {
        onEnter(args) { this.allowed = !!depths[Process.getCurrentThreadId()]; if (this.allowed) { this.handle = args[0].toString(); this.buffer = args[1]; this.length = args[2].toUInt32(); } },
        onLeave(result) { if (this.allowed && result.toInt32() !== 0) capture('HidD_GetFeature', this.handle, this.buffer, this.length, true); }
    });
    // True entry 0x40D2E0: ESI points to a 20-byte vendor frame; EDI is the child.
    // Never hook ReadFile or dump keyboard/consumer-control input buffers.
    hook(at(0x40d2e0), { onEnter() {
        const handle = this.context.edi.add(4).readPointer().toString();
        if (handles.has(handle)) capture('vendor_3632_dispatch', handle, this.context.esi, 20, true);
    } });
    log({ kind: 'ready', hook_count: listeners.length, observed_root: 'CDevG5KB', source: 'installed-4.06' });
} catch (error) { for (const listener of listeners) listener.detach(); throw error; }
rpc.exports = {
    phase(name) { phase = String(name); log({ kind: 'phase' }); },
    stop() { for (const listener of listeners) listener.detach(); Interceptor.flush(); return { counts, emitted, dropped, detached: listeners.length }; }
};
