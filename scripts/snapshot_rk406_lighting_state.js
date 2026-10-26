// Host must hash-check the exact installed 4.06 image before attaching.
// Reads only active list-node -> device -> vtable/Apply target and lighting row/value.
// No keymaps, macro data, input reports, user text, device API or vendor calls.
'use strict';
const image = Process.mainModule;
if (Process.arch !== 'ia32' || image.name.toLowerCase() !== 'devicedriver.exe')
    throw new Error('Expected installed x86 DeviceDriver.exe');
const preferred = 0x400000;
const at = va => image.base.add(va - preferred);
const relative = address => {
    if (address.compare(image.base) < 0 || address.compare(image.base.add(image.size)) >= 0) return null;
    return '0x' + address.sub(image.base).toString(16);
};
const result = { kind: 'bounded_lighting_state', pid: Process.id, image_base: image.base.toString(),
    active_root_present: false, config_present: false, source: 'installed-4.06', reads: [],
    device_commands_issued_by_script: 0, vendor_functions_called_by_script: 0 };
const root = at(0x62b380).readPointer();
if (!root.isNull()) {
    result.active_root_present = true;
    // Global holds a LIST NODE, not the device itself (worker 0x4011E6 onward).
    const device = root.readPointer();
    if (device.isNull()) throw new Error('Active list node has no device');
    const table = device.readPointer();
    result.vtable_rva = relative(table);
    result.root_vtable_state = result.vtable_rva === null ? 'outside-target-image; no Apply target dereferenced' : 'inside-target-image';
    if (result.vtable_rva !== null) result.apply_target_rva = relative(table.add(0x3c).readPointer());
    const names = { '0x1cbe0c': 'CDevRKKB', '0x1cba2c': 'CDevG5KB', '0x1ca32c': 'CDev3632' };
    result.observed_root_class = names[result.vtable_rva] || 'unmapped-vtable';
    result.reads.push(result.vtable_rva === null ? 'list node -> device -> first pointer; unclassified' : 'list node -> device -> vtable; vtable+0x3C function pointer');
}
const config = at(0x62b388).readPointer();
if (!config.isNull()) {
    result.config_present = true;
    result.selected_ordinal = config.add(0x213c).readU32();
    result.reads.push('config+0x213C selected ordinal');
    if (result.selected_ordinal < 24) {
        result.brightness_index = config.add(0x2144 + result.selected_ordinal * 0x30).readU32();
        result.reads.push('selected lighting record+4 brightness index');
    }
}
send(result);
