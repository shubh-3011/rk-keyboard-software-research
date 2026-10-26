// Bounded process-local observation of the installed hash-pinned 4.06 image.
// Host MUST verify executable path/SHA-256/PID before attachment.
// Does not read arguments, input, report buffers, config state or arbitrary memory.
// Does not call vendor functions, change controls, open devices or send commands.
// REA handles session unload/detach; our timer first removes all six interceptors.
'use strict';

const module = Process.mainModule;
if (Process.arch !== 'ia32' || module.name.toLowerCase() !== 'devicedriver.exe')
    throw new Error('Expected the installed x86 DeviceDriver.exe target');

const hooks = [
    ['slider_mouse_up', 0x4d150, '558bec83e4f883ec'],
    ['lighting_parent_message', 0x22190, '8b442408568bf18b'],
    ['lighting_state_copy', 0x25440, '56578b3d????????'],
    ['slider_value_getter', 0x4db20, '8b81a00900008b91'],
    ['lighting_packer_firmware2', 0x11700, '83ec18a1????????'],
    ['lighting_packer_ordinary', 0x11900, '83ec18a1????????']
];
// Verify all instruction witnesses before installing any interceptor.
// '?' masks only the known IMAGE_REL_BASED_HIGHLOW immediate bytes affected by ASLR.
for (const [name, rva, expected] of hooks) {
    const bytes = new Uint8Array(module.base.add(rva).readByteArray(8));
    const actual = Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
    for (let index = 0; index < 8; index++) {
        const witness = expected.slice(index * 2, index * 2 + 2);
        if (witness !== '??' && actual.slice(index * 2, index * 2 + 2) !== witness)
            throw new Error('Target instruction mismatch: ' + name);
    }
}
for (const [rva, pointerRva] of [[0x25444, 0x22b388], [0x11704, 0x201660], [0x11904, 0x201660]]) {
    if (!module.base.add(rva).readPointer().equals(module.base.add(pointerRva)))
        throw new Error('Relocated instruction operand mismatch at RVA ' + rva.toString(16));
}
const counts = {};
const listeners = [];
const started = Date.now();
try {
    for (const [name, rva] of hooks) {
        counts[name] = 0;
        listeners.push(Interceptor.attach(module.base.add(rva), { onEnter() { counts[name]++; } }));
    }
} catch (error) {
    for (const listener of listeners) listener.detach();
    throw error;
}
send({ kind: 'observation_started', pid: Process.id, module: module.name, module_base: module.base.toString(),
       hook_count: listeners.length, capture_scope: 'six entry counters only; no arguments/input/reports; no UI action' });
setTimeout(() => {
    for (const listener of listeners) listener.detach();
    Interceptor.flush();
    send({ kind: 'observation_finished', duration_ms: Date.now() - started, counts,
           interceptors_detached: listeners.length, ui_actions: 0, device_commands_issued_by_script: 0 });
}, 1800);
