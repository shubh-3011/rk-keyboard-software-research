"""Retain reviewed lighting-only runtime frames as deterministic codec fixtures.

This reads a saved direct-Frida trace; it never runs a target or accesses HID.
The source trace and source-script hashes distinguish fixtures from REA Evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path


def extract(path):
    raw = path.read_bytes()
    source = json.loads(raw)
    if source.get('format') != 'rk-runtime-lighting-roundtrip' or source.get('binary_sha256') != 'c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6':
        raise ValueError('Wrong observation format or executable identity')
    if source.get('error') or not source.get('restored_tree_selection'):
        raise ValueError('Require a completed, restored observation')
    if source['observation_summary']['dropped'] or source.get('cleanup_error'):
        raise ValueError('Incomplete observation')
    reports = [event['payload'] for event in source['events'] if event.get('payload', {}).get('kind') == 'lighting_report']
    if len(reports) != 62 or any(event.get('type') == 'error' or event.get('payload', {}).get('kind') == 'capture_error' for event in source['events']):
        raise ValueError('Expected exactly 62 reports without capture errors')
    phases = {}
    for phase in ('select-first-effect', 'restore-original-effect'):
        sets = {}
        for direction, command, name in (('out', 0x44, 'Query'), ('in', 0x44, 'Read'), ('out', 4, 'Write'), ('in', 4, 'Echo')):
            frames = [item['bytes'] for item in reports if item['phase'] == phase and item['direction'] == direction and item['command'] == command]
            expected = 1 if name == 'Query' else 10
            if len(frames) != expected or any(len(frame) != 20 for frame in frames):
                raise ValueError('Unexpected frame count/size for ' + name)
            if name == 'Query':
                if bytes(frames[0]) != bytes([0x13, 0x44, 1] + [0] * 16 + [0x58]):
                    raise ValueError('Unexpected query request')
            else:
                for index, frame in enumerate(frames):
                    if frame[:4] != [0x13, command, 10, index] or frame[4] != (14 if index < 9 else 2):
                        raise ValueError('Unexpected block frame header')
                block = bytes(value for frame in frames for value in frame[5:5 + (frame[4] & 15)])
                if len(block) != 128 or block[-2:] != b'\x5a\xa5':
                    raise ValueError('Invalid block shape/signature')
                sets[name + 'BlockHex'] = block.hex()
            sets[name + 'FramesHex'] = [bytes(frame).hex() for frame in frames]
        if sets['WriteBlockHex'] != sets['EchoBlockHex']:
            raise ValueError('Write echoes differ')
        changes = [(index, before, after) for index, (before, after) in enumerate(zip(bytes.fromhex(sets['ReadBlockHex']), bytes.fromhex(sets['WriteBlockHex']))) if before != after]
        if changes != [(10, 0, 1)] and changes != [(10, 1, 0)]:
            raise ValueError('Unexpected non-mode changes; do not silently call this a one-byte fixture')
        phases[phase] = sets
    if phases['select-first-effect']['WriteBlockHex'] != phases['restore-original-effect']['ReadBlockHex']:
        raise ValueError('Subsequent device read does not match prior write')
    if phases['select-first-effect']['ReadBlockHex'] != phases['restore-original-effect']['WriteBlockHex']:
        raise ValueError('Original block was not restored byte-for-byte')
    return {'Format': 'rk406-observed-wireless-lighting-fixture', 'SchemaVersion': 1,
            'BinarySha256': source['binary_sha256'], 'SourceTraceSha256': hashlib.sha256(raw).hexdigest(),
            'SourceScriptSha256': source['script_sha256'], 'Transport': '20-byte wireless child under CDevG5KB',
            'Limitations': ['One runtime fixture, not universal model certification.',
                            'Query-response checksum differs from outgoing additive checksum; no guessed response-checksum rule.',
                            'Subsequent query validates the first write; final restoration has byte-identical output and echoes but no independent final query in this trace.'],
            'Phases': phases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    fixture = extract(args.trace)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(fixture, stream, indent=2)
        stream.write('\n')
    print('Verified 62 lighting frames, subsequent readback of first write, exact original-block restoration output/echo.')


if __name__ == '__main__':
    main()
