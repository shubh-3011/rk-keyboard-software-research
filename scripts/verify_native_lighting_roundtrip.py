"""Validate and retain the native application's two explicit mode operations."""
import argparse
import hashlib
import json
from pathlib import Path


def validate(document):
    if document['Format'] != 'native-verified-lighting-mode-roundtrip':
        raise ValueError('Wrong format')
    for name, start, target in (('On', 0, 1), ('Off', 1, 0)):
        operation = document[name]
        summary, before, applied, after = [operation[key] for key in ('summary', 'before', 'apply', 'after')]
        if any(summary[key] != 0 for key in ('PreflightExit', 'ApplyExit', 'IndependentQueryExit')) or summary['AutomaticRetryOrRollback']:
            raise ValueError('Operation did not complete without retry/rollback')
        if not summary['IndependentQueryMatchesIntendedBlock'] or summary['TargetMode'] != target:
            raise ValueError('Independent query did not verify target')
        a, b = bytes.fromhex(before['LightingBlockHex']), bytes.fromhex(after['LightingBlockHex'])
        if len(a) != 128 or len(b) != 128 or a[-2:] != b'\x5a\xa5' or b[-2:] != b'\x5a\xa5':
            raise ValueError('Bad block shape/signature')
        if a[10] != start or b[10] != target or [i for i, (x, y) in enumerate(zip(a, b)) if x != y] != [10]:
            raise ValueError('Unexpected state change')
        if not applied['VerifiedByQuery'] or applied['NoOp'] or applied['ConfigurationReportsSent'] != 10:
            raise ValueError('Transaction itself was not verified')
        if applied['BaselineBlockHex'] != before['LightingBlockHex'] or applied['VerifiedBlockHex'] != after['LightingBlockHex']:
            raise ValueError('Transaction and independent query disagree')
        if before['SettingsWritesPerformed'] or after['SettingsWritesPerformed']:
            raise ValueError('Query reports incorrectly claim writes')
    if document['On']['after']['LightingBlockHex'] != document['Off']['before']['LightingBlockHex']:
        raise ValueError('Intermediate state changed between operations')
    if document['On']['before']['LightingBlockHex'] != document['Off']['after']['LightingBlockHex']:
        raise ValueError('Original block was not restored')
    if document['On']['summary']['AppAssemblySha256'] != document['Off']['summary']['AppAssemblySha256']:
        raise ValueError('Mixed application builds')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('on_directory', type=Path)
    parser.add_argument('off_directory', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    document = {'Format': 'native-verified-lighting-mode-roundtrip', 'SchemaVersion': 1,
                'Limitations': ['One connected fixture, one protocol path, two complete configuration fingerprints; not model certification.',
                                'Native CLI tested; WPF apply interactions not yet manually exercised.'],
                'SourceRecordSha256': {}}
    for name, directory in (('On', args.on_directory), ('Off', args.off_directory)):
        operation = {}
        for kind in ('summary', 'before', 'apply', 'after'):
            raw = (directory / (kind + '.json')).read_bytes()
            document['SourceRecordSha256'][name + '/' + kind] = hashlib.sha256(raw).hexdigest()
            operation[kind] = json.loads(raw)
        document[name] = operation
    validate(document)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(document, stream, indent=2)
        stream.write('\n')
    print('PASS: native mode round trip, both transaction verifications, independent queries, exact original-block restoration.')


if __name__ == '__main__':
    main()
