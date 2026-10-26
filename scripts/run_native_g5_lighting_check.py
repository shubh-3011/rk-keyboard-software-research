"""Validate the published G5 query path; no configuration/firmware writes.

One active command-84 query, closing/restarting only the hash-checked vendor
utility normally. The helper process performs no input-report reads.
"""
import argparse
import ctypes
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SHA = 'c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6'


def validate_query_report(report):
    block = bytes.fromhex(report['LightingBlockHex'])
    header = bytes.fromhex(report['ResponseHeaderHex'])
    if (report['Format'] != 'rk-rebuild-experimental-g5-lighting-read' or report['SchemaVersion'] != 1
            or report['SettingsWritesPerformed'] or report['SetFeatureCalls'] != 1 or report['GetFeatureCalls'] != 1
            or report['QueryCommand'] != '84' or report['FeatureReportBytes'] != 520
            or report['UsagePage'] != 'FF02' or report['Usage'] != '0002'
            or len(block) != 128 or block[-2:] != b'\x5a\xa5' or len(header) != 8
            or header[1] != 0x84 or header[0] != int(report['ReportIdHex'], 16)):
        raise ValueError('Incomplete or inconsistent native feature-query result')
    return block


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity', required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    args = parser.parse_args()
    args.output_directory.mkdir(parents=True, exist_ok=False)
    app = ROOT / 'rebuild/windows/dist/RK-Rebuild.exe'
    if not app.is_file():
        parser.error('Build the published application first')
    process = json.loads(subprocess.check_output(['powershell', '-NoProfile', '-Command',
        'Get-CimInstance Win32_Process -Filter "Name=\'DeviceDriver.exe\'" | Select-Object ProcessId,ExecutablePath | ConvertTo-Json'], text=True))
    if not isinstance(process, dict):
        raise RuntimeError('Expected exactly one vendor process')
    binary = Path(process['ExecutablePath'])
    if str(binary).lower() != r'C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe'.lower() or hashlib.sha256(binary.read_bytes()).hexdigest() != SHA:
        raise RuntimeError('Vendor identity mismatch')
    pid = process['ProcessId']
    user = ctypes.WinDLL('user32', use_last_error=True)
    callback = ctypes.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
    user.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]
    user.GetWindowTextW.argtypes = [w.HWND, w.LPWSTR, ctypes.c_int]
    user.GetClassNameW.argtypes = [w.HWND, w.LPWSTR, ctypes.c_int]
    user.PostMessageW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]
    windows = []
    def visit(handle, _):
        owner = w.DWORD()
        user.GetWindowThreadProcessId(handle, ctypes.byref(owner))
        if owner.value == pid:
            title, name = ctypes.create_unicode_buffer(200), ctypes.create_unicode_buffer(100)
            user.GetWindowTextW(handle, title, 200)
            user.GetClassNameW(handle, name, 100)
            if title.value == 'RK Keyboard' and name.value == '#32770':
                windows.append(handle)
        return True
    user.EnumWindows(callback(visit), 0)
    if len(windows) != 1 or not user.PostMessageW(w.HWND(windows[0]), 0x111, 0x6401, 0):
        raise RuntimeError('No uniquely attributed vendor main dialog')
    subprocess.run(['powershell', '-NoProfile', '-Command',
        f'$p=Get-Process -Id {pid} -ErrorAction SilentlyContinue; if ($p -and -not $p.WaitForExit(10000)) {{ throw "Normal vendor exit timed out" }}'], check=True)
    state = {'Format': 'published-native-g5-query-check', 'SchemaVersion': 1,
             'ExecutableSha256': hashlib.sha256(app.read_bytes()).hexdigest(),
             'VendorSha256': SHA, 'Identity': args.identity, 'ConfigurationWritesPerformed': False}
    report_path = args.output_directory / 'query.json'
    try:
        completed = subprocess.run([str(app), '--read-g5-lighting', args.identity, str(report_path.resolve())], timeout=20)
        state['ExitCode'] = completed.returncode
        if completed.returncode == 0:
            report = json.loads(report_path.read_text())
            block = validate_query_report(report)
            state['BlockBytes'] = len(block)
            state['ReportIdHex'] = report['ReportIdHex']
            state['QueryReportSha256'] = hashlib.sha256(report_path.read_bytes()).hexdigest()
            state['ValidatedQueryResult'] = True
    finally:
        subprocess.Popen([str(binary), '-s'])
        state['VendorRestartRequested'] = True
        (args.output_directory / 'summary.json').write_text(json.dumps(state, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(state, indent=2))
    if not state.get('ValidatedQueryResult'):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
