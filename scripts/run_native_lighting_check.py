"""Explicit single-mode native test; fresh query, gated apply, independent query.

Never retries or rolls back, including when verification fails. Closes only the
hash-checked vendor utility through its normal Exit command and restarts it.
Output directory must be new. No input capture or raw HID path export.
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', type=int, choices=(0, 1), required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--confirm-experimental-write', action='store_true', required=True)
    args = parser.parse_args()
    args.output_directory.mkdir(parents=True, exist_ok=False)
    process = json.loads(subprocess.check_output(['powershell', '-NoProfile', '-Command',
        'Get-CimInstance Win32_Process -Filter "Name=\'DeviceDriver.exe\'" | Select-Object ProcessId,ExecutablePath | ConvertTo-Json'], text=True))
    if not isinstance(process, dict):
        raise RuntimeError('Expected exactly one existing vendor process; no lifecycle guessing')
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
        raise RuntimeError('No uniquely attributed vendor main dialog; stop')
    subprocess.run(['powershell', '-NoProfile', '-Command',
        f'$p=Get-Process -Id {pid} -ErrorAction SilentlyContinue; if ($p -and -not $p.WaitForExit(10000)) {{ throw "Normal vendor exit timed out" }}'], check=True)
    runtime = ROOT / 'rebuild/windows/.dotnet/dotnet.exe'
    app = ROOT / 'rebuild/windows/bin/Release/net8.0-windows/RK-Rebuild.dll'
    def run(*arguments):
        return subprocess.run([str(runtime), str(app), *map(str, arguments)], timeout=20).returncode
    state = {'Format': 'native-single-mode-hardware-check', 'TargetMode': args.mode,
             'AppAssemblySha256': hashlib.sha256(app.read_bytes()).hexdigest(),
             'VendorSha256': SHA, 'AutomaticRetryOrRollback': False}
    before, result, after = [args.output_directory / name for name in ('before.json', 'apply.json', 'after.json')]
    try:
        state['PreflightExit'] = run('--read-wireless-lighting', '258A:0150', before)
        if state['PreflightExit'] != 0:
            raise RuntimeError('Preflight query failed; no apply permitted')
        state['ApplyExit'] = run('--apply-observed-wireless-mode', '258A:0150', args.mode, before, result, '--confirm-experimental-write')
        # A fresh observation resolves uncertainty; never silently retry a write.
        state['IndependentQueryExit'] = run('--read-wireless-lighting', '258A:0150', after)
        if state['IndependentQueryExit'] == 0:
            first = bytes.fromhex(json.loads(before.read_text())['LightingBlockHex'])
            last = bytes.fromhex(json.loads(after.read_text())['LightingBlockHex'])
            intended = bytearray(first)
            intended[10] = args.mode
            state['IndependentQueryMatchesIntendedBlock'] = last == intended
            state['ObservedModeAfter'] = last[10]
            state['ChangedOffsets'] = [i for i, (a, b) in enumerate(zip(first, last)) if a != b]
    finally:
        subprocess.Popen([str(binary), '-s'])
        state['VendorRestartRequested'] = True
        (args.output_directory / 'summary.json').write_text(json.dumps(state, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(state, indent=2))
    if state.get('ApplyExit') != 0 or not state.get('IndependentQueryMatchesIntendedBlock'):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
