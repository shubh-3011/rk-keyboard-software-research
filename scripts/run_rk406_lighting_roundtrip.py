"""Authorized vendor-UI effect round trip; logs only allowlisted lighting reports.

Requires the existing lighting page's SysTreeView32. Saves its selected item,
selects the first effect briefly, then restores the exact original tree item.
Never sends a HID report directly, changes keymaps/macros or touches firmware.
Keep raw output local until reviewed. A UI restore is not hardware readback.
"""
import argparse
import ctypes
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import subprocess
import threading
import time

import frida
from rk_lighting_tree_guard import validate_tree

SHA256 = 'c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--tree-hwnd', type=lambda value: int(value, 0), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--click-x', type=int, help='Explicit observed tree state-icon x; sends target-only mouse messages instead of selection-only messages')
    parser.add_argument('--move-pointer', action='store_true', help='Briefly position and restore the mouse pointer because the vendor uses cursor hit testing; no global click injection')
    parser.add_argument('--capture-first-effect', type=Path, help='Optional new local-only target-window screenshot while the first effect is selected')
    parser.add_argument('--main-hwnd', type=lambda value: int(value, 0), help='Main window handle required for the optional screenshot')
    parser.add_argument('--inspect-brightness-hit', action='store_true', help='Passively inspect the window at the observed 1500x900 brightness-slider center while the first effect is selected; no click')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output must be new')
    if (args.capture_first_effect is not None or args.inspect_brightness_hit) and args.main_hwnd is None:
        parser.error('Main window handle is required for visual or hit inspection')
    if args.main_hwnd is not None and args.capture_first_effect is None and not args.inspect_brightness_hit:
        parser.error('Main window handle requires an inspection action')
    if args.capture_first_effect is not None and args.capture_first_effect.exists():
        parser.error('Screenshot output must be new')
    process = json.loads(subprocess.check_output(['powershell', '-NoProfile', '-Command',
        f'Get-CimInstance Win32_Process -Filter "ProcessId={args.pid}" | Select-Object ExecutablePath,CreationDate | ConvertTo-Json'], text=True))
    binary = Path(process['ExecutablePath'])
    if str(binary).lower() != r'C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe'.lower() or hashlib.sha256(binary.read_bytes()).hexdigest() != SHA256:
        parser.error('Executable identity mismatch')
    user = ctypes.WinDLL('user32', use_last_error=True)
    user.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]
    user.GetClassNameW.argtypes = [w.HWND, w.LPWSTR, ctypes.c_int]
    user.SendMessageTimeoutW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM, w.UINT, w.UINT, ctypes.POINTER(ctypes.c_size_t)]
    user.SendMessageTimeoutW.restype = w.LPARAM
    user.PostMessageW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]
    user.GetCursorPos.argtypes = [ctypes.POINTER(w.POINT)]
    user.ClientToScreen.argtypes = [w.HWND, ctypes.POINTER(w.POINT)]
    user.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
    user.GetWindowRect.argtypes = [w.HWND, ctypes.POINTER(w.RECT)]
    user.WindowFromPoint.argtypes = [w.POINT]
    user.WindowFromPoint.restype = w.HWND
    user.GetAncestor.argtypes = [w.HWND, w.UINT]
    user.GetAncestor.restype = w.HWND
    user.IsWindowVisible.argtypes = [w.HWND]
    hwnd = w.HWND(args.tree_hwnd)
    owner = w.DWORD()
    user.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
    name = ctypes.create_unicode_buffer(100)
    user.GetClassNameW(hwnd, name, 100)
    if owner.value != args.pid or name.value != 'SysTreeView32':
        parser.error('Selected tree is not the target process lighting tree')
    if args.inspect_brightness_hit:
        main = w.HWND(args.main_hwnd)
        main_owner = w.DWORD()
        main_class = ctypes.create_unicode_buffer(100)
        rect = w.RECT()
        user.GetWindowThreadProcessId(main, ctypes.byref(main_owner))
        user.GetClassNameW(main, main_class, 100)
        if (main_owner.value != args.pid or main_class.value != '#32770'
                or not user.IsWindowVisible(main) or user.GetAncestor(hwnd, 2) != main.value
                or not user.GetWindowRect(main, ctypes.byref(rect))
                or (rect.right - rect.left, rect.bottom - rect.top) != (1500, 900)):
            parser.error('Visible vendor main window, tree ownership, or observed geometry mismatch')
    def message(code, first, second):
        value = ctypes.c_size_t()
        if not user.SendMessageTimeoutW(hwnd, code, first, second, 2, 2000, ctypes.byref(value)):
            raise RuntimeError('Target tree timed out; stop rather than force a device operation')
        return value.value
    original = message(0x110A, 9, 0)  # TVM_GETNEXTITEM / TVGN_CARET
    first = message(0x110A, 0, 0)  # TVGN_ROOT
    if not original or not first or original == first:
        parser.error('Need a non-first current selection to observe and restore a distinct effect')
    row_height = message(0x111C, 0, 0)  # TVM_GETITEMHEIGHT, scalar result only.
    items, item = [], first
    while item and len(items) < 25:
        items.append(item)
        item = message(0x110A, 1, item)  # TVGN_NEXT
    # THIS runner is scoped to the observed lighting fixture, NOT an
    # arbitrary SysTreeView32. Connection changes can recreate the window and
    # leave a profile tree visible; selecting that tree can apply keymaps.
    # Reject it before any selection/mouse message. Use a separate validated
    # runner for a different profile/layout instead of weakening this guard.
    # The verified page has 19 configuration rows, optionally followed by
    # a separate Music item. Neither shape matches the three-row profile tree.
    try:
        validate_tree(items, original, item, row_height)
    except ValueError as error:
        parser.error(str(error))
    if args.click_x is not None and (args.click_x < 1 or args.click_x > 100 or original not in items or item or row_height < 10 or row_height > 80):
        parser.error('Tree geometry is outside the observed bounded lighting fixture')
    def select(item):
        if args.click_x is None:
            return message(0x110B, 9, item)
        y = items.index(item) * row_height + row_height // 2
        position = (y << 16) | args.click_x
        # Native tree controls can run a modal mouse loop on mouse-down.
        # Queue BOTH messages before waiting: synchronous down can deadlock
        # the automation caller before it has a chance to release the button.
        previous = w.POINT()
        if args.move_pointer:
            target = w.POINT(args.click_x, y)
            if not user.GetCursorPos(ctypes.byref(previous)) or not user.ClientToScreen(hwnd, ctypes.byref(target)) or not user.SetCursorPos(target.x, target.y):
                raise RuntimeError('Cannot safely position pointer for target hit testing')
        try:
            if not user.PostMessageW(hwnd, 0x201, 1, position):
                raise RuntimeError('Could not queue target mouse-down')
            if not user.PostMessageW(hwnd, 0x202, 0, position):
                raise RuntimeError('Could not queue target mouse-up')
            threading.Event().wait(0.2)
        finally:
            if args.move_pointer:
                user.SetCursorPos(previous.x, previous.y)
        return message(0x110A, 9, 0) == item
    source = Path(__file__).with_name('trace_rk406_lighting_transport.js').read_text(encoding='utf-8')
    events, ready = [], threading.Event()
    def receive(message, data):
        events.append(message)
        if message.get('type') == 'send' and message.get('payload', {}).get('kind') == 'ready':
            ready.set()
    session, script = None, None
    state = {'format': 'rk-runtime-lighting-roundtrip', 'binary_sha256': SHA256,
             'script_sha256': hashlib.sha256(source.encode()).hexdigest(),
             'pid': args.pid, 'started_unix': time.time(), 'restored_tree_selection': False,
             'limitations': ['Observed vendor calls only; a restored UI selection is not confirmed hardware state.',
                             'One connected fixture does not validate other models/revisions.']}
    changed = False
    try:
        session = frida.attach(args.pid)
        script = session.create_script(source)
        script.on('message', receive)
        script.load()
        if not ready.wait(5):
            raise RuntimeError('Observation hooks did not become ready')
        script.exports_sync.phase('select-first-effect')
        changed = True  # Restore even if a synchronous notification times out.
        if not select(first):
            raise RuntimeError('Effect selection failed')
        threading.Event().wait(5)
        if args.capture_first_effect is not None:
            capture = Path(__file__).with_name('capture_rk_window.ps1')
            subprocess.run(['powershell', '-NoProfile', '-File', str(capture), '-TargetPid', str(args.pid),
                            '-WindowHandle', str(args.main_hwnd), '-OutputPath', str(args.capture_first_effect.resolve())],
                           check=True, timeout=15)
        if args.inspect_brightness_hit:
            main = w.HWND(args.main_hwnd)
            main_owner = w.DWORD()
            main_class = ctypes.create_unicode_buffer(100)
            user.GetWindowThreadProcessId(main, ctypes.byref(main_owner))
            user.GetClassNameW(main, main_class, 100)
            rect = w.RECT()
            if (main_owner.value != args.pid or main_class.value != '#32770'
                    or not user.IsWindowVisible(main) or user.GetAncestor(hwnd, 2) != main.value
                    or not user.GetWindowRect(main, ctypes.byref(rect))
                    or (rect.right - rect.left, rect.bottom - rect.top) != (1500, 900)):
                raise RuntimeError('Vendor main window identity or observed geometry mismatch')
            hit = user.WindowFromPoint(w.POINT(rect.left + 550, rect.top + 640))
            hit_owner = w.DWORD()
            hit_class = ctypes.create_unicode_buffer(100)
            hit_rect = w.RECT()
            if (not hit or not user.GetWindowThreadProcessId(hit, ctypes.byref(hit_owner))
                    or hit_owner.value != args.pid or user.GetAncestor(hit, 2) != main.value
                    or not user.GetClassNameW(hit, hit_class, 100)
                    or not user.GetWindowRect(hit, ctypes.byref(hit_rect))):
                raise RuntimeError('Brightness position is not an owned descendant; no interaction attempted')
            state['brightness_hit'] = {'class': hit_class.value,
                'relative_rect': [hit_rect.left - rect.left, hit_rect.top - rect.top,
                                  hit_rect.right - rect.left, hit_rect.bottom - rect.top],
                'point': [550, 640], 'click_sent': False}
    except Exception as error:
        state['error'] = str(error)
    finally:
        if changed:
            try:
                if script:
                    script.exports_sync.phase('restore-original-effect')
                select(original)
                state['restored_tree_selection'] = message(0x110A, 9, 0) == original
                threading.Event().wait(5)
            except Exception as error:
                state['restore_error'] = str(error)
        if script:
            try:
                state['observation_summary'] = script.exports_sync.stop()
                script.unload()
            except Exception as error:
                state['cleanup_error'] = str(error)
        if session:
            session.detach()
        state['events'] = events
        state['finished_unix'] = time.time()
        args.output.write_text(json.dumps(state, indent=2) + '\n', encoding='utf-8')
    reports = sum(event.get('payload', {}).get('kind') == 'lighting_report' for event in events)
    print(json.dumps({key: value for key, value in state.items() if key not in ('events', 'pid', 'started_unix', 'finished_unix')}, indent=2))
    print('Allowlisted lighting reports captured:', reports)
    if state.get('error') or (changed and not state['restored_tree_selection']) or state.get('cleanup_error'):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
