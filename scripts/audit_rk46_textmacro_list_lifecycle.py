#!/usr/bin/env python3
"""Verify the 4.6 text-macro mapping-list lifecycle from pinned PE bytes only."""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile

EXPECTED_SHA256 = "8d8538de3ada5fcf80e00c13b364b17acefa708480e102ec1e6a0b1309639ae9"
EXPECTED_SIZE = 2_418_176
LIST_BASE = 0x00619DBC
LIST_HEAD = LIST_BASE + 0x10
TEXTMACRO_WRITER = 0x0041F540
WRITER_CALLS = {0x004215DE, 0x0045A057}

FACTS: dict[int, tuple[str, str, str]] = {
    0x00440AC0: ("8bc1", "generic-list-constructor", "Moves the list object pointer from ECX to EAX."),
    0x00440AC4: ("c7008cbf5d00", "generic-list-constructor", "Sets list vtable pointer to 0x005DBF8C."),
    0x00440ACA: ("894808", "generic-list-constructor", "Initializes list count at object +0x08 to zero."),
    0x00440ACD: ("89480c", "generic-list-constructor", "Initializes callback at object +0x0C to zero."),
    0x00440AD0: ("894814", "generic-list-constructor", "Initializes tail at object +0x14 to zero."),
    0x00440AD3: ("894810", "generic-list-constructor", "Initializes head at object +0x10 to zero."),
    0x00440AD6: ("c7400411000000", "generic-list-constructor", "Sets payload-ownership mode at object +0x04 to 0x11."),
    0x00440B00: ("5657", "generic-list-clear-and-destroy", "Begins list teardown/clear helper."),
    0x00440B04: ("8b7710", "generic-list-clear-and-destroy", "Starts traversal at list head +0x10."),
    0x00440B4B: ("8b0e", "generic-list-clear-and-destroy", "Loads node payload before optional callback."),
    0x00440B53: ("837f0410", "generic-list-clear-and-destroy", "Frees non-null payload only when owner +0x04 equals 0x10."),
    0x00440B68: ("56", "generic-list-clear-and-destroy", "Frees the list node after optional payload release."),
    0x00440B6E: ("ff4f08", "generic-list-clear-and-destroy", "Decrements list count for removed node."),
    0x00440B80: ("6a0c", "generic-list-append", "Requests a 12-byte node allocation."),
    0x00440B95: ("8b542404", "generic-list-append", "Loads the payload argument for the new node."),
    0x00440B99: ("8910", "generic-list-append", "Stores payload at node +0."),
    0x00440B9B: ("894804", "generic-list-append", "Initializes node next link at +0x04 to null."),
    0x00440BA3: ("894808", "generic-list-append", "Initializes previous link for first node."),
    0x00440BA6: ("894610", "generic-list-append", "Sets list head at owner +0x10 for first node."),
    0x00440BA9: ("894614", "generic-list-append", "Sets list tail at owner +0x14 for first node."),
    0x00440BC3: ("894614", "generic-list-append", "Sets list tail at owner +0x14 for later nodes."),
    0x00440BCB: ("014608", "generic-list-append", "Increments list count at owner +0x08."),
    0x00440C50: ("85f6", "generic-list-remove", "Tests whether the target node pointer is non-null."),
    0x00440C84: ("8b470c", "generic-list-remove", "Loads optional callback from owner +0x0C."),
    0x00440C93: ("837f0410", "generic-list-remove", "Uses owner +0x04 == 0x10 to select payload-freeing mode."),
    0x00440CB1: ("ff4f08", "generic-list-remove", "Decrements owner count after node removal."),
    0x00440CC0: ("56", "generic-list-clear", "Begins list clear loop without resetting the vtable."),
    0x00440CC1: ("8b7710", "generic-list-clear", "Starts clear traversal from owner head +0x10."),
    0x00440D02: ("8b470c", "generic-list-clear", "Loads optional callback from owner +0x0C."),
    0x00440D11: ("837f0410", "generic-list-clear", "Uses owner +0x04 == 0x10 to select payload-freeing mode."),
    0x00440D26: ("56", "generic-list-clear", "Frees each list node after optional payload release."),
    0x00440D2C: ("ff4f08", "generic-list-clear", "Decrements owner count as nodes are cleared."),
    0x00427D80: ("c3", "list-callback", "Initializer-supplied callback is a one-byte RET."),
    0x00448B0D: ("bf10000000", "COemDrvDlg-virtual-initializer", "Sets EDI to payload-freeing mode 0x10."),
    0x00448B15: ("c705c89d6100807d4200", "COemDrvDlg-virtual-initializer", "Stores callback 0x00427D80 at list object +0x0C."),
    0x00448B1F: ("893dc09d6100", "COemDrvDlg-virtual-initializer", "Stores mode 0x10 at list object +0x04."),
    0x00448B25: ("c705b09d6100807d4200", "COemDrvDlg-virtual-initializer", "Stores the same callback at adjacent object field 0x00619DB0."),
    0x00448B2F: ("893da89d6100", "COemDrvDlg-virtual-initializer", "Stores the same mode at adjacent object field 0x00619DA8."),
    0x0044910C: ("be bc 9d 61 00".replace(" ", ""), "mapping-list-append-site", "Loads list owner 0x00619DBC into ESI."),
    0x00449111: ("e86a7affff", "mapping-list-append-site", "Calls generic append helper 0x00440B80."),
    0x00460BA0: ("be bc 9d 61 00".replace(" ", ""), "mapping-list-append-site", "Loads list owner 0x00619DBC into ESI."),
    0x00460BA5: ("e8d6fffdff", "mapping-list-append-site", "Calls generic append helper 0x00440B80."),
    0x00460BE5: ("bfbc9d6100", "mapping-list-remove-site", "Loads list owner 0x00619DBC into EDI."),
    0x00460BEA: ("e86100feff", "mapping-list-remove-site", "Calls generic remove helper 0x00440C50."),
    0x00448788: ("bfbc9d6100", "mapping-list-clear-site", "Loads list owner 0x00619DBC into EDI."),
    0x0044878D: ("e82e85ffff", "mapping-list-clear-site", "Calls generic clear helper 0x00440CC0."),
    0x0044904F: ("bfbc9d6100", "mapping-list-clear-site", "Loads list owner 0x00619DBC into EDI."),
    0x00449054: ("e8677cffff", "mapping-list-clear-site", "Calls generic clear helper 0x00440CC0."),
    0x00460D08: ("bfbc9d6100", "mapping-list-clear-site", "Loads list owner 0x00619DBC into EDI."),
    0x00460D0F: ("e8acfffdff", "mapping-list-clear-site", "Calls generic clear helper 0x00440CC0."),
    0x00421645: ("8b5500", "picker-post-cleanup-tail", "Loads the CKeyFunPickDlg vtable pointer."),
    0x00421648: ("8b8258010000", "picker-post-cleanup-tail", "Loads CKeyFunPickDlg vtable slot +0x158."),
    0x0042164E: ("8bcd", "picker-post-cleanup-tail", "Sets ECX to the dialog object."),
    0x00421650: ("ffd0", "picker-post-cleanup-tail", "Calls the resolved dialog vtable method."),
    0x00480C2F: ("6a01", "picker-dialog-close", "Passes result value 1 to the validation/update helper."),
    0x00480C33: ("e8dab6ffff", "picker-dialog-close", "Calls helper 0x0047C312."),
    0x00480C38: ("85c0", "picker-dialog-close", "Tests helper result before close."),
    0x00480C3A: ("7409", "picker-dialog-close", "Zero result skips the EndDialog branch."),
    0x00480C3C: ("6a01", "picker-dialog-close", "Passes modal result 1 to close helper."),
    0x00480C40: ("e8bdffffff", "picker-dialog-close", "Calls dialog close helper 0x00480C02."),
    0x0047C353: ("ff90fc000000", "picker-derived-data-slot", "Calls CKeyFunPickDlg slot +0xFC."),
    0x00405770: ("c20400", "picker-derived-data-target", "Vtable slot target is a three-byte RET 4."),
    0x00480C0A: ("f6463c18", "picker-dialog-close-helper", "Tests modal/window state flags."),
    0x00480C15: ("ff908c000000", "picker-dialog-close-helper", "Conditionally calls CKeyFunPickDlg slot +0x8C."),
    0x00480C21: ("ff15c0655a00", "picker-dialog-close-helper", "Calls USER32 EndDialog through its IAT slot."),
    0x0041D135: ("e8c6240000", "picker-parent-construction", "Calls picker constructor 0x0041F600 on a stack object."),
    0x0041D157: ("e88a400600", "picker-parent-modal-call", "Calls modal wrapper 0x004811E6."),
    0x0041D15C: ("83f801", "picker-parent-modal-result", "Tests modal return value against 1."),
    0x0041D15F: ("0f854d010000", "picker-parent-modal-result", "Non-1 modal result branches to parent cleanup at 0x0041D2B2."),
    0x0041D267: ("e8e4190000", "picker-parent-follow-up", "Calls follow-up handler 0x0041EC50 after the result-1 path."),
    0x0041EC50: ("833d00a2620000", "picker-follow-up-profile-gate", "Selects a follow-up branch using global state at 0x0062A200."),
    0x0041EC6C: ("8b8584210000", "picker-follow-up-selection", "Loads the selected row index from parent object +0x2184."),
    0x0041ECD5: ("8b5734", "picker-follow-up-layer", "Loads the active layer index from the current mapping object."),
    0x0041ED1C: ("894c3a38", "picker-follow-up-map-write", "Begins copying the selected 16-byte record into the active mapping row."),
    0x0041ED23: ("8d543a38", "picker-follow-up-map-write", "Computes the active mapping row destination for the record copy."),
    0x0041ED27: ("894a04", "picker-follow-up-map-write", "Stores the second DWORD of the selected record."),
    0x0041ED2D: ("894a08", "picker-follow-up-map-write", "Stores the third DWORD of the selected record."),
    0x0041ED33: ("894a0c", "picker-follow-up-map-write", "Stores the fourth DWORD of the selected record."),
    0x0041ED3D: ("c7473001000000", "picker-follow-up-map-dirty", "Sets current mapping object field +0x30 to 1 after the record copy."),
    0x0041ED44: ("8b8dac210000", "picker-follow-up-worker-signal", "Loads parent object field +0x21AC for the update helper."),
    0x0041ED4A: ("e8419bffff", "picker-follow-up-worker-signal", "Calls helper 0x00418890 after updating the mapping row."),
    0x0041ED62: ("8b15fca16200", "picker-follow-up-profile-save", "Loads profile path/global argument 0x0062A1FC."),
    0x0041ED69: ("e832200400", "picker-follow-up-profile-save", "Calls the existing pro.dct writer 0x00460DA0 on this update branch."),
    0x0041F1A2: ("8b15fca16200", "picker-follow-up-profile-save", "Loads profile path/global argument 0x0062A1FC on the alternate branch."),
    0x0041F1A9: ("e8f21b0400", "picker-follow-up-profile-save", "Calls the existing pro.dct writer 0x00460DA0 on the alternate update branch."),
    0x0041ED4F: ("833d34a2620000", "picker-follow-up-notification-gate", "Tests global flag 0x0062A234 before optional semaphore notification."),
    0x0041ED5A: ("e8a123feff", "picker-follow-up-notification", "Calls helper 0x00401100 with value 1 on the enabled branch."),
    0x00418890: ("3d84000000", "mapping-row-state-helper", "Bounds direct row indices against 0x84 (132 rows)."),
    0x0041889B: ("8b8180000000", "mapping-row-state-helper", "For a negative index, loads the fallback row index from object +0x80."),
    0x004188A8: ("6a01", "mapping-row-state-helper", "Prepares InvalidateRect erase flag TRUE."),
    0x004188AA: ("899481ac000000", "mapping-row-state-helper", "Stores the supplied state in the indexed row slot at object +0xAC with 0x24-byte stride."),
    0x004188B1: ("8b4120", "mapping-row-state-helper", "Loads the target HWND from object +0x20."),
    0x004188B4: ("6a00", "mapping-row-state-helper", "Passes a null rectangle to InvalidateRect."),
    0x004188B6: ("50", "mapping-row-state-helper", "Passes the stored HWND to InvalidateRect."),
    0x004188B7: ("ff1544675a00", "mapping-row-state-helper", "Calls USER32!InvalidateRect through the IAT."),
    0x00401100: ("81642404ff7fffff", "shared-semaphore-notifier", "Clears bit 0x8000 in the notifier's stack argument."),
    0x0040111D: ("6a00", "shared-semaphore-notifier", "Passes a null previous-count output pointer to ReleaseSemaphore."),
    0x0040111F: ("6a01", "shared-semaphore-notifier", "Requests one semaphore release."),
    0x00401121: ("51", "shared-semaphore-notifier", "Passes the semaphore handle loaded from global 0x006356C4."),
    0x00401122: ("ff15a4645a00", "shared-semaphore-notifier", "Calls KERNEL32!ReleaseSemaphore through the IAT."),
    0x0040110D: ("a1d8566300", "shared-semaphore-queue", "Loads the shared circular-queue object pointer from global 0x006356D8."),
    0x00401112: ("e8a9d50300", "shared-semaphore-queue", "Enqueues the adjusted notification value through helper 0x0043E6C0."),
    0x00401117: ("8b0dc4566300", "shared-semaphore-queue", "Loads the worker semaphore handle from global 0x006356C4."),
    0x00401183: ("8b1db0645a00", "shared-worker-init", "Loads the CreateEventW IAT slot for worker-handle initialization."),
    0x004011B4: ("ffd3", "shared-worker-init", "Calls the loaded CreateEventW import."),
    0x004011BB: ("a3c8566300", "shared-worker-init", "Stores the created event handle at global 0x006356C8."),
    0x004011C0: ("ff15a0645a00", "shared-worker-init", "Calls KERNEL32!CreateSemaphoreW through the IAT."),
    0x004011C8: ("a3c4566300", "shared-worker-init", "Stores the created semaphore handle at global 0x006356C4."),
    0x00401261: ("68c0566300", "shared-worker-init", "Passes the global handle block at 0x006356C0 to the thread wrapper."),
    0x00401267: ("6890124000", "shared-worker-init", "Passes worker entrypoint 0x00401290 to the thread wrapper."),
    0x0040126C: ("e8ba421700", "shared-worker-init", "Calls the CRT thread-creation wrapper at 0x0057552B."),
    0x0057559F: ("ff1568645a00", "shared-worker-init", "CRT wrapper calls KERNEL32!CreateThread through the IAT."),
    0x00401290: ("83ec0c", "shared-worker-entry", "Begins the worker routine passed to the CRT thread wrapper."),
    0x004012A2: ("8b442424", "shared-worker-entry", "Loads the thread parameter, the global handle block pointer."),
    0x004012A6: ("8b4804", "shared-worker-entry", "Loads handle-block field +4 as wait handle zero (global semaphore)."),
    0x004012A9: ("8b5008", "shared-worker-entry", "Loads handle-block field +8 as wait handle one (global event)."),
    0x004012CC: ("ff159c645a00", "shared-worker-wait", "Calls KERNEL32!WaitForMultipleObjects on two handles."),
    0x004012D2: ("3bc3", "shared-worker-wait", "Routes wait result zero to queue processing; nonzero results go to the result check."),
    0x004012DA: ("8b542420", "shared-worker-queue", "Reloads the shared handle block after a semaphore wake."),
    0x004012DE: ("8b7218", "shared-worker-queue", "Loads the circular-queue pointer from handle-block field +0x18."),
    0x004012EA: ("e891d40300", "shared-worker-queue", "Dequeues one notification value through helper 0x0043E780."),
    0x0040148F: ("83f801", "shared-worker-exit", "Tests whether the second wait handle produced result index 1."),
    0x00401492: ("0f8528feffff", "shared-worker-exit", "Non-1 wait result loops; result 1 falls through to worker return."),
    0x0040130E: ("8b08", "shared-worker-window-dispatch", "Loads a window-name pointer from the shared UI object."),
    0x00401310: ("51", "shared-worker-window-dispatch", "Passes the window-name pointer to FindWindowW."),
    0x00401311: ("6a00", "shared-worker-window-dispatch", "Passes a null class-name argument to FindWindowW."),
    0x00401313: ("ff1538675a00", "shared-worker-window-dispatch", "Calls USER32!FindWindowW through the IAT."),
    0x00401319: ("8bd8", "shared-worker-window-dispatch", "Keeps the FindWindowW result HWND in EBX for the later close message."),
    0x004013AB: ("85db", "shared-worker-window-close", "Requires a non-null FindWindowW result before posting a close message."),
    0x004013B3: ("6a00", "shared-worker-window-close", "Passes zero as WM_CLOSE lParam."),
    0x004013B5: ("6a00", "shared-worker-window-close", "Passes zero as WM_CLOSE wParam."),
    0x004013B7: ("6a10", "shared-worker-window-close", "Passes WM_CLOSE message value 0x0010."),
    0x004013B9: ("53", "shared-worker-window-close", "Passes the located HWND as PostMessageW's target."),
    0x004013BA: ("ff153c675a00", "shared-worker-window-close", "Calls USER32!PostMessageW through the IAT."),
    0x0045DF24: ("a1d8566300", "shared-semaphore-queue-producer", "Loads the same shared circular-queue pointer."),
    0x0045DF29: ("8d54240c", "shared-semaphore-queue-producer", "Passes a local notification value to the queue helper."),
    0x0045DF2E: ("c744241002000000", "shared-semaphore-queue-producer", "Sets the queued notification value to 2."),
    0x0045DF36: ("e88507feff", "shared-semaphore-queue-producer", "Enqueues the notification through helper 0x0043E6C0."),
    0x0045DF3B: ("a1c4566300", "shared-semaphore-queue-producer", "Loads the same worker semaphore handle at global 0x006356C4."),
    0x0045DF45: ("ff15a4645a00", "shared-semaphore-queue-producer", "Releases the worker semaphore through KERNEL32!ReleaseSemaphore."),
    0x0041F62B: ("6a6a", "picker-constructor-resource", "Passes dialog resource ID 106 to the base dialog constructor."),
    0x0041F62F: ("e891150600", "picker-constructor-base-dialog", "Calls base dialog constructor 0x00480BC5."),
    0x0041F63E: ("c7060c535d00", "picker-constructor-vtable", "Installs CKeyFunPickDlg vtable 0x005D530C."),
    0x0048113E: ("ff15b8655a00", "picker-dialog-create", "Calls USER32!CreateDialogIndirectParamW through the IAT."),
    0x0048130E: ("e84ab2ffff", "picker-message-loop", "Calls modal message-loop helper 0x0047C55D."),
    0x004813A9: ("8b4644", "picker-modal-return", "Loads modal result from dialog object +0x44."),
    0x0047C5B4: ("ff1538665a00", "picker-message-loop", "Calls USER32!PeekMessageW through the IAT."),
    0x0048A53C: ("e943d5feff", "picker-tls-exception-edge", "Null TLS-object result jumps to shared C++ exception stub 0x00477A84."),
    0x00477A84: ("8bff558bec5168b0f15e008d45fc50c745fcc8736000e81f081000", "shared-cpp-exception-stub", "Builds an exception object and calls shared RaiseException helper 0x005782BE."),
    0x00578300: ("ff15a4625a00", "shared-cpp-exception-raise", "Calls KERNEL32!RaiseException through the IAT."),
    0x005CC030: ("63736de0", "shared-cpp-exception-code", "Exception template begins with MSVC C++ exception code 0xE06D7363."),
    0x0047C6A9: ("894144", "picker-slot-8c-target", "Stores dialog result in object field +0x44."),
    0x0047C6AC: ("8b413c", "picker-slot-8c-target", "Loads modal state flags from object +0x3C."),
    0x0047C6C1: ("ff153c675a00", "picker-slot-8c-target", "Conditionally calls USER32 PostMessageW through its IAT slot."),
    0x0048A529: ("68a07a4700", "picker-first-use-guard", "Passes callback 0x00477AA0 to the MFC thread-local initialization helper."),
    0x0048A52E: ("b998c36100", "picker-first-use-guard", "Passes state object 0x0061C398 in ECX."),
    0x0048A533: ("e84c250000", "picker-first-use-guard", "Calls lazy-initialization helper 0x0048CA84."),
    0x0048A538: ("85c0", "picker-first-use-guard", "Tests the helper's returned thread-local object pointer."),
    0x0048A53C: ("e943d5feff", "picker-first-use-guard", "Null return reaches an MFC/SEH exception stub."),
    0x0048CAA3: ("833e00", "picker-tls-lazy-helper", "Skips setup when the state object's TLS index is already initialized."),
    0x0048CAA8: ("8b0df4c36100", "picker-tls-lazy-helper", "Loads the process TLS context pointer."),
    0x0048CAB2: ("b9f8c36100", "picker-tls-lazy-helper", "Uses global context storage at 0x0061C3F8 when absent."),
    0x0048CABE: ("e8f2fcffff", "picker-tls-lazy-helper", "Calls context/TLS-slot initializer 0x0048C7B5."),
    0x0048CAC9: ("890df4c36100", "picker-tls-lazy-helper", "Stores the initialized process TLS context pointer."),
    0x0048CAD3: ("e8c5fbffff", "picker-tls-lazy-helper", "Calls TLS-index allocator 0x0048C69D."),
    0x0048CADE: ("ff36", "picker-tls-lazy-helper", "Passes the state object's allocated TLS index to lookup."),
    0x0048CAE6: ("e824faffff", "picker-tls-lazy-helper", "Calls per-thread TLS lookup helper 0x0048C50F."),
    0x0048CAF1: ("ff5508", "picker-tls-lazy-helper", "Calls the supplied callback only when the per-thread object is absent."),
    0x0048CAFF: ("e858fdffff", "picker-tls-lazy-helper", "Registers the callback result with per-thread TLS helper 0x0048C85C."),
    0x00477AAC: ("6864010000", "picker-tls-object-callback", "Requests a 0x164-byte per-thread object allocation."),
    0x00477AB1: ("e8264a0100", "picker-tls-object-callback", "Calls allocation helper 0x0048C4DC."),
    0x00477AC0: ("3bc8", "picker-tls-object-callback", "Tests the allocation result before object initialization."),
    0x00477AC4: ("e8f8280100", "picker-tls-object-callback", "Initializes the allocated thread-local object at 0x0048A3C1."),
    0x0048C4E4: ("6a40", "picker-local-allocation", "Passes LocalAlloc flags 0x40 (zero-initialized allocation)."),
    0x0048C4E6: ("ff15c4635a00", "picker-local-allocation", "Calls KERNEL32!LocalAlloc through the IAT."),
    0x0048A3C7: ("c70024a75a00", "picker-tls-object-init", "Sets the new object vtable pointer to 0x005AA724."),
    0x0048A3CD: ("895034", "picker-tls-object-init", "Zeros object field +0x34."),
    0x0048A3D0: ("895054", "picker-tls-object-init", "Zeros object field +0x54."),
    0x0048A3D3: ("89484c", "picker-tls-object-init", "Zeros object field +0x4C."),
    0x0048A3D6: ("895050", "picker-tls-object-init", "Zeros object field +0x50."),
    0x0048C7D4: ("ff150c635a00", "picker-tls-context-init", "Calls KERNEL32!TlsAlloc through the IAT."),
    0x0048C7EA: ("ff1594645a00", "picker-tls-context-init", "Calls KERNEL32!InitializeCriticalSection for the TLS context."),
    0x0048C6B0: ("ff15c0645a00", "picker-tls-index-allocation", "Enters the TLS-index allocator critical section."),
    0x0048C706: ("ff154c645a00", "picker-tls-index-allocation", "Uses KERNEL32!GlobalAlloc when the slot table is first created."),
    0x0048C70F: ("ff1510635a00", "picker-tls-index-allocation", "Obtains a global-memory handle while resizing the slot table."),
    0x0048C719: ("ff1544645a00", "picker-tls-index-allocation", "Unlocks the old global-memory table before reallocation."),
    0x0048C732: ("ff1540645a00", "picker-tls-index-allocation", "Uses KERNEL32!GlobalReAlloc to grow the slot table."),
    0x0048C754: ("ff15c4645a00", "picker-tls-index-allocation", "Leaves the TLS-index allocator critical section."),
    0x0048C51D: ("ff15c0645a00", "picker-tls-lookup", "Enters the TLS context critical section."),
    0x0048C531: ("ff1514635a00", "picker-tls-lookup", "Calls KERNEL32!TlsGetValue for the allocated slot."),
    0x0048C547: ("ff15c4645a00", "picker-tls-lookup", "Leaves the critical section after a found object."),
    0x0048C552: ("ff15c4645a00", "picker-tls-lookup", "Leaves the critical section on a miss."),
    0x0048C874: ("ff15c0645a00", "picker-tls-registration", "Enters the TLS context critical section."),
    0x0048C892: ("ff1514635a00", "picker-tls-registration", "Calls KERNEL32!TlsGetValue before registering the object."),
    0x0048C8C6: ("ff15c4635a00", "picker-tls-registration", "Uses KERNEL32!LocalAlloc for a per-thread TLS record."),
    0x0048C925: ("ff1504635a00", "picker-tls-registration", "Uses KERNEL32!LocalReAlloc when the per-thread table must grow."),
    0x0048C962: ("ff1508635a00", "picker-tls-registration", "Stores the expanded per-thread table with KERNEL32!TlsSetValue."),
    0x0048C983: ("ff15c4645a00", "picker-tls-registration", "Leaves the TLS context critical section."),
    0x005A53B0: ("b9bc9d6100", "mapping-list-destructor-thunk", "Loads list owner into ECX."),
    0x005A53B5: ("e946b7e9ff", "mapping-list-destructor-thunk", "Tail-jumps to generic teardown helper 0x00440B00."),
}

HEAD_LOADS = {
    0x00401AE7: "8b3dcc9d6100",
    0x0041AE32: "a1cc9d6100",
    0x0041B00E: "a1cc9d6100",
    0x0041E4C4: "a1cc9d6100",
    0x0044912A: "8b35cc9d6100",
    0x004491E0: "a1cc9d6100",
    0x00460BC1: "8b35cc9d6100",
    0x00460DB4: "a1cc9d6100",
    0x00460E5E: "8b35cc9d6100",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    require(len(data) == EXPECTED_SIZE and digest == EXPECTED_SHA256,
            "input size/SHA-256 mismatch")
    pe = pefile.PE(data=data)
    require(pe.OPTIONAL_HEADER.ImageBase == 0x00400000 and pe.FILE_HEADER.Machine == 0x14C,
            "expected x86 PE at preferred base")

    def raw(va: int, size: int) -> bytes:
        return data[pe.get_offset_from_rva(va - pe.OPTIONAL_HEADER.ImageBase):
                    pe.get_offset_from_rva(va - pe.OPTIONAL_HEADER.ImageBase) + size]

    rows: list[dict[str, str]] = []

    def add(va: int, expected_hex: str, stage: str, note: str) -> None:
        expected = bytes.fromhex(expected_hex)
        actual = raw(va, len(expected))
        require(actual == expected,
                f"0x{va:08X}: expected {expected.hex()}, got {actual.hex()}")
        rows.append({"binary_sha256": digest, "evidence_va": f"0x{va:08X}",
                     "bytes": actual.hex().upper(), "stage": stage, "observation": note,
                     "scope": "static bytes only; execution and runtime list contents unobserved"})

    for va, (hex_bytes, stage, note) in FACTS.items():
        add(va, hex_bytes, stage, note)

    # Check the entire initialized object image, then distinguish it from the
    # runtime fields changed by the COemDrvDlg virtual initializer.
    static = raw(LIST_BASE, 0x18)
    require(static == bytes.fromhex("8cbf5d001100000000000000000000000000000000000000"),
            f"unexpected static list object image: {static.hex()}")
    rows.append({"binary_sha256": digest, "evidence_va": f"0x{LIST_BASE:08X}",
                 "bytes": static.hex().upper(), "stage": "static-list-object",
                 "observation": "Static image has vptr 0x005DBF8C, mode 0x11, and zero count/callback/head/tail.",
                 "scope": "file image only; process startup/runtime state unobserved"})
    adjacent = raw(0x00619DA4, 0x18)
    require(adjacent == static, f"adjacent list-like object image changed: {adjacent.hex()}")
    rows.append({"binary_sha256": digest, "evidence_va": "0x00619DA4",
                 "bytes": adjacent.hex().upper(), "stage": "adjacent-list-like-object",
                 "observation": "Adjacent object has the same static vtable/mode/zero-field image; initializer writes matching mode and callback fields.",
                 "scope": "static bytes only; semantic role and runtime contents unobserved"})

    # Resolve the virtual initializer to its RTTI-identified owner.
    vtable = 0x005DDC6C
    col = struct.unpack("<I", raw(vtable - 4, 4))[0]
    require(col == 0x005ED7A8, f"COemDrvDlg vtable COL changed: 0x{col:08X}")
    col_fields = struct.unpack("<5I", raw(col, 20))
    require(col_fields == (0, 0, 0, 0x0061A420, 0x005ED7BC),
            f"COemDrvDlg COL fields changed: {col_fields!r}")
    type_name = raw(col_fields[3] + 8, len(b".?AVCOemDrvDlg@@\0"))
    require(type_name == b".?AVCOemDrvDlg@@\0", "COemDrvDlg RTTI name changed")
    initializer = struct.unpack("<I", raw(vtable + 84 * 4, 4))[0]
    require(initializer == 0x00448930,
            f"COemDrvDlg vtable slot 84 changed: 0x{initializer:08X}")
    rows.append({"binary_sha256": digest, "evidence_va": f"0x{vtable + 84 * 4:08X}",
                 "bytes": raw(vtable + 84 * 4, 4).hex().upper(),
                 "stage": "owner-rtti-vtable",
                 "observation": "RTTI name .?AVCOemDrvDlg@@; vtable slot 84 points to initializer 0x00448930.",
                 "scope": "static RTTI/vtable linkage; method execution and symbolic name unobserved"})

    picker_vtable = 0x005D530C
    picker_col = struct.unpack("<I", raw(picker_vtable - 4, 4))[0]
    require(picker_col == 0x005ED020, f"CKeyFunPickDlg vtable COL changed: 0x{picker_col:08X}")
    picker_td = struct.unpack("<I", raw(picker_col + 12, 4))[0]
    require(picker_td == 0x0061A170, f"CKeyFunPickDlg TypeDescriptor changed: 0x{picker_td:08X}")
    require(raw(picker_td + 8, len(b".?AVCKeyFunPickDlg@@\0")) == b".?AVCKeyFunPickDlg@@\0",
            "CKeyFunPickDlg RTTI name changed")
    picker_targets = {
        0x8C: 0x0047C6A1,
        0xFC: 0x00405770,
        0x158: 0x00480C2C,
    }
    for slot, target in picker_targets.items():
        actual = struct.unpack("<I", raw(picker_vtable + slot, 4))[0]
        require(actual == target,
                f"CKeyFunPickDlg vtable slot +0x{slot:X} changed: 0x{actual:08X}")
        rows.append({"binary_sha256": digest,
                     "evidence_va": f"0x{picker_vtable + slot:08X}",
                     "bytes": raw(picker_vtable + slot, 4).hex().upper(),
                     "stage": "picker-rtti-vtable",
                     "observation": f"RTTI .?AVCKeyFunPickDlg@@ slot +0x{slot:X} -> 0x{target:08X}.",
                     "scope": "static RTTI/vtable linkage; method execution unobserved"})

    iat_names = {entry.address: (library.dll.decode(errors="replace"), entry.name.decode(errors="replace") if entry.name else "")
                 for library in pe.DIRECTORY_ENTRY_IMPORT for entry in library.imports}
    require(iat_names.get(0x005A65C0) == ("USER32.dll", "EndDialog"),
            "EndDialog IAT mapping changed")
    require(iat_names.get(0x005A673C) == ("USER32.dll", "PostMessageW"),
            "PostMessageW IAT mapping changed")
    modal_apis = {
        0x005A65B8: ("USER32.dll", "CreateDialogIndirectParamW"),
        0x005A6638: ("USER32.dll", "PeekMessageW"),
        0x005A65C0: ("USER32.dll", "EndDialog"),
        0x005A62A4: ("KERNEL32.dll", "RaiseException"),
    }
    for va, expected in modal_apis.items():
        require(iat_names.get(va) == expected,
                f"picker modal/exception IAT mapping changed at 0x{va:08X}: {iat_names.get(va)!r}")
        rows.append({"binary_sha256": digest, "evidence_va": f"0x{va:08X}", "bytes": "",
                     "stage": "picker-modal-exception-api-import",
                     "observation": f"IAT slot resolves to {expected[0]}!{expected[1]}.",
                     "scope": "static import table; runtime API call and return unobserved"})
    ui_update_apis = {
        0x005A6744: ("USER32.dll", "InvalidateRect"),
        0x005A64A4: ("KERNEL32.dll", "ReleaseSemaphore"),
        0x005A64A0: ("KERNEL32.dll", "CreateSemaphoreW"),
        0x005A64B0: ("KERNEL32.dll", "CreateEventW"),
        0x005A6468: ("KERNEL32.dll", "CreateThread"),
        0x005A649C: ("KERNEL32.dll", "WaitForMultipleObjects"),
        0x005A6738: ("USER32.dll", "FindWindowW"),
        0x005A673C: ("USER32.dll", "PostMessageW"),
    }
    for va, expected in ui_update_apis.items():
        require(iat_names.get(va) == expected,
                f"picker update IAT mapping changed at 0x{va:08X}: {iat_names.get(va)!r}")
        rows.append({"binary_sha256": digest, "evidence_va": f"0x{va:08X}", "bytes": "",
                     "stage": "picker-update-api-import",
                     "observation": f"IAT slot resolves to {expected[0]}!{expected[1]}.",
                     "scope": "static import table; runtime API call and return unobserved"})

    # RTTI for the object constructed by the shared C++ throw stub.
    throw_vtable = struct.unpack("<I", raw(0x006073C8, 4))[0]
    require(throw_vtable == 0x005A708C, f"exception object vtable changed: 0x{throw_vtable:08X}")
    throw_col = struct.unpack("<I", raw(throw_vtable - 4, 4))[0]
    require(throw_col == 0x005E49D0, f"exception object COL changed: 0x{throw_col:08X}")
    throw_col_fields = struct.unpack("<5I", raw(throw_col, 20))
    require(throw_col_fields == (0, 0, 0, 0x00607174, 0x005E49E4),
            f"exception object COL fields changed: {throw_col_fields!r}")
    throw_type = b".?AVCInvalidArgException@@\0"
    require(raw(0x00607174 + 8, len(throw_type)) == throw_type,
            "exception object RTTI type name changed")
    rows.append({"binary_sha256": digest, "evidence_va": "0x0060717C", "bytes": throw_type.hex().upper(),
                 "stage": "shared-cpp-exception-rtti",
                 "observation": "Throw-object vtable/COL resolves to RTTI name .?AVCInvalidArgException@@.",
                 "scope": "static RTTI for shared throw-object template; higher-level catch behavior unobserved"})

    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    # Count direct calls to the shared modal wrapper in executable bytes. This
    # is a candidate-instruction census, not a reachability proof.
    modal_call_count = 0
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        chunk = section.get_data()
        section_va = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
        for offset in range(len(chunk) - 4):
            if chunk[offset] != 0xE8:
                continue
            call_va = section_va + offset
            target = call_va + 5 + struct.unpack_from("<i", chunk, offset + 1)[0]
            if target == 0x004811E6:
                ins = next(decoder.disasm(chunk[offset:offset + 15], call_va, count=1), None)
                require(ins is not None and ins.mnemonic == "call"
                        and int(ins.op_str, 16) == 0x004811E6,
                        f"modal-wrapper call candidate at 0x{call_va:08X} did not decode")
                modal_call_count += 1
    require(modal_call_count == 31,
            f"modal-wrapper direct-call census changed: {modal_call_count}")
    tls_apis = {
        0x005A63C4: "LocalAlloc",
        0x005A630C: "TlsAlloc",
        0x005A6494: "InitializeCriticalSection",
        0x005A64C0: "EnterCriticalSection",
        0x005A64C4: "LeaveCriticalSection",
        0x005A644C: "GlobalAlloc",
        0x005A6310: "GlobalHandle",
        0x005A6444: "GlobalUnlock",
        0x005A6440: "GlobalReAlloc",
        0x005A6448: "GlobalLock",
        0x005A6314: "TlsGetValue",
        0x005A6304: "LocalReAlloc",
        0x005A6308: "TlsSetValue",
    }
    for va, name in tls_apis.items():
        require(iat_names.get(va) == ("KERNEL32.dll", name),
                f"picker TLS IAT mapping changed at 0x{va:08X}: {iat_names.get(va)!r}")
        rows.append({"binary_sha256": digest, "evidence_va": f"0x{va:08X}", "bytes": "",
                     "stage": "picker-tls-api-import",
                     "observation": f"IAT slot resolves to KERNEL32.dll!{name}.",
                     "scope": "static import table; runtime call and API success unobserved"})
    rows.extend((
        {"binary_sha256": digest, "evidence_va": "0x005A65C0", "bytes": "",
         "stage": "picker-api-import", "observation": "IAT slot resolves to USER32.dll!EndDialog.",
         "scope": "static import table; runtime API call and success unobserved"},
        {"binary_sha256": digest, "evidence_va": "0x005A673C", "bytes": "",
         "stage": "picker-api-import", "observation": "IAT slot resolves to USER32.dll!PostMessageW.",
         "scope": "static import table; runtime API call and success unobserved"},
    ))

    # This is a literal absolute-address census, not a whole-program alias proof.
    encoded = struct.pack("<I", LIST_HEAD)
    hits: list[int] = []
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        chunk = section.get_data()
        pos = 0
        while True:
            pos = chunk.find(encoded, pos)
            if pos < 0:
                break
            va = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + pos
            hits.append(va)
            pos += 1
    literal_offsets = [va + (2 if bytes.fromhex(code).startswith((b"\x8b\x3d", b"\x8b\x35")) else 1)
                       for va, code in HEAD_LOADS.items()]
    require(sorted(hits) == sorted(literal_offsets),
            f"head literal census changed: {[hex(x) for x in hits]}")
    for va, expected_hex in HEAD_LOADS.items():
        add(va, expected_hex, "absolute-head-load", "Decoded instruction loads the head pointer from 0x00619DCC.")
        off = pe.get_offset_from_rva(va - pe.OPTIONAL_HEADER.ImageBase)
        ins = next(decoder.disasm(data[off:off + 15], va, count=1), None)
        require(ins is not None and ins.mnemonic == "mov" and "0x619dcc" in ins.op_str,
                f"0x{va:08X} is not a decoded head-field load")

    # Byte-scan relative-call encodings, then decode each matching instruction
    # at its candidate VA. This bounds the direct-call census to executable PE
    # section bytes and does not claim complete interprocedural reachability.
    writer_calls: set[int] = set()
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        chunk = section.get_data()
        section_va = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
        for offset in range(len(chunk) - 4):
            if chunk[offset] != 0xE8:
                continue
            call_va = section_va + offset
            target = call_va + 5 + struct.unpack_from("<i", chunk, offset + 1)[0]
            if target != TEXTMACRO_WRITER:
                continue
            ins = next(decoder.disasm(chunk[offset:offset + 15], call_va, count=1), None)
            require(ins is not None and ins.mnemonic == "call"
                    and int(ins.op_str, 16) == TEXTMACRO_WRITER,
                    f"relative-call candidate at 0x{call_va:08X} did not decode as expected")
            writer_calls.add(call_va)
            rows.append({"binary_sha256": digest, "evidence_va": f"0x{call_va:08X}",
                         "bytes": ins.bytes.hex().upper(), "stage": "textmacro-writer-direct-call",
                         "observation": f"Direct relative call to 0x{TEXTMACRO_WRITER:08X}.",
                         "scope": "executable-section byte scan plus candidate instruction decode; no transitive-reachability proof"})
    require(writer_calls == WRITER_CALLS,
            f"textmacro writer callsite census changed: {[hex(x) for x in sorted(writer_calls)]}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("binary_sha256", "evidence_va", "bytes", "stage", "observation", "scope"))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Verified {len(FACTS)} exact instruction facts, picker exception/update API imports, both dialog RTTI/vtable links, static list bytes, {len(HEAD_LOADS)} absolute head loads, {len(writer_calls)} direct writer calls, and {modal_call_count} modal-wrapper callsites.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
