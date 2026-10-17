# RK native API import inventory

Generated from the installed RK Keyboard Software package by reading PE import tables. Per-binary counts below cover ordinary imports; delay imports are listed separately. No executable was launched and no keyboard interface was opened.

This inventory lists statically imported DLL entrypoints, not proof that every entrypoint is called at runtime. It does not cover APIs resolved dynamically with `GetProcAddress`, COM methods resolved from interface/vtable calls, calls made by Windows drivers, or behavior hidden behind indirect calls. The full application control-flow and every executed system call remain unproven.

For static addresses of direct IAT calls and callers routed through import thunks, see [`rk-native-api-xrefs.csv`](rk-native-api-xrefs.csv). Statically visible `GetProcAddress`/`LoadLibrary*` callsites and nearby literal candidates are in [`rk-dynamic-api-targets.csv`](rk-dynamic-api-targets.csv); unresolved targets and dynamic module/pointer flow remain open.

## Binaries

| Component | Relative path | SHA-256 | Size | Machine | Ordinary imports |
|---|---|---|---:|---|---:|
| Main UI and HID driver | `DeviceDriver.exe` | `c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6` | 2,326,528 | x86 | 672 |
| Model-specific firmware updater | `Dev/01AF/Update.exe` | `27894463b0dfe5bc3f5dc19d4d3351d9dfb692c402bf277bde3889d37e4a206c` | 2,109,952 | x86 | 618 |
| Installer setup helper | `InitSetup.dll` | `59db7bfd9a92cc9a0998260807f17c536ec71159b727df10d08b998bc94de301` | 69,000 | x86 | 76 |
| Uninstaller helper | `uninstall.dll` | `9ca1ebc49998b8b2971debc1776e7aff6086aeb86adcca6cfb95e9fb399eb03c` | 146,944 | x86 | 30 |
| Uninstaller | `unins000.exe` | `b4ca28b192d5a50307d2b28f3323b58b39cb51edd6682e75706cac2dd69a4a14` | 1,316,301 | x86 | 519 |

## Static call-reference coverage

The cross-reference CSV associates every ordinary or delay import row with
its IAT address and recognized executable-section reference addresses. The
following counts distinguish imports with at least one direct `call [IAT]` or
relative `call` to an import thunk from imports that have no such callsite in
the inventory:

| Binary | Import entries | Entries with a direct/thunk call reference | Entries without a recorded direct/thunk call reference |
|---|---:|---:|---:|
| `DeviceDriver.exe` | 675 | 643 | 32 |
| `Dev/01AF/Update.exe` | 618 | 606 | 12 |
| `InitSetup.dll` | 76 | 74 | 2 |
| `uninstall.dll` | 30 | 27 | 3 |
| `unins000.exe` | 519 | 506 | 13 |
| **Total** | **1,918** | **1,856** | **62** |

These are static code-reference findings, not runtime execution counts. An
entry without a listed direct or relative call can still be addressed through
an indirect pointer, callback table, or code path not recovered by the scan;
it should not be treated as proof that the imported API is unused.

The per-binary call-reference counts, direct-IAT/thunk site totals, dynamic
loader crosswalk, and native system-call byte-scan limitations are reconciled
in [`rk-system-api-crosswalk.md`](rk-system-api-crosswalk.md).
The 62 import rows without a recovered direct-IAT or relative thunk call are
listed in [`rk-native-api-callsite-gaps.csv`](rk-native-api-callsite-gaps.csv);
those rows must not be interpreted as unused APIs.

## Main UI and HID driver: `DeviceDriver.exe`

### `KERNEL32.dll` (171 imports)

`WriteConsoleW`, `GetProcessHeap`, `GetConsoleOutputCP`, `SetEnvironmentVariableA`, `WriteConsoleA`, `GetLocaleInfoA`, `GetStringTypeW`, `GetStringTypeA`, `LCMapStringW`, `LCMapStringA`, `InitializeCriticalSectionAndSpinCount`, `GetConsoleMode`, `GetTimeZoneInformation`, `GetConsoleCP`, `IsValidCodePage`, `GetOEMCP`, `GetACP`, `GetCPInfo`, `VirtualFree`, `HeapCreate`, `GetStartupInfoA`, `SetHandleCount`, `GetEnvironmentStringsW`, `FreeEnvironmentStringsW`, `GetModuleFileNameA`, `GetStdHandle`, `VirtualQuery`, `GetSystemInfo`, `VirtualAlloc`, `HeapSize`, `ExitProcess`, `GetFileType`, `SetStdHandle`, `HeapReAlloc`, `RaiseException`, `RtlUnwind`, `IsDebuggerPresent`, `SetUnhandledExceptionFilter`, `UnhandledExceptionFilter`, `TerminateProcess`, `GetSystemTimeAsFileTime`, `HeapFree`, `HeapAlloc`, `ExitThread`, `GetStartupInfoW`, `FindResourceExW`, `VirtualProtect`, `GetProfileIntW`, `SearchPathW`, `GetTempPathW`, `GetTempFileNameW`, `lstrcpyW`, `GetCurrentDirectoryW`, `SetErrorMode`, `GlobalFlags`, `lstrlenA`, `GlobalGetAtomNameW`, `TlsFree`, `LocalReAlloc`, `TlsSetValue`, `TlsAlloc`, `GlobalHandle`, `TlsGetValue`, `ReleaseMutex`, `ResumeThread`, `SetThreadPriority`, `GetCurrentThread`, `ConvertDefaultLocale`, `EnumResourceLanguagesW`, `lstrcmpA`, `GetLocaleInfoW`, `CompareStringA`, `InterlockedExchange`, `GetFullPathNameW`, `GetVolumeInformationW`, `GetCurrentProcess`, `DuplicateHandle`, `SetEndOfFile`, `UnlockFile`, `LockFile`, `FlushFileBuffers`, `SetFilePointer`, `GetThreadLocale`, `GetFileTime`, `GetFileSizeEx`, `GetFileAttributesExW`, `FileTimeToLocalFileTime`, `FileTimeToSystemTime`, `GetCurrentThreadId`, `GlobalAddAtomW`, `GlobalFindAtomW`, `GlobalDeleteAtom`, `CompareStringW`, `LoadLibraryA`, `lstrcmpW`, `GetVersionExA`, `GetCurrentProcessId`, `GetModuleHandleA`, `SetLastError`, `GlobalSize`, `MulDiv`, `CreateProcessW`, `GlobalMemoryStatusEx`, `GetSystemTimes`, `QueryPerformanceCounter`, `QueryPerformanceFrequency`, `LocalAlloc`, `GetVersionExW`, `FreeLibrary`, `FreeResource`, `GetPrivateProfileStringW`, `CreateMutexW`, `GetPrivateProfileIntW`, `LocalFree`, `GetCommandLineW`, `SetWaitableTimer`, `CreateWaitableTimerW`, `InterlockedDecrement`, `InterlockedIncrement`, `GetProcAddress`, `LoadLibraryW`, `MultiByteToWideChar`, `FormatMessageW`, `CreateDirectoryW`, `GetFileAttributesW`, `CopyFileW`, `MoveFileW`, `lstrcmpiW`, `GetModuleHandleW`, `FindClose`, `FindNextFileW`, `FindFirstFileW`, `WideCharToMultiByte`, `lstrlenW`, `GetFileSize`, `GlobalFree`, `GlobalReAlloc`, `GlobalUnlock`, `GlobalLock`, `GlobalAlloc`, `GetOverlappedResult`, `CancelIo`, `GetLocalTime`, `OutputDebugStringW`, `GetLastError`, `WaitForSingleObject`, `WriteFile`, `ReadFile`, `CreateFileW`, `CreateThread`, `ResetEvent`, `DeleteCriticalSection`, `EnterCriticalSection`, `LeaveCriticalSection`, `InitializeCriticalSection`, `GetModuleFileNameW`, `GetTickCount`, `SetEvent`, `DeleteFileW`, `WritePrivateProfileStringW`, `FindResourceW`, `LoadResource`, `LockResource`, `SizeofResource`, `WaitForMultipleObjects`, `CreateSemaphoreW`, `CreateEventW`, `ReleaseSemaphore`, `CloseHandle`, `Sleep`, `CreateFileA`

### `USER32.dll` (218 imports)

`SetWindowContextHelpId`, `MapDialogRect`, `MessageBeep`, `IsZoomed`, `PostQuitMessage`, `GetKeyNameTextW`, `CharUpperW`, `LoadMenuW`, `SetMenuItemBitmaps`, `GetMenuCheckMarkDimensions`, `LoadBitmapW`, `ModifyMenuW`, `EnableMenuItem`, `CheckMenuItem`, `GetDesktopWindow`, `GetActiveWindow`, `CreateDialogIndirectParamW`, `GetNextDlgTabItem`, `EndDialog`, `ShowWindow`, `MoveWindow`, `SetWindowTextW`, `IsDialogMessageW`, `CheckDlgButton`, `RegisterWindowMessageW`, `SendDlgItemMessageW`, `SendDlgItemMessageA`, `WinHelpW`, `IsChild`, `GetCapture`, `SetWindowsHookExW`, `CallNextHookEx`, `GetClassLongW`, `GetClassNameW`, `SetPropW`, `GetPropW`, `RemovePropW`, `GetWindowTextLengthW`, `GetForegroundWindow`, `SetActiveWindow`, `DispatchMessageW`, `BeginDeferWindowPos`, `EndDeferWindowPos`, `GetDlgItem`, `GetTopWindow`, `UnhookWindowsHookEx`, `GetMessageTime`, `GetMessagePos`, `PeekMessageW`, `MapWindowPoints`, `ScrollWindow`, `GetKeyState`, `SetMenu`, `SetScrollRange`, `GetScrollRange`, `SetScrollPos`, `GetScrollPos`, `GetClassInfoExW`, `GetClassInfoW`, `RegisterClassW`, `AdjustWindowRectEx`, `EqualRect`, `DeferWindowPos`, `GetScrollInfo`, `SetScrollInfo`, `SetWindowPlacement`, `GetDlgCtrlID`, `DefWindowProcW`, `GetMenu`, `IntersectRect`, `SystemParametersInfoA`, `GetWindowPlacement`, `ValidateRect`, `GetWindowThreadProcessId`, `IsWindowEnabled`, `EndPaint`, `BeginPaint`, `GrayStringW`, `DrawTextExW`, `DrawTextW`, `TabbedTextOutW`, `GetMenuState`, `GetMenuStringW`, `GetMenuItemID`, `InsertMenuW`, `GetMenuItemCount`, `GetSubMenu`, `RemoveMenu`, `ShowScrollBar`, `MapVirtualKeyW`, `SetWindowPos`, `ClientToScreen`, `SetWindowRgn`, `GetWindowDC`, `OffsetRect`, `TrackPopupMenu`, `CreatePopupMenu`, `GetLastActivePopup`, `RegisterDeviceNotificationW`, `DrawIcon`, `IsIconic`, `SetForegroundWindow`, `AppendMenuW`, `GetSystemMenu`, `UnregisterDeviceNotification`, `TranslateMessage`, `GetMessageW`, `ShowOwnedPopups`, `LoadIconW`, `LoadImageW`, `FindWindowW`, `PostMessageW`, `MessageBoxW`, `InvalidateRect`, `IsWindow`, `ReleaseCapture`, `SetCapture`, `UpdateWindow`, `GetDoubleClickTime`, `SystemParametersInfoW`, `RedrawWindow`, `DrawEdge`, `InflateRect`, `GetSysColor`, `CreateWindowExW`, `CallWindowProcW`, `DestroyWindow`, `GetWindowTextW`, `SetRectEmpty`, `TrackMouseEvent`, `SetWindowLongW`, `GetWindowLongW`, `KillTimer`, `GetMenuItemInfoW`, `DestroyMenu`, `WindowFromPoint`, `GetSysColorBrush`, `WaitMessage`, `DeleteMenu`, `PostThreadMessageW`, `CopyAcceleratorTableW`, `ToUnicodeEx`, `GetKeyboardLayout`, `GetKeyboardState`, `GetAsyncKeyState`, `DestroyAcceleratorTable`, `LoadAcceleratorsW`, `ReleaseDC`, `CopyRect`, `SetTimer`, `GetSystemMetrics`, `GetWindowRect`, `SetCursor`, `LoadCursorW`, `ScreenToClient`, `GetCursorPos`, `PtInRect`, `GetDC`, `CreateAcceleratorTableW`, `NotifyWinEvent`, `SetParent`, `SetClassLongW`, `IsMenu`, `IsRectEmpty`, `DrawStateW`, `BringWindowToTop`, `LockWindowUpdate`, `GetClientRect`, `SetRect`, `FillRect`, `IsWindowVisible`, `FrameRect`, `GetParent`, `EnableWindow`, `SendMessageW`, `GetFocus`, `SetFocus`, `EnumChildWindows`, `RegisterClipboardFormatW`, `DestroyCursor`, `GetWindowRgn`, `CreateMenu`, `GetIconInfo`, `SubtractRect`, `CopyIcon`, `CharUpperBuffW`, `GetUpdateRect`, `TranslateMDISysAccel`, `DrawMenuBar`, `DefMDIChildProcW`, `DefFrameProcW`, `IsClipboardFormatAvailable`, `MapVirtualKeyExW`, `IsCharLowerW`, `GetMenuDefaultItem`, `SetMenuDefaultItem`, `UpdateLayeredWindow`, `EnableScrollBar`, `UnionRect`, `SetCursorPos`, `DrawFocusRect`, `DrawFrameControl`, `DrawIconEx`, `UnpackDDElParam`, `ReuseDDElParam`, `InsertMenuItemW`, `TranslateAcceleratorW`, `UnregisterClassW`, `GetNextDlgGroupItem`, `InvalidateRgn`, `CharNextW`, `EmptyClipboard`, `CloseClipboard`, `SetClipboardData`, `DestroyIcon`, `CopyImage`, `OpenClipboard`, `GetWindow`

### `GDI32.dll` (100 imports)

`RestoreDC`, `SetBkColor`, `SetBkMode`, `SetPolyFillMode`, `SetROP2`, `SetTextColor`, `SetMapMode`, `GetClipBox`, `ExcludeClipRect`, `IntersectClipRect`, `LineTo`, `MoveToEx`, `SetTextAlign`, `SelectClipRgn`, `GetViewportExtEx`, `GetWindowExtEx`, `PtVisible`, `RectVisible`, `TextOutW`, `ExtTextOutW`, `Escape`, `SetViewportOrgEx`, `OffsetViewportOrgEx`, `SetViewportExtEx`, `ScaleViewportExtEx`, `SetWindowOrgEx`, `OffsetWindowOrgEx`, `SetWindowExtEx`, `ScaleWindowExtEx`, `ExtSelectClipRgn`, `CreatePatternBrush`, `CreateBitmap`, `GetObjectType`, `SaveDC`, `CreatePen`, `CreateHatchBrush`, `GetDCOrgEx`, `CreateRectRgnIndirect`, `PatBlt`, `SetRectRgn`, `GetMapMode`, `DPtoLP`, `GetTextMetricsW`, `OffsetRgn`, `GetRgnBox`, `CreateDIBitmap`, `GetTextCharsetInfo`, `CreateRoundRectRgn`, `GetTextColor`, `SetDIBColorTable`, `GetBkColor`, `Ellipse`, `Polygon`, `Rectangle`, `RoundRect`, `CreatePalette`, `GetPaletteEntries`, `GetWindowOrgEx`, `FillRgn`, `FrameRgn`, `GetBoundsRect`, `GetViewportOrgEx`, `LPtoDP`, `ExtFloodFill`, `SetPaletteEntries`, `GetNearestPaletteIndex`, `GetSystemPaletteEntries`, `EnumFontFamiliesExW`, `GetTextFaceW`, `SetPixelV`, `CopyMetaFileW`, `GetDeviceCaps`, `EnumFontFamiliesW`, `GetTextExtentPoint32W`, `RemoveFontResourceW`, `AddFontResourceW`, `CreateFontIndirectW`, `CreateRectRgn`, `Polyline`, `CreateSolidBrush`, `CreatePolygonRgn`, `GetDIBits`, `RealizePalette`, `SelectPalette`, `GetStockObject`, `StretchBlt`, `DeleteDC`, `CombineRgn`, `SelectObject`, `CreateDIBSection`, `GetObjectW`, `SetPixel`, `PtInRegion`, `GetPixel`, `CreateEllipticRgn`, `CreateFontW`, `BitBlt`, `CreateCompatibleBitmap`, `DeleteObject`, `CreateCompatibleDC`

### `MSIMG32.dll` (2 imports)

`AlphaBlend`, `TransparentBlt`

### `COMDLG32.dll` (1 imports)

`GetFileTitleW`

### `WINSPOOL.DRV` (3 imports)

`OpenPrinterW`, `ClosePrinter`, `DocumentPropertiesW`

### `ADVAPI32.dll` (14 imports)

`RegOpenKeyExW`, `RegQueryValueExW`, `AllocateAndInitializeSid`, `CheckTokenMembership`, `FreeSid`, `RegOpenKeyW`, `RegCreateKeyExW`, `RegSetValueExW`, `RegEnumKeyExW`, `RegCloseKey`, `RegQueryValueW`, `RegEnumKeyW`, `RegDeleteKeyW`, `RegDeleteValueW`

### `SHELL32.dll` (12 imports)

`SHGetFileInfoW`, `ShellExecuteW`, `SHGetSpecialFolderLocation`, `SHGetPathFromIDListW`, `SHGetSpecialFolderPathW`, `DragQueryFileW`, `DragFinish`, `SHBrowseForFolderW`, `SHAppBarMessage`, `ShellExecuteExW`, `Shell_NotifyIconW`, `CommandLineToArgvW`

### `COMCTL32.dll` (2 imports)

`InitCommonControlsEx`, `ImageList_GetIconSize`

### `SHLWAPI.dll` (8 imports)

`PathFileExistsW`, `StrStrIW`, `PathRemoveFileSpecW`, `PathFindExtensionW`, `PathFindFileNameW`, `PathRemoveExtensionW`, `PathStripToRootW`, `PathIsUNCW`

### `oledlg.dll` (1 imports)

`OleUIBusyW`

### `ole32.dll` (32 imports)

`ReleaseStgMedium`, `CoTaskMemAlloc`, `OleDuplicateData`, `CoInitializeEx`, `CLSIDFromProgID`, `CLSIDFromString`, `CoGetClassObject`, `StgOpenStorageOnILockBytes`, `StgCreateDocfileOnILockBytes`, `CreateILockBytesOnHGlobal`, `OleLockRunning`, `OleIsCurrentClipboard`, `OleFlushClipboard`, `DoDragDrop`, `OleGetClipboard`, `OleUninitialize`, `CoFreeUnusedLibraries`, `OleInitialize`, `OleCreateMenuDescriptor`, `OleDestroyMenuDescriptor`, `OleTranslateAccelerator`, `IsAccelerator`, `CreateStreamOnHGlobal`, `CoTaskMemFree`, `CoUninitialize`, `CoCreateInstance`, `CoInitialize`, `CoRegisterMessageFilter`, `CoRevokeClassObject`, `RevokeDragDrop`, `CoLockObjectExternal`, `RegisterDragDrop`

### `OLEAUT32.dll` (12 imports)

`SysAllocStringLen`, `VariantClear`, `VariantChangeType`, `VariantInit`, `VariantCopy`, `SysFreeString`, `SafeArrayDestroy`, `VariantTimeToSystemTime`, `SystemTimeToVariantTime`, `SysAllocString`, `OleCreateFontIndirect`, `SysStringLen`

### `urlmon.dll` (1 imports)

`URLDownloadToFileW`

### `gdiplus.dll` (66 imports)

`GdipBitmapLockBits`, `GdipCreateBitmapFromStreamICM`, `GdipCreateBitmapFromStream`, `GdipGetImagePalette`, `GdipGetImagePaletteSize`, `GdipGetImagePixelFormat`, `GdipGetAllPropertyItems`, `GdipGetPropertySize`, `GdipScaleWorldTransform`, `GdipGraphicsClear`, `GdipDrawImageI`, `GdipSetPixelOffsetMode`, `GdipSetInterpolationMode`, `GdipSetImageAttributesWrapMode`, `GdipDisposeImageAttributes`, `GdipCreateImageAttributes`, `GdipBitmapSetPixel`, `GdipRotateWorldTransform`, `GdipBitmapUnlockBits`, `GdipSetPropertyItem`, `GdipSaveAddImage`, `GdipImageGetFrameCount`, `GdipImageGetFrameDimensionsCount`, `GdipImageSelectActiveFrame`, `GdipFillRectangleI`, `GdipSaveImageToFile`, `GdipGetImageEncoders`, `GdipGetImageEncodersSize`, `GdipAddPathRectangleI`, `GdipBitmapGetPixel`, `GdipDrawImageRectI`, `GdipImageGetFrameDimensionsList`, `GdipTranslateWorldTransform`, `GdipFree`, `GdipDisposeImage`, `GdipAlloc`, `GdipCloneImage`, `GdipCreateFromHDC`, `GdipDeleteGraphics`, `GdipGetImageHeight`, `GdipGetImageWidth`, `GdipDrawImageRectRect`, `GdipCreateBitmapFromFile`, `GdipCreateSolidFill`, `GdipDeleteBrush`, `GdipCloneBrush`, `GdipDrawImageRect`, `GdipCreateBitmapFromScan0`, `GdipGetImageGraphicsContext`, `GdipFillRectangle`, `GdipCloneBitmapAreaI`, `GdipAddPathArcI`, `GdipAddPathLineI`, `GdipCreatePath`, `GdipDeletePath`, `GdipCreatePen1`, `GdipDeletePen`, `GdipDrawPath`, `GdiplusShutdown`, `GdipFillPath`, `GdipSetPenColor`, `GdipIsVisiblePathPointI`, `GdipSetSmoothingMode`, `GdipResetPath`, `GdiplusStartup`, `GdipDrawRectangle`

### `SETUPAPI.dll` (4 imports)

`SetupDiGetDeviceInterfaceDetailW`, `SetupDiGetClassDevsW`, `SetupDiEnumDeviceInterfaces`, `SetupDiDestroyDeviceInfoList`

### `HID.DLL` (9 imports)

`HidD_SetFeature`, `HidD_GetHidGuid`, `HidD_GetPreparsedData`, `HidD_GetAttributes`, `HidP_GetCaps`, `HidD_FreePreparsedData`, `HidP_GetSpecificButtonCaps`, `HidP_GetSpecificValueCaps`, `HidD_GetFeature`

### `WININET.dll` (1 imports)

`DeleteUrlCacheEntryW`

### `IMM32.dll` (4 imports)

`ImmGetOpenStatus`, `ImmReleaseContext`, `ImmGetContext`, `ImmGetVirtualKey`

### `WINMM.dll` (5 imports)

`PlaySoundW`, `timeKillEvent`, `timeGetDevCaps`, `timeBeginPeriod`, `timeEndPeriod`

### `pdh.dll` (6 imports)

`PdhCloseQuery`, `PdhCalculateCounterFromRawValue`, `PdhOpenQueryW`, `PdhAddCounterW`, `PdhCollectQueryData`, `PdhGetRawCounterValue`


## Model-specific firmware updater: `Dev/01AF/Update.exe`

### `SETUPAPI.dll` (4 imports)

`SetupDiGetDeviceInterfaceDetailW`, `SetupDiDestroyDeviceInfoList`, `SetupDiEnumDeviceInterfaces`, `SetupDiGetClassDevsW`

### `HID.DLL` (7 imports)

`HidP_GetCaps`, `HidD_GetFeature`, `HidD_GetHidGuid`, `HidD_GetAttributes`, `HidD_FreePreparsedData`, `HidD_SetFeature`, `HidD_GetPreparsedData`

### `KERNEL32.dll` (164 imports)

`GetFileType`, `GetStdHandle`, `GetStartupInfoW`, `QueryPerformanceCounter`, `GetEnvironmentStringsW`, `FreeEnvironmentStringsW`, `UnhandledExceptionFilter`, `SetUnhandledExceptionFilter`, `TerminateProcess`, `IsValidCodePage`, `GetACP`, `GetOEMCP`, `GetCPInfo`, `GetTimeZoneInformation`, `GetDateFormatW`, `GetTimeFormatW`, `LCMapStringW`, `GetConsoleCP`, `GetConsoleMode`, `ReadConsoleW`, `SetFilePointerEx`, `GetStringTypeW`, `OutputDebugStringW`, `WriteConsoleW`, `SetEnvironmentVariableA`, `SetStdHandle`, `IsDebuggerPresent`, `VirtualQuery`, `VirtualAlloc`, `GetSystemInfo`, `HeapQueryInformation`, `GetModuleHandleExW`, `ExitProcess`, `CloseHandle`, `ExitThread`, `SizeofResource`, `LockResource`, `LoadResource`, `FindResourceW`, `GetLastError`, `WritePrivateProfileStringW`, `CreateFileW`, `CreateEventW`, `SetEvent`, `WaitForMultipleObjects`, `ResetEvent`, `SetCommMask`, `GetCommState`, `SetCommState`, `SetCommTimeouts`, `WaitForSingleObject`, `WaitCommEvent`, `GetOverlappedResult`, `ClearCommError`, `ReadFile`, `WriteFile`, `HeapReAlloc`, `HeapAlloc`, `HeapFree`, `GetProcessHeap`, `InitializeCriticalSectionAndSpinCount`, `RaiseException`, `HeapSize`, `DecodePointer`, `DeleteCriticalSection`, `CreateMutexW`, `GetSystemDefaultLangID`, `GetCommandLineW`, `FindResourceExW`, `VirtualProtect`, `SearchPathW`, `GetProfileIntW`, `GetTempPathW`, `GetTempFileNameW`, `VerifyVersionInfoW`, `VerSetConditionMask`, `lstrcpyW`, `GetWindowsDirectoryW`, `GetModuleFileNameW`, `RtlUnwind`, `GetSystemTimeAsFileTime`, `Sleep`, `IsProcessorFeaturePresent`, `GetPrivateProfileIntW`, `GetDriveTypeW`, `GetFileTime`, `GetFileSizeEx`, `GetFileAttributesExW`, `GetFileAttributesW`, `SetErrorMode`, `lstrcmpiW`, `GetCurrentProcess`, `DuplicateHandle`, `UnlockFile`, `SetFilePointer`, `SetEndOfFile`, `LockFile`, `GetVolumeInformationW`, `GetFullPathNameW`, `GetFileSize`, `FlushFileBuffers`, `DeleteFileW`, `GetUserDefaultUILanguage`, `GetSystemDefaultUILanguage`, `GetLocaleInfoW`, `CompareStringW`, `GetCurrentDirectoryW`, `GlobalFlags`, `LocalReAlloc`, `LocalAlloc`, `GlobalHandle`, `GlobalReAlloc`, `TlsFree`, `TlsSetValue`, `TlsGetValue`, `TlsAlloc`, `InitializeCriticalSection`, `GetThreadLocale`, `GlobalGetAtomNameW`, `GlobalFindAtomW`, `GetSystemDirectoryW`, `LeaveCriticalSection`, `EnterCriticalSection`, `EncodePointer`, `FileTimeToSystemTime`, `FindNextFileW`, `FindFirstFileW`, `FindClose`, `FileTimeToLocalFileTime`, `GlobalAddAtomW`, `LoadLibraryA`, `LoadLibraryW`, `GetModuleHandleA`, `OutputDebugStringA`, `GetProcAddress`, `GetModuleHandleW`, `FreeResource`, `GetTickCount`, `lstrcmpW`, `GlobalDeleteAtom`, `LoadLibraryExW`, `FreeLibrary`, `GetVersionExW`, `GetCurrentThread`, `lstrcmpA`, `ResumeThread`, `SuspendThread`, `SetThreadPriority`, `GetCurrentThreadId`, `GetCurrentProcessId`, `SetLastError`, `CopyFileW`, `FormatMessageW`, `MulDiv`, `LocalFree`, `GlobalFree`, `GlobalUnlock`, `GlobalLock`, `GlobalSize`, `GlobalAlloc`, `WideCharToMultiByte`, `GetPrivateProfileStringW`, `MultiByteToWideChar`, `CreateThread`

### `USER32.dll` (223 imports)

`CreateMenu`, `DestroyCursor`, `GetWindowRgn`, `MapVirtualKeyExW`, `IsCharLowerW`, `GetKeyboardLayout`, `IsZoomed`, `GetComboBoxInfo`, `TrackMouseEvent`, `MonitorFromPoint`, `UpdateLayeredWindow`, `IsMenu`, `SetWindowRgn`, `DrawFrameControl`, `DrawEdge`, `DrawStateW`, `EmptyClipboard`, `SetClipboardData`, `CloseClipboard`, `OpenClipboard`, `EnumDisplayMonitors`, `SetLayeredWindowAttributes`, `SetParent`, `UnionRect`, `NotifyWinEvent`, `InvertRect`, `HideCaret`, `EnableScrollBar`, `GetAsyncKeyState`, `GetIconInfo`, `DrawIconEx`, `DrawFocusRect`, `GetMenuDefaultItem`, `ReuseDDElParam`, `UnpackDDElParam`, `LoadImageW`, `SetRectEmpty`, `InsertMenuItemW`, `CreatePopupMenu`, `TranslateAcceleratorW`, `LoadAcceleratorsW`, `BringWindowToTop`, `CharUpperW`, `DestroyIcon`, `MessageBeep`, `GetNextDlgGroupItem`, `IsRectEmpty`, `SetRect`, `InvalidateRgn`, `CopyAcceleratorTableW`, `OffsetRect`, `CharNextW`, `PostThreadMessageW`, `InvalidateRect`, `SetTimer`, `DeleteMenu`, `CopyImage`, `WindowFromPoint`, `ReleaseCapture`, `SetCapture`, `WaitMessage`, `RealChildWindowFromPoint`, `IntersectRect`, `LoadCursorW`, `GetSysColorBrush`, `SystemParametersInfoW`, `InflateRect`, `GetMenuItemInfoW`, `DestroyMenu`, `SendDlgItemMessageA`, `GetMonitorInfoW`, `MonitorFromWindow`, `WinHelpW`, `GetScrollInfo`, `SetScrollInfo`, `GetClassNameW`, `GetClassLongW`, `PtInRect`, `EqualRect`, `AdjustWindowRectEx`, `RemovePropW`, `GetPropW`, `SetPropW`, `ShowScrollBar`, `GetScrollRange`, `SetScrollRange`, `GetScrollPos`, `SetScrollPos`, `ScrollWindow`, `RedrawWindow`, `SetForegroundWindow`, `GetForegroundWindow`, `UpdateWindow`, `TrackPopupMenu`, `SetMenu`, `GetMenu`, `GetCapture`, `EndDeferWindowPos`, `DeferWindowPos`, `BeginDeferWindowPos`, `SetWindowPlacement`, `GetWindowPlacement`, `IsChild`, `CreateWindowExW`, `GetClassInfoExW`, `GetClassInfoW`, `RegisterClassW`, `CallWindowProcW`, `DefWindowProcW`, `GetMessageTime`, `GetMessagePos`, `RegisterWindowMessageW`, `SetCursor`, `ShowOwnedPopups`, `LoadBitmapW`, `SetMenuItemInfoW`, `GetMenuCheckMarkDimensions`, `SetMenuItemBitmaps`, `EnableMenuItem`, `GetWindowRect`, `LoadMenuW`, `CopyRect`, `MapVirtualKeyW`, `GetKeyNameTextW`, `GetDesktopWindow`, `SetActiveWindow`, `GetNextDlgTabItem`, `EndDialog`, `CreateDialogIndirectParamW`, `DestroyWindow`, `MapDialogRect`, `SetWindowContextHelpId`, `RegisterClipboardFormatW`, `PostQuitMessage`, `CallNextHookEx`, `SetWindowsHookExW`, `GetCursorPos`, `ValidateRect`, `GetKeyState`, `GetActiveWindow`, `IsWindowVisible`, `PeekMessageW`, `DispatchMessageW`, `TranslateMessage`, `GetMessageW`, `GetLastActivePopup`, `GetWindowThreadProcessId`, `FillRect`, `GetSysColor`, `ScreenToClient`, `ClientToScreen`, `EndPaint`, `BeginPaint`, `ReleaseDC`, `GetWindowDC`, `GetDC`, `TabbedTextOutW`, `GrayStringW`, `DrawTextExW`, `DrawTextW`, `IsDialogMessageW`, `GetWindow`, `SubtractRect`, `GetUpdateRect`, `IsClipboardFormatAvailable`, `TranslateMDISysAccel`, `DefMDIChildProcW`, `DefFrameProcW`, `DrawMenuBar`, `FrameRect`, `CharUpperBuffW`, `ModifyMenuW`, `SetMenuDefaultItem`, `CopyIcon`, `GetDoubleClickTime`, `GetParent`, `SetWindowLongW`, `SetClassLongW`, `SetCursorPos`, `DestroyAcceleratorTable`, `CreateAcceleratorTableW`, `GetKeyboardState`, `ToUnicodeEx`, `MapWindowPoints`, `LockWindowUpdate`, `GetWindowLongW`, `GetWindowTextLengthW`, `GetWindowTextW`, `SetWindowTextW`, `IsWindowEnabled`, `GetFocus`, `SetFocus`, `GetDlgCtrlID`, `CheckDlgButton`, `GetDlgItem`, `SetWindowPos`, `MoveWindow`, `ShowWindow`, `IsWindow`, `UnhookWindowsHookEx`, `RemoveMenu`, `InsertMenuW`, `GetMenuItemCount`, `GetMenuItemID`, `GetMenuState`, `GetMenuStringW`, `GetSubMenu`, `CheckMenuItem`, `KillTimer`, `RegisterDeviceNotificationW`, `DrawIcon`, `GetClientRect`, `GetSystemMetrics`, `IsIconic`, `AppendMenuW`, `GetSystemMenu`, `LoadIconW`, `EnableWindow`, `MessageBoxW`, `UnregisterClassW`, `PostMessageW`, `SendMessageW`, `GetTopWindow`

### `GDI32.dll` (98 imports)

`GetObjectType`, `GetPixel`, `GetViewportExtEx`, `GetWindowExtEx`, `IntersectClipRect`, `LineTo`, `PtVisible`, `RectVisible`, `RestoreDC`, `SaveDC`, `SelectClipRgn`, `ExtSelectClipRgn`, `SelectObject`, `SelectPalette`, `SetBkColor`, `SetBkMode`, `SetMapMode`, `SetLayout`, `GetLayout`, `SetPolyFillMode`, `SetROP2`, `SetTextColor`, `SetTextAlign`, `GetObjectW`, `MoveToEx`, `TextOutW`, `ExtTextOutW`, `SetViewportExtEx`, `SetViewportOrgEx`, `SetWindowExtEx`, `SetWindowOrgEx`, `OffsetViewportOrgEx`, `OffsetWindowOrgEx`, `ScaleViewportExtEx`, `GetDeviceCaps`, `ScaleWindowExtEx`, `CreateRectRgnIndirect`, `PatBlt`, `GetTextExtentPoint32W`, `GetClipBox`, `GetMapMode`, `SetRectRgn`, `DPtoLP`, `GetBkColor`, `GetTextColor`, `GetRgnBox`, `GetTextMetricsW`, `CreateCompatibleBitmap`, `CreatePalette`, `GetNearestPaletteIndex`, `GetPaletteEntries`, `GetSystemPaletteEntries`, `RealizePalette`, `CreateDIBitmap`, `EnumFontFamiliesW`, `GetTextCharsetInfo`, `SetPixel`, `StretchBlt`, `CreateDIBSection`, `SetDIBColorTable`, `CreateEllipticRgn`, `Ellipse`, `CreatePolygonRgn`, `Polygon`, `Polyline`, `Rectangle`, `EnumFontFamiliesExW`, `OffsetRgn`, `CreateRoundRectRgn`, `RoundRect`, `FrameRgn`, `PtInRegion`, `SetPixelV`, `ExtFloodFill`, `SetPaletteEntries`, `FillRgn`, `GetBoundsRect`, `GetWindowOrgEx`, `LPtoDP`, `GetViewportOrgEx`, `GetTextFaceW`, `ExcludeClipRect`, `Escape`, `DeleteObject`, `DeleteDC`, `CreateRectRgn`, `CreatePatternBrush`, `CreatePen`, `CreateHatchBrush`, `CreateCompatibleDC`, `CreateBitmap`, `CreateDCW`, `CopyMetaFileW`, `GetStockObject`, `CreateSolidBrush`, `CombineRgn`, `CreateFontIndirectW`, `BitBlt`

### `MSIMG32.dll` (2 imports)

`TransparentBlt`, `AlphaBlend`

### `WINSPOOL.DRV` (3 imports)

`ClosePrinter`, `OpenPrinterW`, `DocumentPropertiesW`

### `ADVAPI32.dll` (11 imports)

`RegDeleteValueW`, `RegEnumKeyExW`, `RegQueryValueW`, `RegEnumKeyW`, `RegSetValueExW`, `RegOpenKeyExW`, `RegDeleteKeyW`, `RegCreateKeyExW`, `RegQueryValueExW`, `RegCloseKey`, `RegEnumValueW`

### `SHELL32.dll` (9 imports)

`SHBrowseForFolderW`, `SHGetFileInfoW`, `DragQueryFileW`, `DragFinish`, `ShellExecuteW`, `SHGetPathFromIDListW`, `SHAppBarMessage`, `SHGetDesktopFolder`, `SHGetSpecialFolderLocation`

### `COMCTL32.dll` (1 imports)

`InitCommonControlsEx`

### `SHLWAPI.dll` (6 imports)

`PathFindFileNameW`, `PathRemoveFileSpecW`, `PathIsUNCW`, `PathStripToRootW`, `PathFindExtensionW`, `StrFormatKBSizeW`

### `UxTheme.dll` (12 imports)

`DrawThemeParentBackground`, `GetWindowTheme`, `GetThemeSysColor`, `IsAppThemed`, `DrawThemeText`, `DrawThemeBackground`, `IsThemeBackgroundPartiallyTransparent`, `GetThemePartSize`, `GetCurrentThemeName`, `OpenThemeData`, `CloseThemeData`, `GetThemeColor`

### `ole32.dll` (34 imports)

`CoRegisterMessageFilter`, `OleIsCurrentClipboard`, `OleFlushClipboard`, `CoRevokeClassObject`, `CoGetClassObject`, `CoDisconnectObject`, `CoInitializeEx`, `CoInitialize`, `CoCreateInstance`, `CLSIDFromProgID`, `CLSIDFromString`, `OleUninitialize`, `CoFreeUnusedLibraries`, `CoCreateGuid`, `CoUninitialize`, `ReleaseStgMedium`, `OleDuplicateData`, `StgCreateDocfileOnILockBytes`, `CoTaskMemFree`, `CoTaskMemAlloc`, `RevokeDragDrop`, `RegisterDragDrop`, `CoLockObjectExternal`, `OleGetClipboard`, `IsAccelerator`, `OleTranslateAccelerator`, `OleDestroyMenuDescriptor`, `OleCreateMenuDescriptor`, `OleLockRunning`, `DoDragDrop`, `CreateStreamOnHGlobal`, `CreateILockBytesOnHGlobal`, `OleInitialize`, `StgOpenStorageOnILockBytes`

### `OLEAUT32.dll` (14 imports)

`OleCreateFontIndirect`, `LoadTypeLib`, `VarBstrFromDate`, `VariantCopy`, `SafeArrayDestroy`, `VariantTimeToSystemTime`, `SystemTimeToVariantTime`, `SysStringLen`, `VariantChangeType`, `VariantClear`, `VariantInit`, `SysAllocStringLen`, `SysAllocString`, `SysFreeString`

### `oledlg.dll` (1 imports)

`OleUIBusyW`

### `OLEACC.dll` (3 imports)

`CreateStdAccessibleObject`, `AccessibleObjectFromWindow`, `LresultFromObject`

### `gdiplus.dll` (22 imports)

`GdipSetInterpolationMode`, `GdipCreateFromHDC`, `GdipCreateBitmapFromHBITMAP`, `GdipDrawImageI`, `GdipDeleteGraphics`, `GdipBitmapUnlockBits`, `GdipBitmapLockBits`, `GdipCreateBitmapFromScan0`, `GdipCreateBitmapFromStream`, `GdipGetImagePaletteSize`, `GdipGetImagePalette`, `GdipGetImagePixelFormat`, `GdipGetImageHeight`, `GdipGetImageWidth`, `GdipGetImageGraphicsContext`, `GdipDisposeImage`, `GdipCloneImage`, `GdiplusStartup`, `GdipFree`, `GdipAlloc`, `GdiplusShutdown`, `GdipDrawImageRectI`

### `IMM32.dll` (3 imports)

`ImmGetContext`, `ImmReleaseContext`, `ImmGetOpenStatus`

### `WINMM.dll` (1 imports)

`PlaySoundW`


## Installer setup helper: `InitSetup.dll`

### `SHLWAPI.dll` (1 imports)

`PathFileExistsW`

### `KERNEL32.dll` (75 imports)

`GetCurrentProcessId`, `OutputDebugStringW`, `FindFirstFileW`, `SetFileAttributesW`, `DeleteFileW`, `GetLastError`, `FindNextFileW`, `FindClose`, `RemoveDirectoryW`, `GetCurrentThreadId`, `GetCommandLineA`, `TerminateProcess`, `GetCurrentProcess`, `UnhandledExceptionFilter`, `SetUnhandledExceptionFilter`, `IsDebuggerPresent`, `GetModuleHandleW`, `GetProcAddress`, `TlsGetValue`, `TlsAlloc`, `TlsSetValue`, `TlsFree`, `InterlockedIncrement`, `SetLastError`, `InterlockedDecrement`, `HeapFree`, `Sleep`, `ExitProcess`, `SetHandleCount`, `GetStdHandle`, `GetFileType`, `GetStartupInfoA`, `DeleteCriticalSection`, `GetModuleFileNameA`, `FreeEnvironmentStringsA`, `GetEnvironmentStrings`, `FreeEnvironmentStringsW`, `WideCharToMultiByte`, `GetEnvironmentStringsW`, `HeapCreate`, `HeapDestroy`, `VirtualFree`, `QueryPerformanceCounter`, `GetTickCount`, `GetSystemTimeAsFileTime`, `SetFilePointer`, `WriteFile`, `GetConsoleCP`, `GetConsoleMode`, `EnterCriticalSection`, `LeaveCriticalSection`, `GetCPInfo`, `GetACP`, `GetOEMCP`, `IsValidCodePage`, `MultiByteToWideChar`, `HeapAlloc`, `VirtualAlloc`, `HeapReAlloc`, `LoadLibraryA`, `InitializeCriticalSectionAndSpinCount`, `RtlUnwind`, `SetStdHandle`, `WriteConsoleA`, `GetConsoleOutputCP`, `WriteConsoleW`, `LCMapStringA`, `LCMapStringW`, `GetStringTypeA`, `GetStringTypeW`, `GetLocaleInfoA`, `HeapSize`, `CreateFileA`, `CloseHandle`, `FlushFileBuffers`


## Uninstaller helper: `uninstall.dll`

### `MSVCR90.dll` (17 imports)

`_lock`, `__dllonexit`, `_except_handler4_common`, `_unlock`, `__clean_type_info_names_internal`, `_crt_debugger_hook`, `__CppXcptFilter`, `_adjust_fdiv`, `_amsg_exit`, `_initterm_e`, `_initterm`, `_decode_pointer`, `_encoded_null`, `free`, `_malloc_crt`, `_onexit`, `_encode_pointer`

### `KERNEL32.dll` (13 imports)

`GetCurrentProcessId`, `GetCurrentThreadId`, `GetTickCount`, `QueryPerformanceCounter`, `IsDebuggerPresent`, `SetUnhandledExceptionFilter`, `UnhandledExceptionFilter`, `GetCurrentProcess`, `TerminateProcess`, `InterlockedCompareExchange`, `Sleep`, `InterlockedExchange`, `GetSystemTimeAsFileTime`


## Uninstaller: `unins000.exe`

### `oleaut32.dll` (3 imports)

`SysFreeString`, `SysReAllocStringLen`, `SysAllocStringLen`

### `advapi32.dll` (3 imports)

`RegQueryValueExW`, `RegOpenKeyExW`, `RegCloseKey`

### `user32.dll` (4 imports)

`GetKeyboardType`, `LoadStringW`, `MessageBoxA`, `CharNextW`

### `kernel32.dll` (37 imports)

`GetACP`, `Sleep`, `VirtualFree`, `VirtualAlloc`, `GetSystemInfo`, `GetTickCount`, `QueryPerformanceCounter`, `GetVersion`, `GetCurrentThreadId`, `VirtualQuery`, `WideCharToMultiByte`, `SetCurrentDirectoryW`, `MultiByteToWideChar`, `lstrlenW`, `lstrcpynW`, `LoadLibraryExW`, `GetThreadLocale`, `GetStartupInfoA`, `GetProcAddress`, `GetModuleHandleW`, `GetModuleFileNameW`, `GetLocaleInfoW`, `GetCurrentDirectoryW`, `GetCommandLineW`, `FreeLibrary`, `FindFirstFileW`, `FindClose`, `ExitProcess`, `ExitThread`, `CreateThread`, `CompareStringW`, `WriteFile`, `UnhandledExceptionFilter`, `RtlUnwind`, `RaiseException`, `GetStdHandle`, `CloseHandle`

### `kernel32.dll` (4 imports)

`TlsSetValue`, `TlsGetValue`, `LocalAlloc`, `GetModuleHandleW`

### `user32.dll` (179 imports)

`CreateWindowExW`, `WindowFromPoint`, `WaitMessage`, `WaitForInputIdle`, `UpdateWindow`, `UnregisterClassW`, `UnhookWindowsHookEx`, `TranslateMessage`, `TranslateMDISysAccel`, `TrackPopupMenu`, `SystemParametersInfoW`, `ShowWindow`, `ShowScrollBar`, `ShowOwnedPopups`, `SetWindowsHookExW`, `SetWindowTextW`, `SetWindowPos`, `SetWindowPlacement`, `SetWindowLongW`, `SetTimer`, `SetScrollRange`, `SetScrollPos`, `SetScrollInfo`, `SetRectEmpty`, `SetRect`, `SetPropW`, `SetParent`, `SetMenuItemInfoW`, `SetMenu`, `SetForegroundWindow`, `SetFocus`, `SetCursor`, `SetClassLongW`, `SetCapture`, `SetActiveWindow`, `SendNotifyMessageW`, `SendMessageTimeoutW`, `SendMessageA`, `SendMessageW`, `ScrollWindowEx`, `ScrollWindow`, `ScreenToClient`, `ReplyMessage`, `RemovePropW`, `RemoveMenu`, `ReleaseDC`, `ReleaseCapture`, `RegisterWindowMessageW`, `RegisterClipboardFormatW`, `RegisterClassW`, `RedrawWindow`, `PtInRect`, `PostQuitMessage`, `PostMessageW`, `PeekMessageA`, `PeekMessageW`, `OffsetRect`, `OemToCharBuffA`, `MsgWaitForMultipleObjectsEx`, `MsgWaitForMultipleObjects`, `MessageBoxW`, `MessageBeep`, `MapWindowPoints`, `MapVirtualKeyW`, `LoadStringW`, `LoadKeyboardLayoutW`, `LoadIconW`, `LoadCursorW`, `LoadBitmapW`, `KillTimer`, `IsZoomed`, `IsWindowVisible`, `IsWindowUnicode`, `IsWindowEnabled`, `IsWindow`, `IsRectEmpty`, `IsIconic`, `IsDialogMessageA`, `IsDialogMessageW`, `IsChild`, `InvalidateRect`, `IntersectRect`, `InsertMenuItemW`, `InsertMenuW`, `InflateRect`, `GetWindowThreadProcessId`, `GetWindowTextW`, `GetWindowRect`, `GetWindowPlacement`, `GetWindowLongW`, `GetWindowDC`, `GetTopWindow`, `GetSystemMetrics`, `GetSystemMenu`, `GetSysColorBrush`, `GetSysColor`, `GetSubMenu`, `GetScrollRange`, `GetScrollPos`, `GetScrollInfo`, `GetPropW`, `GetParent`, `GetWindow`, `GetMessagePos`, `GetMessageW`, `GetMenuStringW`, `GetMenuState`, `GetMenuItemInfoW`, `GetMenuItemID`, `GetMenuItemCount`, `GetMenu`, `GetLastActivePopup`, `GetKeyboardState`, `GetKeyboardLayoutNameW`, `GetKeyboardLayoutList`, `GetKeyboardLayout`, `GetKeyState`, `GetKeyNameTextW`, `GetIconInfo`, `GetForegroundWindow`, `GetFocus`, `GetDesktopWindow`, `GetDCEx`, `GetDC`, `GetCursorPos`, `GetCursor`, `GetClientRect`, `GetClassLongW`, `GetClassInfoW`, `GetCapture`, `GetActiveWindow`, `FrameRect`, `FindWindowExW`, `FindWindowW`, `FillRect`, `ExitWindowsEx`, `EnumWindows`, `EnumThreadWindows`, `EnumChildWindows`, `EndPaint`, `EnableWindow`, `EnableScrollBar`, `EnableMenuItem`, `DrawTextExW`, `DrawTextW`, `DrawMenuBar`, `DrawIconEx`, `DrawIcon`, `DrawFrameControl`, `DrawFocusRect`, `DrawEdge`, `DispatchMessageA`, `DispatchMessageW`, `DestroyWindow`, `DestroyMenu`, `DestroyIcon`, `DestroyCursor`, `DeleteMenu`, `DefWindowProcW`, `DefMDIChildProcW`, `DefFrameProcW`, `CreatePopupMenu`, `CreateMenu`, `CreateIcon`, `ClientToScreen`, `CheckMenuItem`, `CharUpperBuffW`, `CharToOemW`, `CharNextW`, `CharLowerBuffW`, `CharLowerW`, `CallWindowProcW`, `CallNextHookEx`, `BringWindowToTop`, `BeginPaint`, `AppendMenuW`, `CharToOemBuffA`, `AdjustWindowRectEx`, `ActivateKeyboardLayout`

### `msimg32.dll` (1 imports)

`AlphaBlend`

### `gdi32.dll` (71 imports)

`UnrealizeObject`, `StretchBlt`, `SetWindowOrgEx`, `SetViewportOrgEx`, `SetTextColor`, `SetStretchBltMode`, `SetROP2`, `SetPixel`, `SetDIBColorTable`, `SetBrushOrgEx`, `SetBkMode`, `SetBkColor`, `SelectPalette`, `SelectObject`, `SaveDC`, `RoundRect`, `RestoreDC`, `RemoveFontResourceW`, `Rectangle`, `RectVisible`, `RealizePalette`, `Polyline`, `Pie`, `PatBlt`, `MoveToEx`, `MaskBlt`, `LineTo`, `LineDDA`, `IntersectClipRect`, `GetWindowOrgEx`, `GetTextMetricsW`, `GetTextExtentPointW`, `GetTextExtentPoint32W`, `GetSystemPaletteEntries`, `GetStockObject`, `GetRgnBox`, `GetPixel`, `GetPaletteEntries`, `GetObjectW`, `GetDeviceCaps`, `GetDIBits`, `GetDIBColorTable`, `GetDCOrgEx`, `GetCurrentPositionEx`, `GetClipBox`, `GetBrushOrgEx`, `GetBitmapBits`, `FrameRgn`, `ExtTextOutW`, `ExtFloodFill`, `ExcludeClipRect`, `EnumFontsW`, `Ellipse`, `DeleteObject`, `DeleteDC`, `CreateSolidBrush`, `CreateRectRgn`, `CreatePenIndirect`, `CreatePalette`, `CreateHalftonePalette`, `CreateFontIndirectW`, `CreateDIBitmap`, `CreateDIBSection`, `CreateCompatibleDC`, `CreateCompatibleBitmap`, `CreateBrushIndirect`, `CreateBitmap`, `Chord`, `BitBlt`, `Arc`, `AddFontResourceW`

### `version.dll` (3 imports)

`VerQueryValueW`, `GetFileVersionInfoSizeW`, `GetFileVersionInfoW`

### `mpr.dll` (5 imports)

`WNetOpenEnumW`, `WNetGetUniversalNameW`, `WNetGetConnectionW`, `WNetEnumResourceW`, `WNetCloseEnum`

### `kernel32.dll` (121 imports)

`lstrcpyW`, `lstrcmpW`, `WriteProfileStringW`, `WritePrivateProfileStringW`, `WriteFile`, `WideCharToMultiByte`, `WaitForSingleObject`, `WaitForMultipleObjectsEx`, `VirtualQueryEx`, `VirtualQuery`, `VirtualFree`, `VirtualAlloc`, `TransactNamedPipe`, `TerminateProcess`, `SwitchToThread`, `SizeofResource`, `SignalObjectAndWait`, `SetThreadLocale`, `SetNamedPipeHandleState`, `SetLastError`, `SetFileTime`, `SetFilePointer`, `SetFileAttributesW`, `SetEvent`, `SetErrorMode`, `SetEndOfFile`, `SetCurrentDirectoryW`, `ResumeThread`, `ResetEvent`, `RemoveDirectoryW`, `ReleaseMutex`, `ReadFile`, `QueryPerformanceCounter`, `OpenProcess`, `OpenMutexW`, `MultiByteToWideChar`, `MulDiv`, `MoveFileExW`, `MoveFileW`, `LockResource`, `LocalFree`, `LocalFileTimeToFileTime`, `LoadResource`, `LoadLibraryExA`, `LoadLibraryA`, `LoadLibraryW`, `LeaveCriticalSection`, `IsDBCSLeadByte`, `IsBadWritePtr`, `InitializeCriticalSection`, `GlobalFindAtomW`, `GlobalDeleteAtom`, `GlobalAddAtomW`, `GetWindowsDirectoryW`, `GetVersionExW`, `GetVersion`, `GetUserDefaultLangID`, `GetTickCount`, `GetThreadLocale`, `GetSystemTimeAsFileTime`, `GetSystemInfo`, `GetSystemDirectoryW`, `GetStdHandle`, `GetShortPathNameW`, `GetProfileStringW`, `GetProcAddress`, `GetPrivateProfileStringW`, `GetOverlappedResult`, `GetModuleHandleW`, `GetModuleFileNameW`, `GetLogicalDrives`, `GetLocaleInfoW`, `GetLocalTime`, `GetLastError`, `GetFullPathNameW`, `GetFileSize`, `GetFileAttributesW`, `GetExitCodeThread`, `GetExitCodeProcess`, `GetEnvironmentVariableW`, `GetDriveTypeW`, `GetDiskFreeSpaceW`, `GetDateFormatW`, `GetCurrentThreadId`, `GetCurrentThread`, `GetCurrentProcessId`, `GetCurrentProcess`, `GetComputerNameW`, `GetCommandLineW`, `GetCPInfo`, `FreeResource`, `InterlockedIncrement`, `InterlockedExchangeAdd`, `InterlockedExchange`, `InterlockedDecrement`, `InterlockedCompareExchange`, `FreeLibrary`, `FormatMessageW`, `FlushFileBuffers`, `FindResourceW`, `FindNextFileW`, `FindFirstFileW`, `FindClose`, `FileTimeToSystemTime`, `FileTimeToLocalFileTime`, `EnumCalendarInfoA`, `EnterCriticalSection`, `DeviceIoControl`, `DeleteFileW`, `DeleteCriticalSection`, `CreateThread`, `CreateProcessW`, `CreateNamedPipeW`, `CreateMutexW`, `CreateFileW`, `CreateEventW`, `CreateDirectoryW`, `CopyFileW`, `CompareStringW`, `CompareFileTime`, `CloseHandle`

### `advapi32.dll` (19 imports)

`RegSetValueExW`, `RegQueryValueExW`, `RegQueryInfoKeyW`, `RegOpenKeyExW`, `RegFlushKey`, `RegEnumValueW`, `RegEnumKeyExW`, `RegDeleteValueW`, `RegDeleteKeyW`, `RegCreateKeyExW`, `RegCloseKey`, `OpenThreadToken`, `OpenProcessToken`, `LookupPrivilegeValueW`, `GetUserNameW`, `GetTokenInformation`, `FreeSid`, `EqualSid`, `AllocateAndInitializeSid`

### `oleaut32.dll` (5 imports)

`GetErrorInfo`, `GetActiveObject`, `RegisterTypeLib`, `LoadTypeLib`, `SysFreeString`

### `ole32.dll` (10 imports)

`OleUninitialize`, `OleInitialize`, `CoTaskMemFree`, `CLSIDFromProgID`, `StringFromCLSID`, `CoCreateInstance`, `CoFreeUnusedLibraries`, `CoUninitialize`, `CoInitialize`, `IsEqualGUID`

### `comctl32.dll` (29 imports)

`InitializeFlatSB`, `FlatSB_SetScrollProp`, `FlatSB_SetScrollPos`, `FlatSB_SetScrollInfo`, `FlatSB_GetScrollPos`, `FlatSB_GetScrollInfo`, `_TrackMouseEvent`, `ImageList_SetIconSize`, `ImageList_GetIconSize`, `ImageList_Write`, `ImageList_Read`, `ImageList_GetDragImage`, `ImageList_DragShowNolock`, `ImageList_DragMove`, `ImageList_DragLeave`, `ImageList_DragEnter`, `ImageList_EndDrag`, `ImageList_BeginDrag`, `ImageList_Remove`, `ImageList_DrawEx`, `ImageList_Draw`, `ImageList_GetBkColor`, `ImageList_SetBkColor`, `ImageList_Add`, `ImageList_SetImageCount`, `ImageList_GetImageCount`, `ImageList_Destroy`, `ImageList_Create`, `InitCommonControls`

### `kernel32.dll` (1 imports)

`Sleep`

### `oleaut32.dll` (11 imports)

`SafeArrayPtrOfIndex`, `SafeArrayPutElement`, `SafeArrayGetElement`, `SafeArrayGetUBound`, `SafeArrayGetLBound`, `SafeArrayCreate`, `VariantChangeType`, `VariantCopyInd`, `VariantCopy`, `VariantClear`, `VariantInit`

### `shell32.dll` (4 imports)

`ShellExecuteExW`, `ShellExecuteW`, `SHGetFileInfoW`, `ExtractIconW`

### `shell32.dll` (4 imports)

`SHGetPathFromIDListW`, `SHGetMalloc`, `SHChangeNotify`, `SHBrowseForFolderW`

### `comdlg32.dll` (2 imports)

`GetSaveFileNameW`, `GetOpenFileNameW`

### `ole32.dll` (1 imports)

`CoDisconnectObject`

### `advapi32.dll` (1 imports)

`AdjustTokenPrivileges`

### `oleaut32.dll` (1 imports)

`SysFreeString`

## Delay imports

`DeviceDriver.exe` has three delay-import entries from `OLEACC.dll`, in
addition to the 672 ordinary imports shown in the binary table. The delay
IAT entries and executable references are included in
[`rk-native-api-xrefs.csv`](rk-native-api-xrefs.csv). The wrapper stubs jump
through the delay IAT; callers reach those stubs through ordinary relative
`call` instructions.

| DLL | API | Delay IAT RVA | Delay thunk VA | Caller VAs | Other IAT reference VA |
| --- | --- | --- | --- | --- | --- |
| `OLEACC.dll` | `AccessibleObjectFromWindow` | `0x00203D20` | `0x00589379` | `0x005035CD` | `0x0058936F` |
| `OLEACC.dll` | `LresultFromObject` | `0x00203D24` | `0x00589389` | `0x00477DFB`, `0x00477E23` | `0x0058937F` |
| `OLEACC.dll` | `CreateStdAccessibleObject` | `0x00203D28` | `0x00589369` | `0x0047348A` | `0x0058934E` |

These are accessibility/UI APIs. Their imported presence and call references
do not establish which assistive-technology paths execute at runtime.
