param([Parameter(Mandatory=$true)][int]$TargetPid, [Parameter(Mandatory=$true)][long]$WindowHandle,
      [Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference = "Stop"
if (Test-Path -LiteralPath $OutputPath) { throw "Output already exists." }
$target = Get-CimInstance Win32_Process -Filter "ProcessId=$TargetPid"
if (-not $target -or $target.ExecutablePath -ne 'C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe' -or
    (Get-FileHash -LiteralPath $target.ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6') { throw "Target identity mismatch." }
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class RkWindowOnlyCapture { [StructLayout(LayoutKind.Sequential)] public struct Rect { public int L,T,R,B; } [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h,IntPtr dc,uint flags); [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid); [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out Rect rect); }'
$handle = [IntPtr]$WindowHandle
$owner = [uint32]0
[void][RkWindowOnlyCapture]::GetWindowThreadProcessId($handle,[ref]$owner)
if ($owner -ne $TargetPid) { throw "Window does not belong to the selected process." }
$rect = New-Object RkWindowOnlyCapture+Rect
if (-not [RkWindowOnlyCapture]::GetWindowRect($handle,[ref]$rect)) { throw "Window bounds unavailable." }
$width = $rect.R-$rect.L; $height = $rect.B-$rect.T
if ($width -lt 1 -or $height -lt 1 -or $width -gt 4096 -or $height -gt 4096) { throw "Window bounds exceed capture limits." }
$bitmap = New-Object System.Drawing.Bitmap($width,$height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
try {
    $dc = $graphics.GetHdc()
    try { $ok = [RkWindowOnlyCapture]::PrintWindow($handle,$dc,2) } finally { $graphics.ReleaseHdc($dc) }
    if (-not $ok) { throw "Target-only PrintWindow failed; never fall back to desktop capture." }
    $bitmap.Save([IO.Path]::GetFullPath($OutputPath),[System.Drawing.Imaging.ImageFormat]::Png)
} finally { $graphics.Dispose(); $bitmap.Dispose() }
Write-Host "Captured only the selected RK window. Vendor artwork remains proprietary; keep images local."
