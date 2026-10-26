param([string]$OutputDirectory = (Join-Path $PSScriptRoot "dist\smoke"))
$ErrorActionPreference = "Stop"
$exe = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "dist\RK-Rebuild.exe")).Path
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$report = Join-Path (Resolve-Path -LiteralPath $OutputDirectory).Path ("compatibility-" + [guid]::NewGuid().ToString("N") + ".json")
$uiReport = $report + ".ui.json"
$uiProcess = Start-Process -FilePath $exe -ArgumentList @("--ui-smoke-test", ('"' + $uiReport + '"')) -PassThru
try {
    if (-not $uiProcess.WaitForExit(30000)) { $uiProcess.Kill(); throw "Offline UI smoke exceeded its deadline." }
    if ($uiProcess.ExitCode -ne 0) { throw "Offline UI rendering failed." }
} finally { $uiProcess.Dispose() }
$ui = Get-Content -LiteralPath $uiReport -Raw | ConvertFrom-Json
if (-not $ui.Passed -or $ui.Pages.Count -ne 9 -or -not $ui.MissingVendorResources -or $ui.SettingsPersistence -or $ui.Network -or $ui.DeviceAccess) { throw "Offline UI smoke scope/rendering mismatch." }
Write-Host "PASS: all nine WPF pages rendered without vendor resources, settings persistence, network or device access."
function Export-Report {
    $process = Start-Process -FilePath $exe -ArgumentList @("--compatibility-report", ('"' + $report + '"')) -PassThru -Wait
    return $process.ExitCode
}
if ((Export-Report) -ne 0) { throw "Published EXE compatibility export failed." }
$data = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
if ($data.Format -ne "rk-rebuild-compatibility-catalog" -or $data.SchemaVersion -ne 1 -or $data.Entries.Count -ne 444) {
    throw "Published catalogue schema/count mismatch. Review this check deliberately when updating snapshots."
}
if (@($data.Entries | Where-Object { $_.HardwareWritesAllowed -or $_.Status -ne "CataloguedOnly" }).Count -ne 0) {
    throw "Catalogue must not claim hardware validation."
}
$original = (Get-FileHash -LiteralPath $report -Algorithm SHA256).Hash
if ((Export-Report) -eq 0 -or (Get-FileHash -LiteralPath $report -Algorithm SHA256).Hash -ne $original) {
    throw "Existing-file overwrite protection failed."
}
$missing = Start-Process -FilePath $exe -ArgumentList @("--compatibility-report") -PassThru -Wait
if ($missing.ExitCode -eq 0) { throw "Missing-argument check failed." }
$metadataPath = $report + ".hid.json"
$metadataProcess = Start-Process -FilePath $exe -ArgumentList @("--hid-diagnostics", ('"' + $metadataPath + '"')) -PassThru -Wait
if ($metadataProcess.ExitCode -ne 0) { throw "Published HID metadata export failed." }
$metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
if ($metadata.Format -ne "rk-rebuild-hid-metadata" -or $metadata.HardwareWritesAllowed) { throw "HID metadata schema mismatch." }
foreach ($endpoint in $metadata.Endpoints) {
    if ($endpoint.PSObject.Properties.Name -contains "DevicePath") { throw "Opaque device path leaked in metadata export." }
}
$invalidPath = $report + ".invalid-query.json"
$invalidQuery = Start-Process -FilePath $exe -ArgumentList @("--read-wireless-lighting", "not-an-identity", ('"' + $invalidPath + '"')) -PassThru -Wait
if ($invalidQuery.ExitCode -eq 0 -or (Test-Path -LiteralPath $invalidPath)) { throw "Invalid query identity was not rejected before I/O." }
$invalidG5Path = $report + ".invalid-g5.json"
$invalidG5 = Start-Process -FilePath $exe -ArgumentList @("--read-g5-lighting", "not-an-identity", ('"' + $invalidG5Path + '"')) -PassThru -Wait
if ($invalidG5.ExitCode -eq 0 -or (Test-Path -LiteralPath $invalidG5Path)) { throw "Invalid G5 query identity was not rejected before worker/native I/O." }
$worker = New-Object System.Diagnostics.Process
$worker.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
$worker.StartInfo.FileName = $exe
$worker.StartInfo.Arguments = "--internal-g5-lighting-query invalid"
$worker.StartInfo.UseShellExecute = $false
$worker.StartInfo.CreateNoWindow = $true
$worker.StartInfo.RedirectStandardOutput = $true
try {
    if (-not $worker.Start()) { throw "Cannot start published query worker." }
    $workerOutput = $worker.StandardOutput.ReadToEndAsync()
    if (-not $worker.WaitForExit(12000)) { $worker.Kill(); throw "Published query worker did not exit in its bounded interval." }
    $workerReport = $workerOutput.GetAwaiter().GetResult()
    if ($worker.ExitCode -eq 0 -or ($workerReport | ConvertFrom-Json).ErrorCode -ne "InvalidEndpointOrIdentity") { throw "Published worker did not fail closed before native I/O." }
} finally { $worker.Dispose() }
$unconfirmedPath = $report + ".unconfirmed-apply.json"
$unconfirmedApply = Start-Process -FilePath $exe -ArgumentList @("--apply-observed-wireless-mode", "258A:0150", "1", ('"' + $report + '"'), ('"' + $unconfirmedPath + '"')) -PassThru -Wait
if ($unconfirmedApply.ExitCode -eq 0 -or (Test-Path -LiteralPath $unconfirmedPath)) { throw "Unconfirmed lighting write was not rejected before I/O." }
$overwriteApply = Start-Process -FilePath $exe -ArgumentList @("--apply-observed-wireless-mode", "258A:0150", "1", ('"' + $report + '"'), ('"' + $report + '"'), "--confirm-experimental-write") -PassThru -Wait
if ($overwriteApply.ExitCode -eq 0 -or (Get-FileHash -LiteralPath $report -Algorithm SHA256).Hash -ne $original) { throw "Apply output overwrite guard failed." }
$failedApplyPath = $report + ".failed-apply.json"
$failedApply = Start-Process -FilePath $exe -ArgumentList @("--apply-observed-wireless-mode", "invalid", "1", ('"' + $report + '"'), ('"' + $failedApplyPath + '"'), "--confirm-experimental-write") -PassThru -Wait
if ($failedApply.ExitCode -eq 0) { throw "Invalid apply identity unexpectedly succeeded." }
$failureReport = Get-Content -LiteralPath $failedApplyPath -Raw | ConvertFrom-Json
if ($failureReport.Format -ne "rk-rebuild-experimental-lighting-apply-failure" -or $failureReport.VerifiedByQuery) { throw "Apply failure was not retained accurately." }
Write-Host "PASS: published EXE exported 444 catalogued-only entries; overwrite/missing-argument checks failed safely."
Write-Host "PASS: HID metadata export excludes device paths; invalid lighting query refused without report I/O."
Write-Host "PASS: unconfirmed apply and output overwrite refused before device access."
Write-Host "Report retained: $report"
