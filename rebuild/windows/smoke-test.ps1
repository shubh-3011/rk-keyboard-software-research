param([string]$OutputDirectory = (Join-Path $PSScriptRoot "dist\smoke"))
$ErrorActionPreference = "Stop"
$exe = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "dist\RK-Rebuild.exe")).Path
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$report = Join-Path (Resolve-Path -LiteralPath $OutputDirectory).Path ("compatibility-" + [guid]::NewGuid().ToString("N") + ".json")
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
Write-Host "PASS: published EXE exported 444 catalogued-only entries; overwrite/missing-argument checks failed safely."
Write-Host "PASS: HID metadata export excludes device paths; invalid lighting query refused without report I/O."
Write-Host "Report retained: $report"
