[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$MsiPath,
    [string]$SourceExe = (Join-Path $PSScriptRoot "..\dist\RK-Rebuild.exe"),
    [Parameter(Mandatory = $true)][string]$ExpectedVersion
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Installer([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "MSI validation failed: $Message" }
}

function Read-MsiTable([object]$Database, [string]$Table, [string[]]$Columns) {
    $quotedColumns = ($Columns | ForEach-Object { '`' + $_ + '`' }) -join ', '
    $view = $Database.OpenView('SELECT ' + $quotedColumns + ' FROM `' + $Table + '`')
    try {
        [void]$view.Execute()
        while ($null -ne ($record = $view.Fetch())) {
            try {
                $row = [ordered]@{}
                for ($i = 0; $i -lt $Columns.Count; $i++) { $row[$Columns[$i]] = $record.StringData($i + 1) }
                [pscustomobject]$row
            }
            finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
        }
    }
    finally {
        [void]$view.Close()
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    }
}

$MsiPath = (Resolve-Path -LiteralPath $MsiPath).Path
$SourceExe = (Resolve-Path -LiteralPath $SourceExe).Path
$licenseFile = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..\..\LICENSE")).Path
$installer = $null
$database = $null
$work = Join-Path $PSScriptRoot (".validation\" + [Guid]::NewGuid().ToString('N'))
try {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    # msiOpenDatabaseModeReadOnly = 0. No OpenPackage, InstallProduct or msiexec.
    $database = $installer.OpenDatabase($MsiPath, 0)
    $tables = @(Read-MsiTable $database '_Tables' @('Name') | ForEach-Object { $_.Name })
    $properties = @{}
    Read-MsiTable $database 'Property' @('Property', 'Value') | ForEach-Object { $properties[$_.Property] = $_.Value }
    Assert-Installer ($properties['ProductVersion'] -eq $ExpectedVersion) "ProductVersion mismatch"
    Assert-Installer ($properties['UpgradeCode'] -eq '{12D50DE5-7286-4B6E-99D9-B4F9FC1F7996}') "UpgradeCode changed"
    Assert-Installer (-not $properties.ContainsKey('ALLUSERS')) "ALLUSERS must be absent (per-user)"
    Assert-Installer (-not $properties.ContainsKey('ARPSYSTEMCOMPONENT')) "Uninstaller must remain visible"
    Assert-Installer (-not $properties.ContainsKey('ARPNOREMOVE')) "Uninstall must remain enabled"
    $summary = $database.SummaryInformation(0)
    try {
        Assert-Installer (([int]$summary.Property(15) -band 8) -eq 8) "Summary must mark this as a non-elevated package"
        Assert-Installer ($summary.Property(7) -match '^x64;') "Package must target x64"
    }
    finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary) }

    $directories = @{}
    Read-MsiTable $database 'Directory' @('Directory', 'Directory_Parent', 'DefaultDir') | ForEach-Object { $directories[$_.Directory] = $_ }
    Assert-Installer ($directories['INSTALLFOLDER'].Directory_Parent -eq 'UserProgramsFolder') "App directory parent"
    Assert-Installer ($directories['INSTALLFOLDER'].DefaultDir -match '(^|\|)RK Rebuild$') "App directory name"
    Assert-Installer ($directories['UserProgramsFolder'].Directory_Parent -eq 'LocalAppDataFolder') "Programs must be in LocalAppData"
    Assert-Installer ($directories['UserProgramsFolder'].DefaultDir -match '(^|\|)Programs$') "Programs directory name"
    Assert-Installer ($directories['ApplicationMenuFolder'].Directory_Parent -eq 'ProgramMenuFolder') "Menu must be per-user"
    Assert-Installer (-not $directories.ContainsKey('DesktopFolder')) "No desktop shortcut by default"
    Assert-Installer (-not $directories.ContainsKey('StartupFolder')) "No startup entry"

    $files = @(Read-MsiTable $database 'File' @('File', 'Component_', 'FileName', 'FileSize'))
    Assert-Installer ($files.Count -eq 2) "Payload must contain exactly EXE + project MIT license"
    Assert-Installer (@($files | Where-Object { $_.File -eq 'AppExecutable' -and $_.FileName -match '(^|\|)RK-Rebuild.exe$' -and $_.Component_ -eq 'ApplicationFiles' -and [long]$_.FileSize -eq (Get-Item -LiteralPath $SourceExe).Length }).Count -eq 1) "EXE allowlist/size"
    Assert-Installer (@($files | Where-Object { $_.File -eq 'ProjectLicense' -and $_.FileName -match '(^|\|)LICENSE.txt$' -and $_.Component_ -eq 'ApplicationFiles' }).Count -eq 1) "MIT license allowlist"
    $shortcuts = @(Read-MsiTable $database 'Shortcut' @('Shortcut', 'Directory_', 'Target', 'Arguments', 'WkDir'))
    Assert-Installer ($shortcuts.Count -eq 1) "Exactly one Start Menu shortcut"
    Assert-Installer ($shortcuts[0].Directory_ -eq 'ApplicationMenuFolder' -and $shortcuts[0].Target -eq '[INSTALLFOLDER]RK-Rebuild.exe' -and $shortcuts[0].Arguments -eq '' -and $shortcuts[0].WkDir -eq 'INSTALLFOLDER') "Non-advertised shortcut, no hardware/launch arguments"
    $registry = @(Read-MsiTable $database 'Registry' @('Registry', 'Root', 'Key', 'Name', 'Component_'))
    Assert-Installer ($registry.Count -eq 2) "Exactly two HKCU component key paths"
    foreach ($row in $registry) {
        Assert-Installer ($row.Root -eq '1' -and $row.Key -eq 'Software\RK Rebuild\Installer') "Only own HKCU registry key allowed"
    }
    $components = @(Read-MsiTable $database 'Component' @('Component', 'Directory_', 'Attributes', 'KeyPath'))
    Assert-Installer ($components.Count -eq 2) "Unexpected component"
    foreach ($row in $components) {
        Assert-Installer (([int]$row.Attributes -band 4) -eq 4 -and $row.KeyPath -in $registry.Registry) "Per-user component needs HKCU registry key path"
        Assert-Installer ($row.Directory_ -in @('INSTALLFOLDER', 'ApplicationMenuFolder')) "Component outside per-user folders"
    }
    foreach ($table in @('CustomAction', 'ServiceInstall', 'ServiceControl', 'Environment', 'SelfReg', 'Binary', 'Icon')) {
        Assert-Installer ($table -notin $tables) "Unexpected $table table (no custom actions/services/vendor art)"
    }
    $launch = @(Read-MsiTable $database 'LaunchCondition' @('Condition', 'Description'))
    Assert-Installer ('NOT ALLUSERS' -in $launch.Condition) "Explicit per-machine override must be blocked"
    $upgrades = @(Read-MsiTable $database 'Upgrade' @('UpgradeCode', 'VersionMin', 'VersionMax', 'Attributes', 'ActionProperty'))
    Assert-Installer ($upgrades.Count -eq 2) "Expected older-version upgrade and newer-version detection"
    $older = @($upgrades | Where-Object { $_.ActionProperty -eq 'WIX_UPGRADE_DETECTED' })
    $newer = @($upgrades | Where-Object { $_.ActionProperty -eq 'WIX_DOWNGRADE_DETECTED' })
    Assert-Installer ($older.Count -eq 1 -and $older[0].VersionMax -eq $ExpectedVersion -and ([int]$older[0].Attributes -band 512) -eq 0) "Only strictly older versions may be upgraded"
    Assert-Installer ($newer.Count -eq 1 -and $newer[0].VersionMin -eq $ExpectedVersion -and ([int]$newer[0].Attributes -band 2) -eq 2) "Newer-version detect-only rule"
    Assert-Installer (@($launch | Where-Object { $_.Condition -match 'WIX_DOWNGRADE_DETECTED' }).Count -gt 0) "Downgrade block condition"
    $sequence = @{}
    Read-MsiTable $database 'InstallExecuteSequence' @('Action', 'Sequence') | ForEach-Object { $sequence[$_.Action] = [int]$_.Sequence }
    Assert-Installer ($sequence.ContainsKey('RegisterProduct') -and $sequence.ContainsKey('PublishProduct')) "Standard uninstaller registration required"
    Assert-Installer ($sequence['RemoveExistingProducts'] -gt $sequence['InstallInitialize'] -and $sequence['RemoveExistingProducts'] -lt $sequence['InstallFiles']) "Upgrade removal must be rollback protected"

    # Export only the embedded cabinet as bytes; expand.exe extracts data, not an
    # administrative install. Never execute MSI sequences or the EXE.
    $media = @(Read-MsiTable $database 'Media' @('Cabinet'))
    Assert-Installer ($media.Count -eq 1 -and $media[0].Cabinet.StartsWith('#')) "One embedded cabinet required"
    $cabinetName = $media[0].Cabinet.Substring(1).Replace("'", "''")
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $cabinetPath = Join-Path $work 'payload.cab'
    $view = $database.OpenView("SELECT ``Data`` FROM ``_Streams`` WHERE ``Name`` = '$cabinetName'")
    try {
        [void]$view.Execute()
        $record = $view.Fetch()
        Assert-Installer ($null -ne $record) "Embedded cabinet stream missing"
        try {
            $stream = [IO.File]::Create($cabinetPath)
            try {
                do {
                    [string]$chunk = $record.ReadStream(1, 65536, 1)
                    if ($chunk.Length -gt 0) {
                        $bytes = [Text.Encoding]::GetEncoding(28591).GetBytes($chunk)
                        $stream.Write($bytes, 0, $bytes.Length)
                    }
                } while ($chunk.Length -gt 0)
            }
            finally { $stream.Dispose() }
        }
        finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
    }
    finally { [void]$view.Close(); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) }
    $extract = Join-Path $work 'extracted'
    New-Item -ItemType Directory -Path $extract | Out-Null
    & (Join-Path $env:SystemRoot 'System32\expand.exe') '-F:*' $cabinetPath $extract | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Cabinet extraction failed: $LASTEXITCODE" }
    $extractedFiles = @(Get-ChildItem -LiteralPath $extract -File -Recurse)
    Assert-Installer ($extractedFiles.Count -eq 2) "Cabinet payload count"
    foreach ($pair in @(@('AppExecutable', $SourceExe), @('ProjectLicense', $licenseFile))) {
        $payload = Join-Path $extract $pair[0]
        Assert-Installer (Test-Path -LiteralPath $payload -PathType Leaf) "Cabinet file $($pair[0]) missing"
        $expectedHash = (Get-FileHash -LiteralPath $pair[1] -Algorithm SHA256).Hash
        Assert-Installer ((Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash -eq $expectedHash) "Embedded $($pair[0]) SHA-256 differs from source"
    }
    Write-Host "PASS: read-only MSI tables, per-user/no-admin scope, registration, upgrade rules, shortcut and exact payload SHA-256."
}
finally {
    if ($null -ne $database) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) }
    if ($null -ne $installer) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) }
    # Only this invocation's newly generated, installer-local scratch directory.
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
