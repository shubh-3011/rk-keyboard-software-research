[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CurrentMsiPath,
    [Parameter(Mandatory = $true)][string]$PreviousMsiPath,
    [Parameter(Mandatory = $true)][string]$SourceExe,
    [switch]$ConfirmDisposableVm
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-DisposableRunner {
    if (-not $ConfirmDisposableVm -or $env:GITHUB_ACTIONS -cne 'true' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows') {
        throw 'REFUSED: requires -ConfirmDisposableVm on a disposable GitHub-hosted Windows runner; never run on a user VM or self-hosted runner.'
    }
}

# This must precede even input resolution, COM activation, registry reads and scratch creation.
Assert-DisposableRunner

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'REFUSED: lifecycle installation must run as a standard user, not the elevated hosted-runner administrator. Use test-installer-standard-user.ps1.'
}

function Assert-Lifecycle([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "Installer lifecycle validation failed: $Message" }
}

function Get-LifecycleFolder([Environment+SpecialFolder]$Folder) {
    # A fresh standard-user profile need not have a Desktop/Startup directory
    # yet. Resolve the configured path without creating it or requiring it to exist.
    # In a credential-launched PowerShell, .NET can retain the original runner's
    # LocalApplicationData path even after profile/environment correction. The
    # wrapper resolves LOCALAPPDATA from this token's actual user registration.
    $path = if ($Folder -eq [Environment+SpecialFolder]::LocalApplicationData) {
        $env:LOCALAPPDATA
    } else {
        [Environment]::GetFolderPath($Folder, [Environment+SpecialFolderOption]::DoNotVerify)
    }
    Assert-Lifecycle (-not [string]::IsNullOrWhiteSpace($path)) "Known folder has no configured path: $Folder"
    return $path
}

function Assert-ProductCode([string]$Code) {
    Assert-Lifecycle ($Code -cmatch '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') 'ProductCode must be a braced GUID, not an msiexec argument fragment'
}

function Read-Table($Database, [string]$Table, [string[]]$Columns) {
    $names = ($Columns | ForEach-Object { '`' + $_ + '`' }) -join ', '
    $view = $Database.OpenView('SELECT ' + $names + ' FROM `' + $Table + '`')
    try {
        [void]$view.Execute()
        while ($null -ne ($record = $view.Fetch())) {
            try {
                $row = @{}
                for ($i = 0; $i -lt $Columns.Count; $i++) { $row[$Columns[$i]] = $record.StringData($i + 1) }
                [pscustomobject]$row
            }
            finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
        }
    }
    finally { [void]$view.Close(); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) }
}

function Read-Package([string]$Path) {
    # msiOpenDatabaseModeReadOnly = 0; never use OpenPackage/InstallProduct here.
    $database = $installer.OpenDatabase($Path, 0)
    try {
        $properties = @{}
        Read-Table $database 'Property' @('Property', 'Value') | ForEach-Object { $properties[$_.Property] = $_.Value }
        foreach ($name in @('ProductCode', 'ProductVersion', 'UpgradeCode')) {
            Assert-Lifecycle ($properties.ContainsKey($name)) "Missing package property $name"
        }
        Assert-ProductCode $properties.ProductCode
        Assert-Lifecycle ($properties.ProductVersion -match '^\d+\.\d+\.\d+$') 'Three-part MSI version required'
        Assert-Lifecycle ($properties.UpgradeCode -eq '{12D50DE5-7286-4B6E-99D9-B4F9FC1F7996}') 'Foreign UpgradeCode'
        Assert-Lifecycle (-not $properties.ContainsKey('ALLUSERS')) 'Must be per-user'
        $summary = $database.SummaryInformation(0)
        try { Assert-Lifecycle (([int]$summary.Property(15) -band 8) -eq 8) 'Non-elevated MSI required' }
        finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary) }
        $tables = @(Read-Table $database '_Tables' @('Name') | ForEach-Object { $_.Name })
        foreach ($name in @('CustomAction', 'ServiceInstall', 'ServiceControl', 'Environment', 'SelfReg', 'Binary')) {
            Assert-Lifecycle ($name -notin $tables) "Unexpected MSI table $name"
        }
        $dirs = @{}
        Read-Table $database 'Directory' @('Directory', 'Directory_Parent', 'DefaultDir') | ForEach-Object { $dirs[$_.Directory] = $_ }
        Assert-Lifecycle ($dirs.INSTALLFOLDER.Directory_Parent -eq 'UserProgramsFolder' -and $dirs.INSTALLFOLDER.DefaultDir -match '(^|\|)RK Rebuild$') 'Unexpected target folder'
        Assert-Lifecycle ($dirs.UserProgramsFolder.Directory_Parent -eq 'LocalAppDataFolder' -and $dirs.UserProgramsFolder.DefaultDir -match '(^|\|)Programs$') 'Unexpected Programs folder'
        Assert-Lifecycle ($dirs.ApplicationMenuFolder.Directory_Parent -eq 'ProgramMenuFolder') 'Shortcut must be current-user only'
        return [pscustomobject]@{ Path = $Path; ProductCode = $properties.ProductCode; Version = [version]$properties.ProductVersion }
    }
    finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) }
}

function Get-UninstallEntries {
    foreach ($hive in @([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryHive]::LocalMachine)) {
        foreach ($view in @([Microsoft.Win32.RegistryView]::Registry32, [Microsoft.Win32.RegistryView]::Registry64)) {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
            try {
                $root = $base.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Uninstall', $false)
                if ($null -eq $root) { continue }
                try {
                    foreach ($name in $root.GetSubKeyNames()) {
                        $key = $root.OpenSubKey($name, $false)
                        if ($null -eq $key) { continue }
                        try {
                            $display = [string]$key.GetValue('DisplayName', '')
                            if ($name -in @($current.ProductCode, $previous.ProductCode) -or $display -match '^RK Rebuild(?:\b|\s|\()') {
                                $values = [ordered]@{}
                                foreach ($value in ($key.GetValueNames() | Sort-Object)) { $values[$value] = $key.GetValue($value) }
                                [pscustomobject]@{ Hive = $hive.ToString(); View = $view.ToString(); Code = $name; Values = $values }
                            }
                        }
                        finally { $key.Dispose() }
                    }
                }
                finally { $root.Dispose() }
            }
            finally { $base.Dispose() }
        }
    }
}

function Get-ProductContexts([string]$Code) {
    Assert-ProductCode $Code
    if (-not ('RkMsiContextEvidence' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
using System.Text;
public static class RkMsiContextEvidence {
    [DllImport("msi.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
    public static extern uint MsiEnumProductsExW(string product, string userSid,
        uint contexts, uint index, StringBuilder installedProduct,
        out uint installedContext, StringBuilder installedSid, ref uint sidCharacters);
}
'@
    }
    # Query only this package's GUID, for the current user and machine. Do not
    # use WMI product inventory or enumerate unrelated products/other users.
    for ([uint32]$index = 0; $index -lt 4; $index++) {
        $product = [Text.StringBuilder]::new(39)
        $sid = [Text.StringBuilder]::new(256)
        [uint32]$sidCharacters = 256
        [uint32]$context = 0
        $result = [RkMsiContextEvidence]::MsiEnumProductsExW($Code, $null, 7, $index, $product, [ref]$context, $sid, [ref]$sidCharacters)
        if ($result -eq 259) { return } # ERROR_NO_MORE_ITEMS
        Assert-Lifecycle ($result -eq 0 -and $sidCharacters -lt 256) "Cannot read bounded MSI context evidence for $Code (status $result)"
        [pscustomobject]@{ Code = $product.ToString(); Context = $context; UserSid = $sid.ToString() }
    }
    throw 'MSI context enumeration exceeded its current-user/machine bound.'
}

function Assert-RegisteredPerUser($Package) {
    $contexts = @(Get-ProductContexts $Package.ProductCode)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    # MSIINSTALLCONTEXT_USERUNMANAGED=2, MACHINE=4. The ARP registry hive
    # alone does not establish install context, even for a standard-user install.
    Assert-Lifecycle ($contexts.Count -eq 1 -and $contexts[0].Code -eq $Package.ProductCode -and $contexts[0].Context -eq 2 -and $contexts[0].UserSid -eq $sid) 'Product must be registered only in this standard user unmanaged MSI context'
    Assert-Lifecycle ([string]$installer.ProductInfo($Package.ProductCode, 'AssignmentType') -eq '0') 'MSI assignment must remain per-user'
    Assert-Lifecycle ([string]$installer.ProductInfo($Package.ProductCode, 'VersionString') -eq $Package.Version.ToString()) 'Registered MSI version mismatch'
    $entries = @(Get-UninstallEntries | Where-Object { $_.Code -eq $Package.ProductCode })
    Assert-Lifecycle ($entries.Count -gt 0) 'Visible uninstall registration missing'
    foreach ($entry in $entries) {
        Assert-Lifecycle ($entry.Values.DisplayVersion -eq $Package.Version.ToString() -and $entry.Values.WindowsInstaller -eq 1) 'Uninstall registration version/provider mismatch'
    }
}

function Assert-NoAutoLaunch {
    Assert-Lifecycle (@(Get-Process -Name 'RK-Rebuild' -ErrorAction SilentlyContinue).Count -eq 0) 'Application process exists (installer must not auto-launch)'
    $run = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run', $false)
    if ($null -ne $run) {
        try { Assert-Lifecycle ('RK Rebuild' -notin $run.GetValueNames()) 'Unexpected RK Rebuild startup entry' }
        finally { $run.Dispose() }
    }
}

function Assert-CurrentState {
    Assert-Lifecycle ((Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash -eq $exeHash) 'Installed EXE hash differs from current source'
    Assert-Lifecycle ((Get-FileHash -LiteralPath $installedLicense -Algorithm SHA256).Hash -eq $licenseHash) 'Installed LICENSE hash differs from project license'
    $entries = @(Get-UninstallEntries)
    Assert-RegisteredPerUser $current
    Assert-Lifecycle (@($entries | Where-Object { $_.Code -eq $previous.ProductCode }).Count -eq 0) 'Previous registration survived upgrade'
    Assert-Lifecycle (@(Get-ProductContexts $previous.ProductCode).Count -eq 0) 'Previous MSI context survived upgrade'
    Assert-Lifecycle (Test-Path -LiteralPath $shortcut -PathType Leaf) 'Current-user shortcut missing'
    $shell = New-Object -ComObject WScript.Shell
    $link = $null
    try {
        $link = $shell.CreateShortcut($shortcut)
        Assert-Lifecycle ($link.TargetPath -eq $installedExe -and $link.WorkingDirectory -eq $target -and [string]::IsNullOrEmpty($link.Arguments)) 'Shortcut target/working directory/arguments incorrect'
    }
    finally {
        if ($null -ne $link) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($link) }
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
    }
    foreach ($path in $forbiddenShortcuts) { Assert-Lifecycle (-not (Test-Path -LiteralPath $path)) "Unexpected shortcut: $path" }
    Assert-NoAutoLaunch
}

$script:MsiUncertain = $false
function Invoke-Msi([string]$Operation, [string]$Operand, [string]$Label, [switch]$ExpectFailure) {
    Assert-DisposableRunner
    Assert-Lifecycle (-not $script:MsiUncertain) 'An MSI transaction may still be active; refusing concurrent cleanup/installation'
    Assert-Lifecycle ($Operation -in @('/i', '/fa', '/x')) 'Unsupported MSI operation'
    if ($Operation -eq '/x') { Assert-ProductCode $Operand }
    else { Assert-Lifecycle ($Operand -in @($current.Path, $previous.Path)) 'Unowned package argument' }
    $log = Join-Path $work ($Label + '.msi.log')
    $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList "$Operation `"$Operand`" /qn /norestart /L*v `"$log`"" -PassThru
    try {
        if (-not $process.WaitForExit(120000)) {
            $script:MsiUncertain = $true
            # Only our client, never the MSI service. Its transaction may continue.
            try { $process.Kill() } catch { Write-Warning "Could not terminate own MSI client: $_" }
            throw "MSI $Label exceeded 120 seconds. Service transaction may continue; no cleanup MSI will be launched. Logs: $work"
        }
        $code = $process.ExitCode
        if ($code -eq 1618) { $script:MsiUncertain = $true; throw 'Another MSI transaction is active; refusing further MSI operations.' }
        if ($ExpectFailure) { Assert-Lifecycle ($code -ne 0 -and $code -ne 3010 -and $code -ne 1641) 'Downgrade unexpectedly succeeded' }
        else { Assert-Lifecycle ($code -eq 0) "MSI $Label exit code $code (see $log)" }
        Write-Host "MSI ${Label}: exit $code; log $log"
    }
    finally { $process.Dispose() }
}

$installer = $null
$attemptedProducts = [Collections.Generic.List[string]]::new()
$completed = $false
try {
    $CurrentMsiPath = (Resolve-Path -LiteralPath $CurrentMsiPath).Path
    $PreviousMsiPath = (Resolve-Path -LiteralPath $PreviousMsiPath).Path
    $SourceExe = (Resolve-Path -LiteralPath $SourceExe).Path
    foreach ($path in @($CurrentMsiPath, $PreviousMsiPath, $SourceExe)) {
        Assert-Lifecycle ((Test-Path -LiteralPath $path -PathType Leaf) -and -not $path.Contains('"')) 'Input must be an existing file with no argument quoting characters'
    }
    Assert-Lifecycle ([IO.Path]::GetExtension($CurrentMsiPath) -eq '.msi' -and [IO.Path]::GetExtension($PreviousMsiPath) -eq '.msi') 'MSI inputs required'
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $current = Read-Package $CurrentMsiPath
    $previous = Read-Package $PreviousMsiPath
    Assert-Lifecycle ($current.ProductCode -ne $previous.ProductCode -and $previous.Version -lt $current.Version) 'Requires distinct ProductCodes and a strictly older previous package'
    $metadata = [Diagnostics.FileVersionInfo]::GetVersionInfo($SourceExe)
    Assert-Lifecycle ($metadata.FileMajorPart -eq $current.Version.Major -and $metadata.FileMinorPart -eq $current.Version.Minor -and $metadata.FileBuildPart -eq $current.Version.Build) 'Current source EXE version mismatch'
    $exeHash = (Get-FileHash -LiteralPath $SourceExe -Algorithm SHA256).Hash
    $licenseHash = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot '..\..\..\LICENSE') -Algorithm SHA256).Hash
    $target = Join-Path (Get-LifecycleFolder 'LocalApplicationData') 'Programs\RK Rebuild'
    $installedExe = Join-Path $target 'RK-Rebuild.exe'
    $installedLicense = Join-Path $target 'LICENSE.txt'
    $menu = Join-Path (Get-LifecycleFolder 'Programs') 'RK Rebuild'
    $shortcut = Join-Path $menu 'RK Rebuild.lnk'
    $forbiddenShortcuts = @(
        (Join-Path (Get-LifecycleFolder 'CommonPrograms') 'RK Rebuild'),
        (Join-Path (Get-LifecycleFolder 'DesktopDirectory') 'RK Rebuild.lnk'),
        (Join-Path (Get-LifecycleFolder 'CommonDesktopDirectory') 'RK Rebuild.lnk'),
        (Join-Path (Get-LifecycleFolder 'Startup') 'RK Rebuild.lnk'),
        (Join-Path (Get-LifecycleFolder 'CommonStartup') 'RK Rebuild.lnk')
    )
    foreach ($path in (@($target, $menu) + $forbiddenShortcuts)) {
        Assert-Lifecycle (-not (Test-Path -LiteralPath $path)) "Pre-existing path; refusing to overwrite: $path"
    }
    Assert-Lifecycle (@(Get-UninstallEntries).Count -eq 0) 'Pre-existing product registration; refusing to proceed'
    Assert-Lifecycle (@(Get-ProductContexts $current.ProductCode).Count -eq 0 -and @(Get-ProductContexts $previous.ProductCode).Count -eq 0) 'Pre-existing MSI context; refusing to proceed'
    $marker = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\RK Rebuild\Installer', $false)
    if ($null -ne $marker) { $marker.Dispose(); throw 'Pre-existing installer component key; refusing to proceed' }
    Assert-Lifecycle (@($installer.RelatedProducts('{12D50DE5-7286-4B6E-99D9-B4F9FC1F7996}')).Count -eq 0) 'Pre-existing related MSI product'
    Assert-NoAutoLaunch
    Assert-Lifecycle (-not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) 'RUNNER_TEMP required'
    $tempRoot = (Resolve-Path -LiteralPath $env:RUNNER_TEMP).Path
    $work = Join-Path $tempRoot ('rk-installer-lifecycle-' + [Guid]::NewGuid().ToString('N'))
    Assert-Lifecycle (-not (Test-Path -LiteralPath $work)) 'Scratch path must be new'
    New-Item -ItemType Directory -Path $work | Out-Null
    Write-Host "Lifecycle logs and smoke artifacts: $work"
    [ordered]@{ Target = $target; Exe = $installedExe; License = $installedLicense; Menu = $menu; UserProfile = $env:USERPROFILE; LocalAppData = $env:LOCALAPPDATA } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $work 'expected-install-paths.json') -Encoding utf8

    $attemptedProducts.Add($previous.ProductCode)
    Invoke-Msi '/i' $previous.Path '01-install-previous'
    Assert-Lifecycle ((Test-Path -LiteralPath $installedExe -PathType Leaf) -and (Test-Path -LiteralPath $installedLicense -PathType Leaf)) "Previous payload missing at expected paths: $installedExe; $installedLicense"
    $oldMetadata = [Diagnostics.FileVersionInfo]::GetVersionInfo($installedExe)
    Assert-Lifecycle ($oldMetadata.FileMajorPart -eq $previous.Version.Major -and $oldMetadata.FileMinorPart -eq $previous.Version.Minor -and $oldMetadata.FileBuildPart -eq $previous.Version.Build) 'Previous installed EXE must really be the older version'
    Assert-Lifecycle ((Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash -ne $exeHash) 'Previous payload must not be a relabelled current EXE'
    $previousEntries = @(Get-UninstallEntries)
    $previousEntries | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $work 'previous-uninstall-registration.json') -Encoding utf8
    $registrationDiagnostics = [ordered]@{ ExpectedCode = $previous.ProductCode; ExpectedVersion = $previous.Version.ToString(); Entries = $previousEntries }
    foreach ($property in @('ProductName', 'VersionString', 'AssignmentType')) {
        try { $registrationDiagnostics[$property] = $installer.ProductInfo($previous.ProductCode, $property) }
        catch { $registrationDiagnostics[$property] = 'Unavailable' }
    }
    $registrationDiagnostics | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $work 'previous-msi-registration-diagnostics.json') -Encoding utf8
    @(Get-ProductContexts $previous.ProductCode) | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $work 'previous-msi-context.json') -Encoding utf8
    Assert-RegisteredPerUser $previous
    Assert-NoAutoLaunch
    $attemptedProducts.Add($current.ProductCode)
    Invoke-Msi '/i' $current.Path '02-upgrade-current'
    Assert-CurrentState
    $registrationBefore = @(Get-UninstallEntries) | ConvertTo-Json -Depth 10 -Compress
    $shortcutHash = (Get-FileHash -LiteralPath $shortcut -Algorithm SHA256).Hash
    Invoke-Msi '/i' $previous.Path '03-reject-downgrade' -ExpectFailure
    Assert-CurrentState
    Assert-Lifecycle ((@(Get-UninstallEntries) | ConvertTo-Json -Depth 10 -Compress) -ceq $registrationBefore) 'Downgrade changed uninstall registration'
    Assert-Lifecycle ((Get-FileHash -LiteralPath $shortcut -Algorithm SHA256).Hash -eq $shortcutHash) 'Downgrade changed shortcut'

    # Delete exactly the verified, owned EXE only; never directories or user data.
    Assert-DisposableRunner
    Assert-CurrentState
    Assert-Lifecycle ($installedExe -eq (Join-Path $target 'RK-Rebuild.exe') -and (Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash -eq $exeHash) 'Repair deletion ownership/hash guard'
    Remove-Item -LiteralPath $installedExe
    Invoke-Msi '/fa' $current.Path '04-repair-current'
    Assert-CurrentState

    # Offline catalogue and guarded UI rendering: no HID discovery/report commands. Shadow
    # writable app/runtime locations into this invocation's new runner temp tree.
    $smoke = Join-Path $work 'smoke'
    New-Item -ItemType Directory -Path $smoke | Out-Null
    $reportPath = Join-Path $smoke 'compatibility-report.json'
    Assert-Lifecycle (-not (Test-Path -LiteralPath $reportPath)) 'Smoke output must be new'
    $saved = @{}
    try {
        foreach ($name in @('APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'DOTNET_BUNDLE_EXTRACT_BASE_DIR')) {
            $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
            $shadow = Join-Path $smoke $name
            New-Item -ItemType Directory -Path $shadow | Out-Null
            [Environment]::SetEnvironmentVariable($name, $shadow, 'Process')
        }
        $app = Start-Process -FilePath $installedExe -ArgumentList "--compatibility-report `"$reportPath`"" -WorkingDirectory $smoke -RedirectStandardOutput (Join-Path $smoke 'stdout.txt') -RedirectStandardError (Join-Path $smoke 'stderr.txt') -PassThru
        try {
            if (-not $app.WaitForExit(120000)) {
                try { $app.Kill() } catch { Write-Warning "Could not terminate own smoke process: $_" }
                throw 'Installed compatibility smoke exceeded 120 seconds'
            }
            Assert-Lifecycle ($app.ExitCode -eq 0) 'Installed compatibility-report failed'
        }
        finally { $app.Dispose() }
        $uiReportPath = Join-Path $smoke 'installed-offline-ui.json'
        Assert-Lifecycle (-not (Test-Path -LiteralPath $uiReportPath)) 'UI smoke output must be new'
        $uiApp = Start-Process -FilePath $installedExe -ArgumentList "--ui-smoke-test `"$uiReportPath`"" -WorkingDirectory $smoke -RedirectStandardOutput (Join-Path $smoke 'ui-stdout.txt') -RedirectStandardError (Join-Path $smoke 'ui-stderr.txt') -PassThru
        try {
            if (-not $uiApp.WaitForExit(30000)) {
                try { $uiApp.Kill() } catch { Write-Warning 'Could not terminate own offline UI smoke process.' }
                throw 'Installed offline UI smoke exceeded 30 seconds'
            }
            Assert-Lifecycle ($uiApp.ExitCode -eq 0) 'Installed offline UI rendering failed'
        }
        finally { $uiApp.Dispose() }
    }
    finally { foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') } }
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    Assert-Lifecycle ($report.Format -eq 'rk-rebuild-compatibility-catalog' -and $report.SchemaVersion -eq 1) 'Unexpected compatibility report format'
    Assert-Lifecycle (@($report.Entries).Count -eq 444 -and @($report.Entries | Where-Object { $_.Status -cne 'CataloguedOnly' }).Count -eq 0) 'Expected exactly 444 CataloguedOnly entries'
    $uiReport = Get-Content -LiteralPath $uiReportPath -Raw | ConvertFrom-Json
    Assert-Lifecycle ($uiReport.Format -eq 'rk-rebuild-offline-ui-smoke' -and $uiReport.SchemaVersion -eq 1 -and $uiReport.Passed -and $uiReport.Guards.Passed) 'Installed UI smoke schema/guard result'
    Assert-Lifecycle ($uiReport.MissingVendorResources -and -not $uiReport.DeviceAccess -and -not $uiReport.Network -and -not $uiReport.SettingsPersistence -and -not $uiReport.StartupRegistryAccess -and -not $uiReport.TrayCreated) 'Installed UI smoke must remain offline without persistence or hardware'
    $expectedPages = @('Compatibility', 'Device', 'Key mapping', 'Lighting', 'Macros', 'RK Drive editor', 'Models', 'RK Drive directory', 'Preferences')
    Assert-Lifecycle (@($uiReport.Pages).Count -eq 9 -and (@($uiReport.Pages | ForEach-Object { $_.Page }) -join '|') -ceq ($expectedPages -join '|')) 'All nine installed UI pages must render in order'
    foreach ($page in $uiReport.Pages) {
        Assert-Lifecycle ($page.Passed -and $page.PageChildCount -gt 0 -and $page.DistinctPixelColors -gt 16 -and $page.PixelSha256 -match '^[0-9A-Fa-f]{64}$') "Installed UI page rendering failed: $($page.Page)"
    }
    Assert-CurrentState

    Invoke-Msi '/x' $current.ProductCode '05-uninstall-current'
    foreach ($path in @($installedExe, $installedLicense, $shortcut)) { Assert-Lifecycle (-not (Test-Path -LiteralPath $path)) "Owned installed file remains: $path" }
    Assert-Lifecycle (@(Get-UninstallEntries).Count -eq 0) 'Uninstall registration remains'
    Assert-Lifecycle (@(Get-ProductContexts $current.ProductCode).Count -eq 0 -and @(Get-ProductContexts $previous.ProductCode).Count -eq 0) 'MSI context remains after uninstall'
    $remainingMarker = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\RK Rebuild\Installer', $false)
    if ($null -ne $remainingMarker) {
        try { Assert-Lifecycle (@($remainingMarker.GetValueNames() | Where-Object { $_ -in @('Application', 'StartMenuShortcut') }).Count -eq 0) 'Owned component registration remains' }
        finally { $remainingMarker.Dispose() }
    }
    Assert-NoAutoLaunch
    [ordered]@{
        Format = 'rk-rebuild-standard-user-installer-lifecycle'; SchemaVersion = 1; Passed = $true
        AdministratorToken = $false; CurrentVersion = $current.Version.ToString(); PreviousVersion = $previous.Version.ToString()
        ExecutableSha256 = $exeHash.ToLowerInvariant()
        Steps = @('InstallPrevious', 'UpgradeCurrent', 'RejectDowngrade', 'RepairCurrent', 'InstalledCatalogueExport', 'InstalledNinePageOfflineRender', 'UninstallCurrent')
        HardwareAccess = $false
        Scope = 'One disposable Windows runner with unmanaged per-user MSI permitted. Not a signature, reboot-recovery, broad OS or hardware compatibility certification.'
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $work 'lifecycle-result.json') -Encoding utf8
    $completed = $true
    Write-Host "PASS: previous install, current upgrade, rejected downgrade, repair, installed catalogue and nine-page offline UI smoke, and uninstall. Logs: $work"
}
finally {
    if (-not $completed -and $attemptedProducts.Count -gt 0) {
        if ($script:MsiUncertain) {
            Write-Warning 'Cleanup deliberately skipped: MSI service may still be executing. Discard the disposable runner; retain logs.'
        }
        else {
            foreach ($code in ($attemptedProducts | Select-Object -Unique)) {
                try {
                    Assert-DisposableRunner
                    Assert-ProductCode $code
                    if (@(Get-ProductContexts $code | Where-Object { $_.Context -eq 2 -and $_.UserSid -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }).Count -gt 0) {
                        Invoke-Msi '/x' $code ('cleanup-' + $code.Trim('{}'))
                    }
                }
                catch { Write-Warning "Bounded cleanup failed for own product ${code}: $_" }
                if ($script:MsiUncertain) { break }
            }
        }
    }
    if ($null -ne $installer) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) }
    # Keep only our temp artifacts/logs for CI diagnostics; no broad file/registry cleanup.
}
