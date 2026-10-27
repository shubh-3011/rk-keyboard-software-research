[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CurrentMsiPath,
    [Parameter(Mandatory = $true)][string]$PreviousMsiPath,
    [Parameter(Mandatory = $true)][string]$SourceExe,
    [switch]$ConfirmDisposableVm
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Account creation, ACL changes and installation are forbidden outside this
# explicitly confirmed disposable hosted runner. No local developer execution.
if (-not $ConfirmDisposableVm -or $env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows') {
    throw 'REFUSED: standard-user installer validation requires an explicitly confirmed disposable GitHub-hosted Windows runner.'
}

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The CI wrapper needs the hosted runner administrator token to create its temporary standard account.'
}
foreach ($path in @($CurrentMsiPath, $PreviousMsiPath, $SourceExe)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing lifecycle input: $path" }
}
$CurrentMsiPath = (Resolve-Path -LiteralPath $CurrentMsiPath).Path
$PreviousMsiPath = (Resolve-Path -LiteralPath $PreviousMsiPath).Path
$SourceExe = (Resolve-Path -LiteralPath $SourceExe).Path
$id = [Guid]::NewGuid().ToString('N')
$name = 'rkci' + $id.Substring(0, 12)
$scratch = Join-Path $env:PUBLIC ('RK-Rebuild-CI-' + $id)
$retained = Join-Path $env:RUNNER_TEMP ('rk-installer-lifecycle-standard-' + $id)
$created = $false
$worker = $null
$uncertain = $false
$installerPolicy = $null
$policyChanged = $false
try {
    $passwordBytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    $secret = ConvertTo-SecureString ([Convert]::ToBase64String($passwordBytes) + '!Aa9') -AsPlainText -Force
    $account = New-LocalUser -Name $name -Password $secret -AccountNeverExpires -PasswordNeverExpires -Description 'Disposable RK MSI lifecycle test'
    $created = $true
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $account
    New-Item -ItemType Directory -Path $scratch | Out-Null
    # Only SYSTEM, administrators and this specific new account can access the
    # test tree. No ACLs on user profiles or existing project files are changed.
    & icacls.exe $scratch /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' ("*" + $account.SID.Value + ':(OI)(CI)M') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot confine the temporary standard-user test directory.' }
    $scripts = Join-Path $scratch 'rebuild\windows\installer'
    $payload = Join-Path $scratch 'payload'
    $results = Join-Path $scratch 'results'
    foreach ($directory in @($scripts, $payload, $results)) { New-Item -ItemType Directory -Path $directory | Out-Null }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'test-installer-lifecycle.ps1') -Destination $scripts
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\..\..\LICENSE') -Destination (Join-Path $scratch 'LICENSE')
    Copy-Item -LiteralPath $CurrentMsiPath -Destination (Join-Path $payload 'current.msi')
    Copy-Item -LiteralPath $PreviousMsiPath -Destination (Join-Path $payload 'previous.msi')
    Copy-Item -LiteralPath $SourceExe -Destination (Join-Path $payload 'RK-Rebuild.exe')
    # The bootstrap contains no password. CI identity is inherited explicitly;
    # its worker independently rejects an administrator token before any input IO.
    $bootstrap = @'
$ErrorActionPreference = 'Stop'
$env:GITHUB_ACTIONS = 'true'
$env:RUNNER_ENVIRONMENT = 'github-hosted'
$env:RUNNER_OS = 'Windows'
$env:RUNNER_TEMP = Join-Path $PSScriptRoot 'results'
# CreateProcessWithLogon can inherit runneradmin's environment even when its
# token/profile belong to our new user. Bind USERPROFILE to the token SID's
# ProfileList entry before resolving expandable shell folder paths.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$profileKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $identity.User.Value), $false)
if ($null -eq $profileKey) { throw 'The standard-user token has no loaded profile registration.' }
try { $profilePath = [string]$profileKey.GetValue('ProfileImagePath') }
finally { $profileKey.Dispose() }
if ([string]::IsNullOrWhiteSpace($profilePath)) { throw 'The standard-user profile path is unavailable.' }
$env:USERPROFILE = $profilePath
$env:USERNAME = $identity.Name.Split('\')[-1]
$env:USERDOMAIN = $identity.Name.Split('\')[0]
$env:HOMEDRIVE = [IO.Path]::GetPathRoot($profilePath).TrimEnd('\')
$env:HOMEPATH = $profilePath.Substring($env:HOMEDRIVE.Length)
$env:APPDATA = [Environment]::GetFolderPath('ApplicationData', [Environment+SpecialFolderOption]::DoNotVerify)
$env:LOCALAPPDATA = [Environment]::GetFolderPath('LocalApplicationData', [Environment+SpecialFolderOption]::DoNotVerify)
$env:TEMP = $env:RUNNER_TEMP
$env:TMP = $env:RUNNER_TEMP
$env:DOTNET_BUNDLE_EXTRACT_BASE_DIR = Join-Path $env:RUNNER_TEMP 'bundle-cache'
$env:DOTNET_CLI_HOME = $env:RUNNER_TEMP
[ordered]@{ TokenName = $identity.Name; UserProfile = $env:USERPROFILE; LocalAppData = $env:LOCALAPPDATA; AppData = $env:APPDATA } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $env:RUNNER_TEMP 'standard-user-profile.json') -Encoding utf8
try {
    & (Join-Path $PSScriptRoot 'rebuild\windows\installer\test-installer-lifecycle.ps1') -CurrentMsiPath (Join-Path $PSScriptRoot 'payload\current.msi') -PreviousMsiPath (Join-Path $PSScriptRoot 'payload\previous.msi') -SourceExe (Join-Path $PSScriptRoot 'payload\RK-Rebuild.exe') -ConfirmDisposableVm
    exit 0
} catch {
    [Console]::Error.WriteLine($_.Exception.ToString())
    [Console]::Error.WriteLine($_.InvocationInfo.PositionMessage)
    [Console]::Error.WriteLine($_.ScriptStackTrace)
    exit 1
}
'@
    $bootstrapPath = Join-Path $scratch 'run-standard-user.ps1'
    Set-Content -LiteralPath $bootstrapPath -Value $bootstrap -Encoding utf8
    $credential = [Management.Automation.PSCredential]::new(($env:COMPUTERNAME + '\' + $name), $secret)
    $service = Get-Service -Name seclogon
    if ($service.Status -ne 'Running') { Start-Service -Name seclogon }
    # Windows Server hosted images can default DisableMSI to 1, prohibiting
    # unmanaged installs for standard users. Configure only this disposable
    # fixture, restoring the exact prior value/absence in finally. Never enable
    # AlwaysInstallElevated or change a user's machine to make our MSI work.
    $machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try { $installerPolicy = $machine.CreateSubKey('Software\Policies\Microsoft\Windows\Installer') }
    finally { $machine.Dispose() }
    $hadDisableMsi = 'DisableMSI' -in $installerPolicy.GetValueNames()
    $oldDisableMsi = if ($hadDisableMsi) { $installerPolicy.GetValue('DisableMSI') } else { $null }
    if ($hadDisableMsi -and $installerPolicy.GetValueKind('DisableMSI') -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
        throw 'Unexpected DisableMSI registry type; refuse to alter the fixture policy.'
    }
    $installerPolicy.SetValue('DisableMSI', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
    $policyChanged = $true
    Write-Host 'Disposable fixture: permit unmanaged standard-user MSI installs; original DisableMSI value/absence will be restored.'
    $worker = Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') -ArgumentList ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $bootstrapPath + '"') -Credential $credential -LoadUserProfile -WorkingDirectory $scratch -RedirectStandardOutput (Join-Path $results 'standard-user.stdout.log') -RedirectStandardError (Join-Path $results 'standard-user.stderr.log') -PassThru
    if (-not $worker.WaitForExit(1200000)) {
        $uncertain = $true
        try { $worker.Kill() } catch { Write-Warning 'Could not stop the owned test worker.' }
        throw 'Standard-user test exceeded 20 minutes. Do not start further MSI transactions; discard the disposable runner.'
    }
    if ($worker.ExitCode -ne 0) { throw "Standard-user lifecycle failed with exit $($worker.ExitCode); retain stdout/stderr and MSI logs." }
    Write-Host 'PASS: complete MSI lifecycle executed under an independent standard Windows account, without administrator membership.'
} finally {
    if ($null -ne $worker) { $worker.Dispose() }
    if ($null -ne $installerPolicy) {
        try {
            if ($policyChanged) {
                if ($hadDisableMsi) { $installerPolicy.SetValue('DisableMSI', $oldDisableMsi, [Microsoft.Win32.RegistryValueKind]::DWord) }
                else { $installerPolicy.DeleteValue('DisableMSI', $false) }
            }
        } finally { $installerPolicy.Dispose() }
    }
    if (Test-Path -LiteralPath (Join-Path $scratch 'results')) {
        New-Item -ItemType Directory -Path $retained | Out-Null
        Copy-Item -Path (Join-Path $scratch 'results\*') -Destination $retained -Recurse
        Write-Host "Standard-user lifecycle artifacts: $retained"
    }
    if ($created -and -not $uncertain) {
        # Remove only the unique account this invocation created. Its disposable
        # profile/scratch can remain for diagnostics; no recursive profile deletion.
        Remove-LocalUser -SID $account.SID
    }
}
