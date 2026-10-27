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
$env:USERPROFILE = [Environment]::GetFolderPath('UserProfile')
$env:APPDATA = [Environment]::GetFolderPath('ApplicationData')
$env:LOCALAPPDATA = [Environment]::GetFolderPath('LocalApplicationData')
$env:TEMP = $env:RUNNER_TEMP
$env:TMP = $env:RUNNER_TEMP
$env:DOTNET_BUNDLE_EXTRACT_BASE_DIR = Join-Path $env:RUNNER_TEMP 'bundle-cache'
$env:DOTNET_CLI_HOME = $env:RUNNER_TEMP
try {
    & (Join-Path $PSScriptRoot 'rebuild\windows\installer\test-installer-lifecycle.ps1') -CurrentMsiPath (Join-Path $PSScriptRoot 'payload\current.msi') -PreviousMsiPath (Join-Path $PSScriptRoot 'payload\previous.msi') -SourceExe (Join-Path $PSScriptRoot 'payload\RK-Rebuild.exe') -ConfirmDisposableVm
    exit 0
} catch { Write-Error $_; exit 1 }
'@
    $bootstrapPath = Join-Path $scratch 'run-standard-user.ps1'
    Set-Content -LiteralPath $bootstrapPath -Value $bootstrap -Encoding utf8
    $credential = [Management.Automation.PSCredential]::new(($env:COMPUTERNAME + '\' + $name), $secret)
    $service = Get-Service -Name seclogon
    if ($service.Status -ne 'Running') { Start-Service -Name seclogon }
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
