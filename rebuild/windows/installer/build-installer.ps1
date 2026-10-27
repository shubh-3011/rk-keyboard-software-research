[CmdletBinding()]
param(
    [string]$SourceExe = (Join-Path $PSScriptRoot "..\dist\RK-Rebuild.exe"),
    [string]$VersionProject = (Join-Path $PSScriptRoot "..\RKRebuild.csproj"),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "..\dist\installer")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Build/inspect only. Never run the payload, msiexec, or installation APIs.
$windowsRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$dotnetPath = Join-Path $windowsRoot ".dotnet\dotnet.exe"
if (-not (Test-Path -LiteralPath $dotnetPath -PathType Leaf)) {
    $dotnetCommand = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($dotnetCommand) { $dotnetPath = $dotnetCommand.Source }
}
if (-not (Test-Path -LiteralPath $dotnetPath -PathType Leaf)) {
    throw "A .NET 8 SDK is required; first build the app with rebuild/windows/build.ps1."
}
if (-not (Test-Path -LiteralPath $SourceExe -PathType Leaf)) {
    throw "Source executable not found: $SourceExe. Build the source-only app first."
}
$SourceExe = (Resolve-Path -LiteralPath $SourceExe).Path
$VersionProject = (Resolve-Path -LiteralPath $VersionProject).Path
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$licenseFile = (Resolve-Path -LiteralPath (Join-Path $windowsRoot "..\..\LICENSE")).Path

# Confine SDK/package acquisition and CLI state to the installer directory.
$environmentNames = @("DOTNET_CLI_HOME", "NUGET_PACKAGES", "NUGET_HTTP_CACHE_PATH", "DOTNET_CLI_TELEMETRY_OPTOUT", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "DOTNET_GENERATE_ASPNET_CERTIFICATE", "DOTNET_NOLOGO")
$savedEnvironment = @{}
foreach ($name in $environmentNames) { $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process") }
Push-Location -LiteralPath $PSScriptRoot
try {
    $env:DOTNET_CLI_HOME = Join-Path $PSScriptRoot ".dotnet-home"
    $env:NUGET_PACKAGES = Join-Path $PSScriptRoot ".packages"
    $env:NUGET_HTTP_CACHE_PATH = Join-Path $PSScriptRoot ".http-cache"
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
    $env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
    $env:DOTNET_GENERATE_ASPNET_CERTIFICATE = "false"
    $env:DOTNET_NOLOGO = "true"

    # Ask MSBuild rather than duplicating the app version or parsing a fixed line.
    $versionOutput = & $dotnetPath msbuild $VersionProject -nologo -getProperty:Version
    if ($LASTEXITCODE -ne 0) { throw "Could not read the app Version using MSBuild." }
    $version = ($versionOutput -join "`n").Trim()
    if ($version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
        throw "MSI requires a three-part numeric app Version, got: $version"
    }
    $parts = $version.Split('.')
    if ([long]$parts[0] -gt 255 -or [long]$parts[1] -gt 255 -or [long]$parts[2] -gt 65535) {
        throw "App Version exceeds MSI limits (255.255.65535): $version"
    }
    $metadata = [Diagnostics.FileVersionInfo]::GetVersionInfo($SourceExe)
    # InformationalVersion may include the app's experimental label / git suffix.
    $productVersionPattern = '^' + [regex]::Escape($version) + '(?:\.0)?(?:[-+].*)?$'
    if ($metadata.ProductVersion -notmatch $productVersionPattern) {
        throw "Executable ProductVersion '$($metadata.ProductVersion)' does not match app Version '$version'. Rebuild the app."
    }
    if ($metadata.FileMajorPart -ne [int]$parts[0] -or $metadata.FileMinorPart -ne [int]$parts[1] -or $metadata.FileBuildPart -ne [int]$parts[2]) {
        throw "Executable FileVersion '$($metadata.FileVersion)' does not match app Version '$version'."
    }

    # Stable identity for maintenance of the SAME immutable version; a new version
    # has a new ProductCode, while UpgradeCode in Package.wxs never changes.
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $identity = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("RK Rebuild|12D50DE5-7286-4B6E-99D9-B4F9FC1F7996|$version|win-x64")) }
    finally { $sha.Dispose() }
    $guidBytes = New-Object byte[] 16
    [Array]::Copy($identity, $guidBytes, 16)
    $guidBytes[7] = ($guidBytes[7] -band 15) -bor 80
    $guidBytes[8] = ($guidBytes[8] -band 63) -bor 128
    $productCode = (New-Object Guid -ArgumentList (,$guidBytes)).ToString().ToUpperInvariant()

    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
    $exeHash = (Get-FileHash -LiteralPath $SourceExe -Algorithm SHA256).Hash.ToLowerInvariant()
    & $dotnetPath build (Join-Path $PSScriptRoot "RKRebuild.Installer.wixproj") --configuration Release `
        "-p:PackageVersion=$version" "-p:SourceExe=$SourceExe" "-p:LicenseFile=$licenseFile" `
        "-p:ProductCode=$productCode" "-p:OutputPath=$outputDirectory\" `
        "-p:IntermediateOutputPath=obj\$version\Release\" `
        "-p:RestoreConfigFile=$(Join-Path $PSScriptRoot 'NuGet.Config')"
    if ($LASTEXITCODE -ne 0) { throw "WiX MSI build failed with exit code $LASTEXITCODE." }
    if ((Get-FileHash -LiteralPath $SourceExe -Algorithm SHA256).Hash.ToLowerInvariant() -ne $exeHash) {
        throw "Source executable changed during packaging. Retry with an immutable build."
    }
    $msi = Join-Path $outputDirectory "RK-Rebuild-$version-win-x64-experimental.msi"
    if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) { throw "Expected MSI was not built: $msi" }
    & (Join-Path $PSScriptRoot "test-installer.ps1") -MsiPath $msi -SourceExe $SourceExe -ExpectedVersion $version
    $hash = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath "$msi.sha256" -Value "$hash  $([IO.Path]::GetFileName($msi))" -NoNewline -Encoding ascii
    Write-Host "Built unsigned experimental per-user MSI: $msi"
    Write-Host "MSI SHA-256: $hash"
    Write-Host "Source EXE SHA-256: $exeHash"
}
finally {
    Pop-Location
    foreach ($name in $environmentNames) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], "Process") }
}
