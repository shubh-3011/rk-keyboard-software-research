$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$dotnetPath = Join-Path $PSScriptRoot ".dotnet\dotnet.exe"
if (-not (Test-Path -LiteralPath $dotnetPath)) {
    $dotnetCommand = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($dotnetCommand) { $dotnetPath = $dotnetCommand.Source }
}
if (-not (Test-Path -LiteralPath $dotnetPath)) {
    throw "The .NET 8 SDK was not found. Install the Windows SDK from https://dotnet.microsoft.com/download/dotnet/8.0 and retry."
}
$sdks = & $dotnetPath --list-sdks
if (-not $sdks) {
    throw "Only the .NET runtime is installed. Build RK Rebuild with the .NET 8 SDK, not only the runtime."
}

$output = Join-Path $PSScriptRoot "dist\RK-Rebuild.exe"
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $output) | Out-Null

& $dotnetPath publish (Join-Path $PSScriptRoot "RKRebuild.csproj") `
    --configuration Release `
    --runtime win-x64 `
    --self-contained true `
    --output (Join-Path $PSScriptRoot "dist") `
    /p:PublishSingleFile=true `
    /p:IncludeAllContentForSelfExtract=true `
    /p:EnableCompressionInSingleFile=true `
    /p:DebugSymbols=false `
    /p:DebugType=None

if ($LASTEXITCODE -ne 0) {
    throw "The native Windows build failed with exit code $LASTEXITCODE."
}

$hash = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$output.sha256" -Value "$hash  RK-Rebuild.exe" -NoNewline -Encoding ascii
Write-Host "Built native WPF app: $output"
Write-Host "SHA-256: $hash"
