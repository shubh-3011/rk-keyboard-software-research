$ErrorActionPreference = "Stop"
$dotnetPath = Join-Path $PSScriptRoot ".dotnet\dotnet.exe"
if (-not (Test-Path -LiteralPath $dotnetPath)) {
    $dotnetPath = (Get-Command dotnet -ErrorAction Stop).Source
}
$projects = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot "tests") -Filter "*.Tests.csproj" | Sort-Object Name
if ($projects.Count -eq 0) { throw "No native model test projects were found." }
foreach ($project in $projects) {
    Write-Host "Testing $($project.Name)"
    & $dotnetPath run --project $project.FullName --configuration Release
    if ($LASTEXITCODE -ne 0) { throw "$($project.Name) failed with exit code $LASTEXITCODE" }
}
Write-Host "All $($projects.Count) offline test projects passed."
