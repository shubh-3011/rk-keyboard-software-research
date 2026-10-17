$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    throw "Python 3.10 or newer is required to build the desktop app."
}

python -c "import PyInstaller, webview" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Desktop build dependencies are missing. Install them with: python -m pip install -r requirements-desktop.txt"
}

python -m PyInstaller --noconfirm --clean --onefile --windowed --name RK-Research-Workbench `
    --add-data "index.html;." `
    --add-data "styles.css;." `
    --add-data "app.js;." `
    --add-data "models.json;." `
    --hidden-import webview.platforms.edgechromium `
    --hidden-import clr `
    --exclude-module webview.platforms.android `
    --exclude-module webview.platforms.gtk `
    --exclude-module webview.platforms.qt `
    --exclude-module webview.platforms.cocoa `
    --exclude-module webview.platforms.cef `
    --exclude-module PyQt5 `
    --exclude-module PyQt6 `
    --exclude-module PySide2 `
    --exclude-module PySide6 `
    --exclude-module gi `
    --exclude-module kivy `
    --exclude-module cefpython3 `
    launcher.py

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller exited with code $LASTEXITCODE"
}
Write-Host "Built dist\RK-Research-Workbench.exe"
