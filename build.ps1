$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$python = Join-Path $env:LOCALAPPDATA "Python\pythoncore-3.14-64\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        & $launcher.Source -3 -m venv "$projectRoot\.build-venv"
    } else {
        $launcher = Get-Command python.exe -ErrorAction Stop
        & $launcher.Source -m venv "$projectRoot\.build-venv"
    }
} else {
    & $python -m venv "$projectRoot\.build-venv"
}

$buildPython = "$projectRoot\.build-venv\Scripts\python.exe"
$releaseDir = Join-Path $projectRoot "release-onion-proxy"
& $buildPython -m pip install -r requirements-build.txt
if ($LASTEXITCODE -ne 0) { throw "Build dependency installation failed with exit code $LASTEXITCODE" }
& $buildPython -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name onion-proxy `
    --distpath "$releaseDir" `
    --workpath "$projectRoot\build-package" `
    --specpath "$projectRoot\build-package" `
    --collect-all mitmproxy `
    --collect-all mitmproxy_rs `
    --collect-all publicsuffix2 `
    --collect-all certifi `
    --hidden-import mitmproxy_windows `
    --additional-hooks-dir "$projectRoot\packaging\hooks" `
    --copy-metadata mitmproxy `
    "--add-data=$projectRoot\settings\ignore_domains.txt;settings" `
    "--add-data=$projectRoot\settings\blocklist.txt;settings" `
    "--add-data=$projectRoot\ui\dashboard.html;ui" `
    onion_proxy_app.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE" }

$instructions = Join-Path $projectRoot "ПРОЧТИ ПЕРЕД ЗАПУСКОМ.txt"
if (Test-Path -LiteralPath $instructions) {
    Copy-Item -LiteralPath $instructions -Destination (Join-Path $releaseDir "ПРОЧТИ ПЕРЕД ЗАПУСКОМ.txt") -Force
}
$exePath = Join-Path $releaseDir "onion-proxy.exe"
$checksum = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash
"$checksum  onion-proxy.exe" | Set-Content -LiteralPath (Join-Path $releaseDir "SHA256SUMS.txt") -Encoding ascii
Write-Host "Build complete: $releaseDir\onion-proxy.exe"
Write-Host "SHA-256: $checksum"
