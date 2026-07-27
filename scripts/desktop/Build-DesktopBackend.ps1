$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repository = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
& (Join-Path $PSScriptRoot "Validate-DesktopBuildEnvironment.ps1")
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$buildPython = Join-Path $repository ".desktop-build\venv\Scripts\python.exe"
$specification = Join-Path $repository "backend\glacial-backend.spec"
$outputRoot = Join-Path $repository ".desktop-build\pyinstaller"
$distribution = Join-Path $outputRoot "dist"
$work = Join-Path $outputRoot "work"
$env:PYINSTALLER_CONFIG_DIR = Join-Path $outputRoot "cache"

& $buildPython -m PyInstaller --noconfirm --clean --distpath $distribution --workpath $work $specification
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$backendExecutable = Join-Path $distribution "glacial-backend\glacial-backend.exe"
$supportDirectory = Join-Path $distribution "glacial-backend\_internal"
if (-not (Test-Path -LiteralPath $backendExecutable -PathType Leaf) -or
    -not (Test-Path -LiteralPath $supportDirectory -PathType Container)) {
    throw "PyInstaller did not produce the expected onedir backend layout."
}
Write-Output "<REPOSITORY_ROOT>\.desktop-build\pyinstaller\dist\glacial-backend\glacial-backend.exe"
