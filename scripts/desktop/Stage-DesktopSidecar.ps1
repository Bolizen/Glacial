$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repository = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$sourceRoot = Join-Path $repository ".desktop-build\pyinstaller\dist\glacial-backend"
$stageRoot = Join-Path $repository "frontend\src-tauri\binaries"
$expectedStage = [System.IO.Path]::GetFullPath((Join-Path $repository "frontend\src-tauri\binaries"))
$resolvedStage = [System.IO.Path]::GetFullPath($stageRoot)
if (-not $resolvedStage.Equals($expectedStage, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to stage the sidecar outside Tauri's ignored binaries directory."
}

$sourceExecutable = Join-Path $sourceRoot "glacial-backend.exe"
$sourceSupport = Join-Path $sourceRoot "_internal"
$sourceReceipt = Join-Path $sourceRoot ".glacial-backend-stage.json"
if (-not (Test-Path -LiteralPath $sourceExecutable -PathType Leaf) -or
    -not (Test-Path -LiteralPath $sourceSupport -PathType Container) -or
    -not (Test-Path -LiteralPath $sourceReceipt -PathType Leaf)) {
    throw "Build the PyInstaller onedir backend before staging the Tauri sidecar."
}

$targetTriple = (& rustc --print host-tuple).Trim()
if ($LASTEXITCODE -ne 0 -or $targetTriple -ne "x86_64-pc-windows-msvc") {
    throw "Phase 2A staging requires the x86_64-pc-windows-msvc Rust target."
}

if (Test-Path -LiteralPath $stageRoot) {
    Remove-Item -LiteralPath $stageRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $stageRoot | Out-Null
Copy-Item -LiteralPath $sourceExecutable -Destination (Join-Path $stageRoot "glacial-backend-$targetTriple.exe")
Copy-Item -LiteralPath $sourceSupport -Destination (Join-Path $stageRoot "_internal") -Recurse
Copy-Item -LiteralPath $sourceReceipt -Destination (Join-Path $stageRoot ".glacial-backend-stage.json")
Write-Output "<REPOSITORY_ROOT>\frontend\src-tauri\binaries"
