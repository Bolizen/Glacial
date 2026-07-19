$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Compatibility entrypoint for hosts whose policy permits local scripts. The
# normal npm workflow calls the Node implementation directly and does not rely
# on an execution-policy bypass.
$developmentScript = Join-Path $PSScriptRoot "desktop-development.mjs"
& node.exe $developmentScript build-portable
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
