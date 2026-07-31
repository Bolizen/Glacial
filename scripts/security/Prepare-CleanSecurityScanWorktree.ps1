param(
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-GitText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,
        [Parameter(Mandatory = $true)]
        [string[]]$GitArguments
    )

    $lines = @(& git -C $WorkingDirectory @GitArguments)
    if ($LASTEXITCODE -ne 0) {
        throw "git $($GitArguments -join ' ') failed."
    }

    return ($lines -join [Environment]::NewLine).Trim()
}

function Get-Commit {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,
        [Parameter(Mandatory = $true)]
        [string[]]$GitArguments
    )

    $commit = Invoke-GitText -WorkingDirectory $WorkingDirectory -GitArguments $GitArguments
    if ($commit -notmatch '^[0-9a-f]{40}$') {
        throw "Expected a full Git commit from git $($GitArguments -join ' ')."
    }

    return $commit
}

$repository = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$repositoryParent = Split-Path -Parent $repository
$target = [System.IO.Path]::GetFullPath((Join-Path $repositoryParent "Glacial-security-scan-target"))
$repositoryPrefix = "$repository$([System.IO.Path]::DirectorySeparatorChar)"

if ($target.StartsWith($repositoryPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "The clean scan target must be outside the source worktree."
}
if (Test-Path -LiteralPath $target) {
    throw "Refusing to overwrite an existing clean scan target: $target"
}

$status = Invoke-GitText -WorkingDirectory $repository -GitArguments @("status", "--porcelain=v1")
if ($status) {
    throw "Refusing to prepare a scan target from a dirty source worktree."
}

$branch = Invoke-GitText -WorkingDirectory $repository -GitArguments @("branch", "--show-current")
if ($branch -ne "main") {
    throw "Refusing to prepare a scan target unless the source branch is main."
}

$head = Get-Commit -WorkingDirectory $repository -GitArguments @("rev-parse", "HEAD")
$localMain = Get-Commit -WorkingDirectory $repository -GitArguments @("rev-parse", "main")
$originMain = Get-Commit -WorkingDirectory $repository -GitArguments @("rev-parse", "origin/main")
$directRemoteLine = Invoke-GitText -WorkingDirectory $repository -GitArguments @("ls-remote", "origin", "refs/heads/main")
if ($directRemoteLine -notmatch '^(?<commit>[0-9a-f]{40})\s+refs/heads/main$') {
    throw "Could not verify direct origin/main."
}
$directRemoteMain = $Matches.commit

if ($head -ne $localMain -or $head -ne $originMain -or $head -ne $directRemoteMain) {
    throw "Refusing to prepare a scan target from a misaligned source worktree."
}

if ($DryRun) {
    Write-Output "Dry run: would create $target at $head from the clean, aligned main worktree."
    exit 0
}

& git -C $repository worktree add --detach $target $head
if ($LASTEXITCODE -ne 0) {
    throw "Could not create the clean scan worktree."
}

$targetHead = Get-Commit -WorkingDirectory $target -GitArguments @("rev-parse", "HEAD")
$targetStatus = Invoke-GitText -WorkingDirectory $target -GitArguments @("status", "--porcelain=v1")
$targetUntracked = Invoke-GitText -WorkingDirectory $target -GitArguments @("ls-files", "--others", "--exclude-standard")
$targetIgnored = Invoke-GitText -WorkingDirectory $target -GitArguments @("ls-files", "--others", "--ignored", "--exclude-standard")
$sourceTracked = @(& git -C $repository ls-files).Count
$targetTracked = @(& git -C $target ls-files).Count

if ($targetHead -ne $head -or $targetStatus -or $targetUntracked -or $targetIgnored -or $targetTracked -ne $sourceTracked) {
    throw "The clean scan worktree did not validate as an exact tracked-only checkout."
}

Write-Output "Prepared clean scan target: $target"
Write-Output "Commit: $targetHead"
Write-Output "Tracked files: $targetTracked"
