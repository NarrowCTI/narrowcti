[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$Image = 'narrowcti/gateway:local',

    [switch]$SkipTests,

    [switch]$InstallTestDependencies,

    [switch]$Preview
)

$ErrorActionPreference = 'Stop'

$RepoDir = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$RuntimeHelper = Join-Path $PSScriptRoot 'validate_runtime_package.py'

if ($SkipTests -or $InstallTestDependencies) {
    Write-Warning 'The immutable runtime image no longer installs development dependencies or runs the behavioral suite. Use CI for behavioral validation; the switches are retained for compatibility and are deprecated.'
}

$dockerArgs = @(
    'run',
    '--rm',
    '--read-only',
    '--tmpfs',
    '/tmp',
    '--mount',
    "type=bind,src=${RuntimeHelper},dst=/tmp/validate_runtime_package.py,readonly",
    $Image,
    'python',
    '/tmp/validate_runtime_package.py',
    '--compile',
    '--imports'
)

Write-Host 'NarrowCTI release runtime validation'
Write-Host ('  image={0}' -f $Image)
Write-Host '  behavioral tests: CI package-first gate (not production image)'
if ($Preview) {
    Write-Host ('docker {0}' -f ($dockerArgs -join ' '))
    Write-Host '  preview=true docker will not be executed'
    exit 0
}

& docker @dockerArgs
if ($LASTEXITCODE -ne 0) {
    throw "runtime validation failed with exit code $LASTEXITCODE"
}

Write-Host 'NarrowCTI release runtime validation completed'
