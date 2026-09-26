[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$Image = 'narrowcti/gateway:local',

    [switch]$SkipTests,

    [switch]$SkipTestDependencyInstall,

    [switch]$Preview
)

$ErrorActionPreference = 'Stop'

& (Join-Path $PSScriptRoot 'validate-release-runtime.ps1') `
    -Image $Image `
    -SkipTests:$SkipTests `
    -InstallTestDependencies:(!$SkipTestDependencyInstall) `
    -Preview:$Preview
