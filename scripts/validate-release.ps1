[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$Image = 'opencti-connector-narrowcti',

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
