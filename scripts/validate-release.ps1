[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$Image = 'opencti-connector-narrowcti',

    [switch]$SkipTests,

    [switch]$Preview
)

$ErrorActionPreference = 'Stop'

& (Join-Path $PSScriptRoot 'validate-v0.6.ps1') `
    -Image $Image `
    -SkipTests:$SkipTests `
    -Preview:$Preview
