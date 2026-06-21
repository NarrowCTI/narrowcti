[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[0-9]{4}-[0-9]{2}-[0-9]{2}$')]
    [string]$FromDate,

    [ValidatePattern('^$|^[0-9]{4}-[0-9]{2}-[0-9]{2}$')]
    [string]$ToDate = '',

    [ValidateNotNullOrEmpty()]
    [string]$Tags = 'tlp:green',

    [ValidateRange(1, 5)]
    [int]$MaxEvents = 1,

    [ValidateRange(1, 1000)]
    [int]$MaxAttributes = 1000,

    [ValidateRange(1, 1000)]
    [int]$MaxIocs = 1000,

    [string]$LabRoot = '',

    [ValidateNotNullOrEmpty()]
    [string]$ComposeProfile = 'narrowcti-misp',

    [ValidateNotNullOrEmpty()]
    [string]$Service = 'connector-narrowcti-misp',

    [switch]$Preview
)

$ErrorActionPreference = 'Stop'

function Resolve-LabRoot {
    param([string]$Value)

    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        return (Resolve-Path -LiteralPath $Value).Path
    }

    $repoParent = Join-Path $PSScriptRoot '..'
    return (Resolve-Path -LiteralPath (Join-Path $repoParent '..')).Path
}

function New-SafeLabel {
    param([string]$Value)

    $label = ($Value -replace '[^A-Za-z0-9_.-]', '_').Trim('_')
    if ([string]::IsNullOrWhiteSpace($label)) {
        return 'window'
    }

    return $label
}

if (-not [string]::IsNullOrWhiteSpace($ToDate)) {
    if ([datetime]::Parse($FromDate) -gt [datetime]::Parse($ToDate)) {
        throw 'FromDate must be earlier than or equal to ToDate.'
    }
}

$resolvedLabRoot = Resolve-LabRoot $LabRoot
$openctiDir = Join-Path $resolvedLabRoot 'opencti'
$repoDir = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $openctiDir 'docker-compose.yml'
$mispEnv = Join-Path (Join-Path (Join-Path $repoDir 'connectors') 'misp') '.env'

if (-not (Test-Path -LiteralPath $composeFile)) {
    throw "OpenCTI compose file not found: $composeFile"
}

if (-not (Test-Path -LiteralPath $mispEnv)) {
    throw "MISP env file not found: $mispEnv"
}

$toLabel = $ToDate
if ([string]::IsNullOrWhiteSpace($toLabel)) {
    $toLabel = 'open'
}

$safeLabel = New-SafeLabel ('{0}_{1}_{2}' -f $FromDate, $toLabel, $Tags)
$stateFile = '/tmp/narrowcti_misp_state_{0}.json' -f $safeLabel
$auditFile = '/tmp/narrowcti_misp_decisions_{0}.jsonl' -f $safeLabel

Write-Host 'NarrowCTI MISP safe backfill window'
Write-Host ('  from={0} to={1} tags={2}' -f $FromDate, $toLabel, $Tags)
Write-Host ('  max_events={0} max_attributes={1} max_iocs={2}' -f $MaxEvents, $MaxAttributes, $MaxIocs)
Write-Host '  dry_run=true run_once=true state=ephemeral'
if ($Preview) {
    Write-Host '  preview=true docker will not be executed'
}

$composeArgs = @(
    'compose',
    '--profile', $ComposeProfile,
    'run',
    '--rm',
    '--no-deps',
    '-e', 'MISP_DRY_RUN=true',
    '-e', 'MISP_RUN_ONCE=true',
    '-e', ('MISP_STATE_FILE={0}' -f $stateFile),
    '-e', ('MISP_DECISION_AUDIT_FILE={0}' -f $auditFile),
    '-e', ('MISP_FROM_DATE={0}' -f $FromDate),
    '-e', ('MISP_TO_DATE={0}' -f $ToDate),
    '-e', ('MISP_TAGS={0}' -f $Tags),
    '-e', 'MISP_PUBLISHED_ONLY=true',
    '-e', ('MISP_MAX_EVENTS_PER_RUN={0}' -f $MaxEvents),
    '-e', ('MISP_MAX_ATTRIBUTES_PER_EVENT={0}' -f $MaxAttributes),
    '-e', ('MISP_MAX_IOCS_PER_EVENT={0}' -f $MaxIocs),
    $Service
)

if ($Preview) {
    Write-Host ('Compose directory: {0}' -f $openctiDir)
    Write-Host ('Docker command: docker {0}' -f ($composeArgs -join ' '))
    return
}

Push-Location $openctiDir
try {
    & docker @composeArgs
    $exitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}

if ($exitCode -ne 0) {
    throw "docker compose run failed with exit code $exitCode"
}
