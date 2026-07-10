[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OutputFile = '',

    [switch]$DiskPostureOk,

    [switch]$DiskPostureUnhealthy,

    [string]$Notes = '',

    [switch]$Preview
)

$ErrorActionPreference = 'Stop'

if ($DiskPostureOk -and $DiskPostureUnhealthy) {
    throw 'Use only one of -DiskPostureOk or -DiskPostureUnhealthy.'
}

$RepoDir = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($OutputFile)) {
    $OutputFile = Join-Path (Join-Path $RepoDir 'state') 'operational-validation-evidence.json'
}

function Invoke-DockerCapture {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$DockerArgs
    )

    $output = & docker @DockerArgs 2>&1
    return @{
        exit_code = $LASTEXITCODE
        output = @($output)
    }
}

function Test-ContainerStatusesHealthy {
    param([string[]]$Lines)

    foreach ($line in $Lines) {
        if ($line -match '(?i)unhealthy|restarting|dead') {
            return $false
        }
    }
    return $true
}

$statsCommand = 'docker stats --no-stream'
$systemDfCommand = 'docker system df'
$containerStatusCommand = 'docker ps --format "{{.Names}}\t{{.Status}}"'

if ($Preview) {
    Write-Host 'NarrowCTI resource posture capture'
    Write-Host ('  output_file={0}' -f $OutputFile)
    Write-Host ('  command={0}' -f $statsCommand)
    Write-Host ('  command={0}' -f $systemDfCommand)
    Write-Host ('  command={0}' -f $containerStatusCommand)
    Write-Host '  preview=true docker will not be executed'
    return
}

$stats = Invoke-DockerCapture -DockerArgs @('stats', '--no-stream')
$systemDf = Invoke-DockerCapture -DockerArgs @('system', 'df')
$containers = Invoke-DockerCapture -DockerArgs @('ps', '--format', '{{.Names}}\t{{.Status}}')

$dockerStatsCaptured = $stats.exit_code -eq 0
$dockerSystemDfCaptured = $systemDf.exit_code -eq 0
$containerStatusCaptured = $containers.exit_code -eq 0
$containersHealthy = $containerStatusCaptured -and (Test-ContainerStatusesHealthy $containers.output)

$resourcePosture = [ordered]@{
    captured_at = (Get-Date).ToUniversalTime().ToString('o')
    docker_stats_captured = $dockerStatsCaptured
    docker_stats_command = $statsCommand
    docker_stats_exit_code = $stats.exit_code
    docker_system_df_captured = $dockerSystemDfCaptured
    docker_system_df_command = $systemDfCommand
    docker_system_df_exit_code = $systemDf.exit_code
    container_status_captured = $containerStatusCaptured
    container_status_command = $containerStatusCommand
    container_status_exit_code = $containers.exit_code
    containers_healthy = $containersHealthy
    containers_seen = @($containers.output).Count
}

if ($DiskPostureOk) {
    $resourcePosture.disk_posture_ok = $true
}
elseif ($DiskPostureUnhealthy) {
    $resourcePosture.disk_posture_ok = $false
}

if (-not [string]::IsNullOrWhiteSpace($Notes)) {
    $resourcePosture.notes = $Notes
}

if (
    $dockerStatsCaptured -and
    $dockerSystemDfCaptured -and
    $containersHealthy -and
    $DiskPostureOk
) {
    $resourcePosture.status = 'ok'
}
elseif (
    -not $dockerStatsCaptured -or
    -not $dockerSystemDfCaptured -or
    -not $containersHealthy -or
    $DiskPostureUnhealthy
) {
    $resourcePosture.status = 'unhealthy'
}
else {
    $resourcePosture.status = 'needs-review'
}

$evidence = [ordered]@{
    full_validation_passed = $false
    opencti_ui_no_duplicate = $false
    opencti_ui_duplicate_found = $false
    resource_posture_ok = $resourcePosture.status -eq 'ok'
    resource_posture_unhealthy = $resourcePosture.status -eq 'unhealthy'
    resource_posture = $resourcePosture
}

$parent = Split-Path -Parent $OutputFile
if (-not [string]::IsNullOrWhiteSpace($parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}

$evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputFile -Encoding UTF8

Write-Host 'NarrowCTI resource posture evidence written'
Write-Host ('  output_file={0}' -f $OutputFile)
Write-Host ('  status={0}' -f $resourcePosture.status)
Write-Host ('  docker_stats_captured={0}' -f $dockerStatsCaptured.ToString().ToLower())
Write-Host ('  docker_system_df_captured={0}' -f $dockerSystemDfCaptured.ToString().ToLower())
Write-Host ('  containers_healthy={0}' -f $containersHealthy.ToString().ToLower())
if (-not ($DiskPostureOk -or $DiskPostureUnhealthy)) {
    Write-Host '  disk_posture=needs-review (rerun with -DiskPostureOk after reviewing docker system df)'
}
