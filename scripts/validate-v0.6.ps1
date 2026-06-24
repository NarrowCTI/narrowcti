[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$Image = 'opencti-connector-narrowcti',

    [switch]$SkipTests,

    [switch]$Preview
)

$ErrorActionPreference = 'Stop'

$RepoDir = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

$CoreModules = @(
    'connectors/otx/connector.py',
    'connectors/otx/entity_extraction.py',
    'connectors/otx/feed_adapter.py',
    'connectors/otx/models.py',
    'connectors/otx/processor.py',
    'connectors/otx/runtime.py',
    'connectors/otx/settings.py',
    'connectors/otx/otx_client.py',
    'connectors/misp/client.py',
    'connectors/misp/connector.py',
    'connectors/misp/feed_adapter.py',
    'connectors/misp/models.py',
    'connectors/misp/processor.py',
    'connectors/misp/runtime.py',
    'connectors/misp/settings.py',
    'core/decision_audit.py',
    'core/contextual_scoring.py',
    'core/feed_contract.py',
    'core/graph_candidates.py',
    'core/graph_deduplication.py',
    'core/graph_evidence.py',
    'core/graph_export_plan.py',
    'core/indicator_policy.py',
    'core/mitre_attack.py',
    'core/opencti_deduplication.py',
    'core/opencti_graph_lookup.py',
    'core/quarantine.py',
    'core/scoring.py',
    'core/policy.py',
    'core/state_repository.py',
    'core/tlp.py',
    'exporters/opencti.py',
    'exporters/stix_builder.py'
)

$GatewayModules = @(
    'gateway/preflight.py',
    'gateway/report.py',
    'gateway/decisions.py',
    'gateway/correlation.py',
    'gateway/mitre.py',
    'gateway/quarantine.py',
    'gateway/quarantine_export.py'
)

function Invoke-DockerPython {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$PythonArgs
    )

    $dockerArgs = @(
        'run',
        '--rm',
        '-v',
        "${RepoDir}:/repo",
        '-w',
        '/repo',
        $Image,
        'python'
    ) + $PythonArgs

    Write-Host ('docker {0}' -f ($dockerArgs -join ' '))
    if ($Preview) {
        return
    }

    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    try {
        $process = Start-Process `
            -FilePath 'docker' `
            -ArgumentList $dockerArgs `
            -NoNewWindow `
            -Wait `
            -PassThru `
            -RedirectStandardOutput $stdoutFile `
            -RedirectStandardError $stderrFile

        Get-Content -LiteralPath $stdoutFile
        Get-Content -LiteralPath $stderrFile
        $exitCode = $process.ExitCode
    }
    finally {
        Remove-Item -LiteralPath $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
    }

    if ($exitCode -ne 0) {
        throw "docker command failed with exit code $exitCode"
    }
}

Write-Host 'NarrowCTI v0.6 validation'
Write-Host ('  repo={0}' -f $RepoDir)
Write-Host ('  image={0}' -f $Image)
Write-Host ('  skip_tests={0}' -f $SkipTests.IsPresent.ToString().ToLower())
if ($Preview) {
    Write-Host '  preview=true docker will not be executed'
}

Invoke-DockerPython -PythonArgs (@('-m', 'py_compile') + $CoreModules)
Invoke-DockerPython -PythonArgs (@('-m', 'py_compile') + $GatewayModules)

if (-not $SkipTests) {
    Invoke-DockerPython -PythonArgs @('-m', 'unittest', 'discover', '-s', 'tests', '-v')
}

Write-Host 'NarrowCTI v0.6 validation completed'
