# Local equivalent of .github/workflows/ci.yml for machines without a runner.
#
#   pwsh -File scripts/check.ps1
#
# Runs the same two gates CI runs: ruff, then the test suite. Deliberately does
# NOT run `ruff format`: the codebase writes dense one-line statements, and
# reformatting would rewrite hundreds of lines of reviewed cryptographic logic.
[CmdletBinding()]
param(
    [string]$Python = ".venv/Scripts/python.exe"
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if (-not (Test-Path $Python)) {
        throw "Python not found at '$Python'. Pass -Python <path>, or create the venv first."
    }

    Write-Host '== ruff ==' -ForegroundColor Cyan
    & $Python -m ruff check src tests
    if ($LASTEXITCODE -ne 0) { throw 'ruff reported findings' }

    Write-Host ''
    Write-Host '== pytest ==' -ForegroundColor Cyan
    & $Python -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw 'tests failed' }

    Write-Host ''
    Write-Host 'All checks passed.' -ForegroundColor Green
}
finally {
    Pop-Location
}
