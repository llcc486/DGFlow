param(
    [string]$PythonPath = '',
    [string]$Runtime = '',
    [ValidateRange(2, 100)][Nullable[int]]$ClientCount = $null,
    [ValidateRange(2, 32)][Nullable[int]]$AuthorityCount = $null,
    [ValidateRange(2, 32)][Nullable[int]]$AggregatorCount = $null,
    [ValidateRange(2, 32)][Nullable[int]]$AuthorityThreshold = $null,
    [ValidateRange(2, 32)][Nullable[int]]$AggregatorThreshold = $null,
    [ValidateSet('local', 'A', 'B', 'C')][string]$Machine = '',
    [switch]$Offline,
    [switch]$SetupOnly,
    [string]$MnistSource = '',
    [string]$CifarSource = ''
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$EnvironmentRoot = Join-Path $ProjectRoot '.venv'
if (-not $Runtime) { $Runtime = Join-Path $ProjectRoot 'runtime' }

function Invoke-DgflPython {
    param([string[]]$Arguments)
    & $script:DgflPython @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Python command failed (exit $LASTEXITCODE). Startup stopped." }
}

function Get-DgflHash {
    param([string]$Path, [string]$Text)
    $Algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        [byte[]]$Bytes = if ($PSBoundParameters.ContainsKey('Text')) {
            [System.Text.Encoding]::UTF8.GetBytes($Text)
        } else {
            [System.IO.File]::ReadAllBytes($Path)
        }
        return [BitConverter]::ToString($Algorithm.ComputeHash($Bytes)).Replace('-', '')
    }
    finally { $Algorithm.Dispose() }
}

Push-Location -LiteralPath $ProjectRoot
try {
    if ($PythonPath) {
        $script:DgflPython = (Resolve-Path -LiteralPath $PythonPath).Path
    } else {
        $script:DgflPython = Join-Path $EnvironmentRoot 'Scripts/python.exe'
        if (-not (Test-Path -LiteralPath $script:DgflPython)) {
            if ($Offline) { throw 'Offline setup requires an existing Python environment. Run once without -Offline.' }
            $Launcher = Get-Command py -ErrorAction SilentlyContinue
            if ($Launcher) {
                & $Launcher.Source -3 -m venv $EnvironmentRoot
            } else {
                $Launcher = Get-Command python -ErrorAction Stop
                & $Launcher.Source -m venv $EnvironmentRoot
            }
            if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
        }
    }
    Invoke-DgflPython -Arguments @('-c', 'import sys; sys.exit(''Locked deployment requires Python 3.12 or newer; Python 3.12 is recommended'') if sys.version_info < (3,12) else None')
    $ProjectFile = Join-Path $ProjectRoot 'pyproject.toml'
    $LockFile = Join-Path $ProjectRoot 'requirements-lock.txt'
    $Fingerprint = Get-DgflHash -Path $ProjectFile
    if (Test-Path -LiteralPath $LockFile) { $Fingerprint += Get-DgflHash -Path $LockFile }
    # A project stamp must not stand in for installing another selected environment.
    # Hash UTF-8 identity bytes so the stamp remains ASCII even with a Chinese path.
    $Fingerprint += Get-DgflHash -Text $script:DgflPython
    $StampFile = Join-Path $EnvironmentRoot 'dgflow-install.sha256'
    $InstalledFingerprint = if (Test-Path -LiteralPath $StampFile) { (Get-Content -LiteralPath $StampFile -Raw).Trim() } else { '' }
    if (-not $Offline -and $InstalledFingerprint -ne $Fingerprint) {
        Write-Host 'First setup or changed dependencies: pip may access the network.'
        if (Test-Path -LiteralPath $LockFile) {
            Invoke-DgflPython -Arguments @('-B', (Join-Path $PSScriptRoot 'deployment_downloads.py'), '--root', $ProjectRoot, 'pip-install', '--', '--only-binary=:all:', '-r', $LockFile)
            Invoke-DgflPython -Arguments @('-m', 'pip', 'install', '--no-index', '--no-build-isolation', '--no-deps', '-e', $ProjectRoot)
        } else {
            Invoke-DgflPython -Arguments @('-B', (Join-Path $PSScriptRoot 'deployment_downloads.py'), '--root', $ProjectRoot, 'pip-install', '--', '-e', $ProjectRoot)
        }
    }
    Invoke-DgflPython -Arguments @('-m', 'pip', 'check')
    Invoke-DgflPython -Arguments @('-c', 'import numpy, fastapi, uvicorn, httpx, cryptography, yaml, psutil, py_arkworks_bls12381, dgfl.cli')
    if (-not $Offline) {
        New-Item -ItemType Directory -Path $EnvironmentRoot -Force | Out-Null
        Set-Content -LiteralPath $StampFile -Value $Fingerprint -Encoding Ascii
    }

    # Match the helper and roles, including relative paths and linked runtime parents.
    # JSON keeps the probe's stdout ASCII when the resulting path contains Chinese.
    $DataDirectory = Invoke-DgflPython -Arguments @('-c', 'import json,pathlib,sys; print(json.dumps(str(pathlib.Path(sys.argv[1]).resolve().parent / ''data'' / ''mnist'')))', $Runtime) | ConvertFrom-Json
    $Archives = @('train-images-idx3-ubyte.gz', 'train-labels-idx1-ubyte.gz', 't10k-images-idx3-ubyte.gz', 't10k-labels-idx1-ubyte.gz')
    $MissingData = @($Archives | Where-Object { -not (Test-Path -LiteralPath (Join-Path $DataDirectory "raw/$_")) })
    if ($MissingData.Count -gt 0) {
        if ($Offline) { throw 'MNIST files are missing. Offline startup will not download them.' }
        Write-Host 'First data preparation: MNIST will be downloaded over HTTPS and verified.'
    } else {
        Write-Host 'Verifying the existing local MNIST cache; no dataset download is needed.'
    }
    $SetupArguments = @('-B', (Join-Path $PSScriptRoot 'setup_environment.py'), '--runtime', $Runtime)
    if ($Offline) { $SetupArguments += '--offline' }
    if ($MnistSource) { $SetupArguments += @('--mnist-source', $MnistSource) }
    if ($CifarSource) { $SetupArguments += @('--cifar-source', $CifarSource) }
    Write-Host 'Preparing runtime dependencies, default development CRS, both datasets and the frontend before opening the application.'
    Invoke-DgflPython -Arguments $SetupArguments
    if ($SetupOnly) {
        Write-Host 'Deployment completed. Run this script with -Offline to start without further downloads.'
        exit 0
    }
    $DemoArguments = @('-m', 'dgfl.cli', 'demo', '--runtime', $Runtime)
    if ($null -ne $ClientCount) { $DemoArguments += @('--client-count', [string]$ClientCount) }
    if ($null -ne $AuthorityCount) { $DemoArguments += @('--authority-count', [string]$AuthorityCount) }
    if ($null -ne $AggregatorCount) { $DemoArguments += @('--aggregator-count', [string]$AggregatorCount) }
    if ($null -ne $AuthorityThreshold) { $DemoArguments += @('--authority-threshold', [string]$AuthorityThreshold) }
    if ($null -ne $AggregatorThreshold) { $DemoArguments += @('--aggregator-threshold', [string]$AggregatorThreshold) }
    if ($Machine) { $DemoArguments += @('--machine', $Machine) }
    Write-Host 'Starting DGFlow. Control page: http://127.0.0.1:8765'
    Write-Host 'After exiting the control page server, use python -m dgfl.cli stop to stop owned node processes.'
    Invoke-DgflPython -Arguments $DemoArguments
} catch {
    Write-Error -Message $_ -ErrorAction Continue
    exit 1
} finally {
    Pop-Location
}
