param([string]$Python = '.venv/Scripts/python.exe', [string]$WheelDirectory = 'native/wheels')
$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $project
try {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        $localCargo = Join-Path $project 'tmp/native-toolchain/cargo'
        $localRustup = Join-Path $project 'tmp/native-toolchain/rustup'
        if (-not (Test-Path -LiteralPath (Join-Path $localCargo 'bin/cargo.exe'))) {
            throw 'Install the Rust MSVC toolchain and Visual Studio C++ build tools first.'
        }
        $env:CARGO_HOME = $localCargo
        $env:RUSTUP_HOME = $localRustup
        $env:PATH = (Join-Path $localCargo 'bin') + ';' + $env:PATH
    }
    & $Python -m maturin build --locked --release --manifest-path native/dgfl-native/Cargo.toml --interpreter $Python --out $WheelDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Native build failed.' }
    $wheels = Get-ChildItem -LiteralPath $WheelDirectory -Filter 'dgfl_native-*.whl' | Sort-Object LastWriteTime -Descending
    if (-not $wheels) { throw 'Native wheel missing.' }
    if (Get-Command uv -ErrorAction SilentlyContinue) {
        & uv pip install --python $Python --no-index --no-deps $wheels[0].FullName
    } else {
        & $Python -m pip install --no-index --no-deps $wheels[0].FullName
    }
    if ($LASTEXITCODE -ne 0) { throw 'Native installation failed.' }
} finally { Pop-Location }
