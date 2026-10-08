#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
offline=false
setup_only=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --offline) offline=true ;;
        --setup-only) setup_only=true ;;
        *) echo 'Usage: bash scripts/start_demo.sh [--offline] [--setup-only]' >&2; exit 2 ;;
    esac
    shift
done
runtime="${DGFL_RUNTIME:-$project_root/runtime}"
client_count="${DGFL_CLIENT_COUNT:-}"
authority_count="${DGFL_AUTHORITY_COUNT:-}"
aggregator_count="${DGFL_AGGREGATOR_COUNT:-}"
authority_threshold="${DGFL_AUTHORITY_THRESHOLD:-}"
aggregator_threshold="${DGFL_AGGREGATOR_THRESHOLD:-}"
validate_count() {
    local value="$1" label="$2" maximum="$3"
    if [[ -n "$value" ]] && { [[ ! "$value" =~ ^([2-9]|[1-9][0-9]|100)$ ]] || (( 10#$value > maximum )); }; then
        echo "$label must be an integer from 2 to $maximum." >&2
        exit 2
    fi
}
validate_count "$client_count" DGFL_CLIENT_COUNT 100
validate_count "$authority_count" DGFL_AUTHORITY_COUNT 32
validate_count "$aggregator_count" DGFL_AGGREGATOR_COUNT 32
validate_count "$authority_threshold" DGFL_AUTHORITY_THRESHOLD 32
validate_count "$aggregator_threshold" DGFL_AGGREGATOR_THRESHOLD 32
environment_root="$project_root/.venv"
if [[ -n "${DGFL_PYTHON_PATH:-}" ]]; then
    dgfl_python="$DGFL_PYTHON_PATH"
else
    dgfl_python="$environment_root/bin/python"
    if [[ ! -x "$dgfl_python" ]]; then
        if $offline; then
            echo 'Offline setup requires an existing Python environment. Run once without --offline.' >&2
            exit 1
        fi
        python3 -m venv "$environment_root"
    fi
fi
"$dgfl_python" -c 'import sys; sys.exit("Locked deployment requires Python 3.12 or newer; Python 3.12 is recommended") if sys.version_info < (3,12) else None'
lock_file="$project_root/requirements-lock.txt"
# Bind the project stamp to this interpreter and venv; all stored fields are ASCII hashes.
fingerprint="$("$dgfl_python" -c 'import hashlib,pathlib,sys; identity="\0".join(str(pathlib.Path(p).resolve()) for p in (sys.executable,sys.prefix)); print(hashlib.sha256(identity.encode("utf-8")).hexdigest()+"".join(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in sys.argv[1:] if pathlib.Path(p).exists()))' "$project_root/pyproject.toml" "$lock_file")"
stamp_file="$environment_root/dgflow-install.sha256"
installed_fingerprint=''
if [[ -f "$stamp_file" ]]; then installed_fingerprint="$(cat "$stamp_file")"; fi
if ! $offline && [[ "$installed_fingerprint" != "$fingerprint" ]]; then
    echo 'First setup or changed dependencies: pip may access the network.'
    if [[ -f "$lock_file" ]]; then
        "$dgfl_python" -B "$project_root/scripts/deployment_downloads.py" --root "$project_root" pip-install -- --only-binary=:all: -r "$lock_file"
        "$dgfl_python" -m pip install --no-index --no-build-isolation --no-deps -e "$project_root"
    else
        "$dgfl_python" -B "$project_root/scripts/deployment_downloads.py" --root "$project_root" pip-install -- -e "$project_root"
    fi
fi
"$dgfl_python" -m pip check
"$dgfl_python" -c 'import numpy, fastapi, uvicorn, httpx, cryptography, yaml, psutil, py_arkworks_bls12381, dgfl.cli'
if ! $offline; then
    mkdir -p "$environment_root"
    printf '%s\n' "$fingerprint" > "$stamp_file"
fi
data_directory="$("$dgfl_python" -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve().parent / "data" / "mnist")' "$runtime")"
missing_data=false
for archive in train-images-idx3-ubyte.gz train-labels-idx1-ubyte.gz t10k-images-idx3-ubyte.gz t10k-labels-idx1-ubyte.gz; do
    if [[ ! -f "$data_directory/raw/$archive" ]]; then missing_data=true; fi
done
if $missing_data; then
    if $offline; then
        echo 'MNIST files are missing. Offline startup will not download them.' >&2
        exit 1
    fi
    echo 'First data preparation: MNIST will be downloaded over HTTPS and verified.'
else
    echo 'Verifying the existing local MNIST cache; no dataset download is needed.'
fi
setup_arguments=(-B "$project_root/scripts/setup_environment.py" --runtime "$runtime")
if $offline; then setup_arguments+=(--offline); fi
if [[ -n "${DGFL_MNIST_SOURCE:-}" ]]; then setup_arguments+=(--mnist-source "$DGFL_MNIST_SOURCE"); fi
if [[ -n "${DGFL_CIFAR_SOURCE:-}" ]]; then setup_arguments+=(--cifar-source "$DGFL_CIFAR_SOURCE"); fi
echo 'Preparing all runtime dependencies, both datasets and the frontend before opening the application.'
"$dgfl_python" "${setup_arguments[@]}"
if $setup_only; then
    echo 'Deployment completed. Run this script with --offline to start without further downloads.'
    exit 0
fi
demo_arguments=(-m dgfl.cli demo --runtime "$runtime")
if [[ -n "$client_count" ]]; then demo_arguments+=(--client-count "$client_count"); fi
if [[ -n "$authority_count" ]]; then demo_arguments+=(--authority-count "$authority_count"); fi
if [[ -n "$aggregator_count" ]]; then demo_arguments+=(--aggregator-count "$aggregator_count"); fi
if [[ -n "$authority_threshold" ]]; then demo_arguments+=(--authority-threshold "$authority_threshold"); fi
if [[ -n "$aggregator_threshold" ]]; then demo_arguments+=(--aggregator-threshold "$aggregator_threshold"); fi
if [[ -n "${DGFL_MACHINE:-}" ]]; then demo_arguments+=(--machine "$DGFL_MACHINE"); fi
echo 'Starting DGFlow. Control page: http://127.0.0.1:8765'
echo 'After exiting the control page server, use python -m dgfl.cli stop to stop owned node processes.'
exec "$dgfl_python" "${demo_arguments[@]}"
