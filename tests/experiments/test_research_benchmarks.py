"""Research evidence must not silently skip validation under Python -O."""
import subprocess
import sys
from pathlib import Path


def test_crypto_benchmark_rejects_optimized_python_before_publishing(tmp_path):
    root = Path(__file__).resolve().parents[2]
    output = tmp_path / 'unverified.json'
    result = subprocess.run(
        [sys.executable, '-O', str(root/'scripts/benchmark_crypto.py'),
         '--dimensions', '1', '--repeats', '1', '--output', str(output)],
        cwd=root, capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert 'optimized Python' in result.stderr
    assert not output.exists()
