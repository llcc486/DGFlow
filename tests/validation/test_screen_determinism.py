"""Boundary scores must produce the same signed approval in every process."""
import itertools
import json
import os
import subprocess
import sys
from pathlib import Path

from dgfl.validation import policy


def test_clustering_center_at_strict_boundary_is_stable_under_input_order():
    pairs = [("client1", .24999999999999994), ("client2", .24999999999999994),
             ("client3", .25), ("client4", .25), ("client5", .8), ("client6", .8)]
    for order in itertools.permutations(pairs):
        assert policy.select(dict(order)) == {"client5", "client6"}


def test_unchanged_exact_threshold_rules():
    equal = {"low1": .25, "low2": .25, "high1": .8, "high2": .8}
    assert policy.select(equal) == set(equal)
    assert policy.select({"low1": 0., "low2": 0., "high1": .45, "high2": .45}) == {"high1", "high2"}


def test_fixed_batches_agree_across_process_hash_seeds():
    root = Path(policy.__file__).resolve().parents[2]
    code = """
import json
from dgfl.validation import policy
scores = {'client1': .24999999999999994, 'client2': .24999999999999994,
          'client3': .25, 'client4': .25, 'client5': .8, 'client6': .8}
selected, _ = policy.screen(scores, dict.fromkeys(scores, 100), policy.SCREENING_DEFAULTS)
print(json.dumps(policy.apply_batches(selected, 6)))
"""
    for seed in (1, 2, 3, 4, 11, 16):
        environment = dict(os.environ, PYTHONHASHSEED=str(seed), OPENBLAS_NUM_THREADS="1")
        paths = [str(root), *[entry for entry in sys.path if "site-packages" in entry]]
        environment["PYTHONPATH"] = os.pathsep.join(paths)
        result = subprocess.run([sys.executable, "-B", "-c", code], env=environment,
                                capture_output=True, text=True, check=True)
        assert json.loads(result.stdout) == ["client5", "client6"]
