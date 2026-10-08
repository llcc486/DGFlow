"""Reproduce the small real-MNIST learning smoke test (not a research result).

From the project root:
    .venv/Scripts/python.exe tests/training/run_mnist_smoke.py --prepare
Omit --prepare for an entirely offline run using previously verified archives.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from dgfl.training.data import load_mnist, partition_clients, prepare_mnist
from dgfl.training.model import average_models, evaluate, initial_model, train_local


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("data/mnist"))
    parser.add_argument("--prepare", action="store_true", help="Explicitly permit MNIST download")
    arguments = parser.parse_args()
    if arguments.prepare:
        metadata = prepare_mnist(arguments.data_dir)
        (arguments.data_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    x, y, test_x, test_y = load_mnist(arguments.data_dir, train_limit=1200, test_limit=400)
    weights = initial_model(seed=42)
    initial = evaluate(weights, test_x, test_y)
    parts = partition_clients(y, clients=6, seed=42)
    history = []
    for round_number in range(5):
        local = [train_local(weights, x[ids], y[ids], epochs=2, learning_rate=.3,
                             batch_size=64, seed=42 + round_number, backend="numpy") for ids in parts]
        weights = average_models(local)
        history.append({"round": round_number + 1, **evaluate(weights, test_x, test_y)})
    result = {"dataset": "MNIST", "backend": "numpy", "seed": 42, "train_samples": len(y),
              "test_samples": len(test_y), "clients": 6, "rounds": 5, "local_epochs": 2,
              "learning_rate": .3, "batch_size": 64, "initial": initial,
              "history": history, "final": history[-1]}
    (arguments.data_dir / "smoke-result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    if history[-1]["loss"] >= initial["loss"] or history[-1]["accuracy"] <= initial["accuracy"]:
        raise RuntimeError("The real-MNIST smoke run did not improve over initialization")


if __name__ == "__main__":
    main()
