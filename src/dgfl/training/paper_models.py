"""Full CNN training foundation matching the paper's reported parameter counts.

Architecture reference: PFLlib FedAvgCNN (TsingZ0/PFLlib, Apache-2.0),
https://github.com/TsingZ0/PFLlib/blob/master/system/flcore/trainmodel/models.py
This independent implementation is a reconstruction, not the authors' DGFlow
code. It is not connected to the existing 650-coordinate encrypted services.
"""
from __future__ import annotations

import hashlib
import json
import re
from numbers import Integral, Real

import numpy as np
import torch
from torch import nn

MODEL_SPECS = {
    "paper_cnn_mnist": {"input_shape": (1, 28, 28), "hidden_input": 1024, "dimension": 582026},
    "paper_cnn_cifar10": {"input_shape": (3, 32, 32), "hidden_input": 1600, "dimension": 878538},
}


def _positive_integer(value, name):
    if isinstance(value, bool) or not isinstance(value, Integral) or value < 1:
        raise ValueError(f"{name} must be a positive integer")


def _seed(value):
    if isinstance(value, bool) or not isinstance(value, Integral) or not 0 <= value < 2**32:
        raise ValueError("seed must be an integer in [0, 2**32)")
    return int(value)


def _device(device):
    if not isinstance(device, str):
        raise ValueError("device must be 'cpu', 'cuda', or 'cuda:N'")
    if device == "cpu":
        return torch.device("cpu")
    if re.fullmatch(r"cuda(?::(?:0|[1-9][0-9]*))?", device) is None:
        raise ValueError("device must be 'cpu', 'cuda', or 'cuda:N'")
    if not torch.cuda.is_available():
        raise ValueError("CUDA is unavailable; select CPU explicitly or provide a CUDA runtime/device")
    index = int(device.split(":")[1]) if ":" in device else 0
    if index >= torch.cuda.device_count():
        raise ValueError(f"CUDA device index {index} is unavailable")
    return torch.device(f"cuda:{index}")


class PaperCNN(nn.Module):
    """Two convolution/pooling stages and two fully connected layers."""

    def __init__(self, model_name):
        super().__init__()
        if model_name not in MODEL_SPECS:
            raise ValueError("unknown paper model")
        self.model_name = model_name
        spec = MODEL_SPECS[model_name]
        self.conv1 = nn.Conv2d(spec["input_shape"][0], 32, 5, dtype=torch.float32)
        self.relu1 = nn.ReLU()
        self.pool1 = nn.MaxPool2d(2)
        self.conv2 = nn.Conv2d(32, 64, 5, dtype=torch.float32)
        self.relu2 = nn.ReLU()
        self.pool2 = nn.MaxPool2d(2)
        self.fc1 = nn.Linear(spec["hidden_input"], 512, dtype=torch.float32)
        self.relu3 = nn.ReLU()
        self.fc2 = nn.Linear(512, 10, dtype=torch.float32)

    def forward(self, x):
        x = self.pool1(self.relu1(self.conv1(x)))
        x = self.pool2(self.relu2(self.conv2(x)))
        return self.fc2(self.relu3(self.fc1(torch.flatten(x, 1))))


def build_model(model_name: str, *, seed: int = 42, device: str = "cpu") -> PaperCNN:
    """Initialize on CPU without changing its global RNG, then move explicitly."""
    seed, target = _seed(seed), _device(device)
    with torch.random.fork_rng(devices=[]):
        torch.random.default_generator.manual_seed(seed)
        model = PaperCNN(model_name)
    return model.to(target)


def model_manifest(model: PaperCNN) -> dict:
    """Describe ordered float32 tensors and actual layer options with SHA-256.

The architecture hash excludes values, seed, device, and train/eval mode. It
binds tensor names/order/shapes/dtypes and forward layer settings. This hash is
an interoperability check, not proof of honest execution by a remote trainer.
"""
    if type(model) is not PaperCNN or model.model_name not in MODEL_SPECS:
        raise ValueError("unsupported model architecture")
    parameters = []
    for name, value in model.named_parameters():
        if value.dtype != torch.float32:
            raise ValueError("model parameters must have dtype float32")
        parameters.append({"name": name, "shape": list(value.shape), "numel": value.numel(),
                           "dtype": "float32"})
    layers = []
    for name, layer in model.named_children():
        config = {"name": name, "type": type(layer).__name__}
        if type(layer) is nn.Conv2d:
            config.update(in_channels=layer.in_channels, out_channels=layer.out_channels,
                          kernel_size=list(layer.kernel_size), stride=list(layer.stride),
                          padding=list(layer.padding), dilation=list(layer.dilation),
                          groups=layer.groups, bias=layer.bias is not None,
                          padding_mode=layer.padding_mode)
        elif type(layer) is nn.Linear:
            config.update(in_features=layer.in_features, out_features=layer.out_features,
                          bias=layer.bias is not None)
        elif type(layer) is nn.ReLU:
            config["inplace"] = layer.inplace
        elif type(layer) is nn.MaxPool2d:
            config.update(kernel_size=layer.kernel_size, stride=layer.stride,
                          padding=layer.padding, dilation=layer.dilation,
                          ceil_mode=layer.ceil_mode, return_indices=layer.return_indices)
        else:
            raise ValueError("unsupported layer in model architecture")
        layers.append(config)
    manifest = {"schema": "dgflow-paper-model-v1", "model_name": model.model_name,
                "input_shape": list(MODEL_SPECS[model.model_name]["input_shape"]),
                "dtype": "float32", "flatten_order": "named_parameters/C",
                "dimension": sum(item["numel"] for item in parameters),
                "parameters": parameters, "layers": layers}
    serialized = json.dumps(manifest, sort_keys=True, separators=(",", ":"), allow_nan=False)
    manifest["architecture_hash"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return manifest


def flatten_parameters(model: PaperCNN) -> np.ndarray:
    """Export a finite contiguous owned float32 vector of every trainable layer."""
    model_manifest(model)
    values = torch.cat([parameter.detach().reshape(-1).cpu() for parameter in model.parameters()])
    result = values.numpy().copy()
    if not np.isfinite(result).all():
        raise ValueError("model parameters must be finite")
    return result


def load_parameters(model: PaperCNN, values: np.ndarray, *, architecture_hash: str) -> None:
    """Validate the complete packet before modifying any model parameter."""
    manifest = model_manifest(model)
    if architecture_hash != manifest["architecture_hash"]:
        raise ValueError("model architecture hash mismatch")
    if not isinstance(values, np.ndarray) or values.dtype != np.float32:
        raise TypeError("parameter vector must be a float32 numpy array")
    if values.shape != (manifest["dimension"],) or not np.isfinite(values).all():
        raise ValueError("parameter vector has wrong dimension or nonfinite values")
    offset = 0
    with torch.no_grad():
        for parameter in model.parameters():
            count = parameter.numel()
            source = torch.from_numpy(values[offset:offset + count].copy()).reshape(parameter.shape)
            parameter.copy_(source.to(parameter.device))
            offset += count


def train_local(model_name: str, weights: np.ndarray, *, architecture_hash: str,
                x: np.ndarray, y: np.ndarray, epochs: int = 1,
                learning_rate: float = 0.01, batch_size: int = 64,
                seed: int = 42, device: str = "cpu") -> np.ndarray:
    """Train every CNN layer with mini-batch SGD and return the entire model.

Inputs are preprocessed NCHW float32 samples and integer labels [0, 9]. No
download, preprocessing, quantization, parameter freezing, or device fallback
is implicit. The caller controls preprocessing and the training data split.
There is no momentum, weight decay, or learning-rate scheduling in this API.
CPU inputs remain on CPU; only the current mini-batch is copied to the device.
"""
    _positive_integer(epochs, "epochs")
    _positive_integer(batch_size, "batch_size")
    if isinstance(learning_rate, bool) or not isinstance(learning_rate, Real) or not np.isfinite(learning_rate) or learning_rate <= 0:
        raise ValueError("learning_rate must be finite and positive")
    seed = _seed(seed)
    model = build_model(model_name, seed=seed, device=device)
    load_parameters(model, weights, architecture_hash=architecture_hash)
    input_shape = MODEL_SPECS[model_name]["input_shape"]
    if not isinstance(x, np.ndarray) or x.dtype != np.float32:
        raise TypeError("training samples must be a float32 numpy array")
    if x.ndim != 4 or x.shape[1:] != input_shape or len(x) == 0 or not np.isfinite(x).all():
        raise ValueError("training samples must have finite nonempty NCHW model input shape")
    if (not isinstance(y, np.ndarray) or y.shape != (len(x),) or y.dtype.kind not in "iu"
            or np.any(y < 0) or np.any(y > 9)):
        raise ValueError("labels must be a matching integer vector in [0, 9]")
    target = next(model.parameters()).device
    # Values are validated above. Convert once, then advanced indexing owns
    # each batch, preserving the original labels and the SGD batch ordering.
    labels_int64 = y.astype(np.int64, copy=True)
    generator = np.random.default_rng(seed)
    optimizer = torch.optim.SGD(model.parameters(), lr=float(learning_rate))
    model.train()
    for _ in range(epochs):
        order = generator.permutation(len(y))
        for start in range(0, len(y), batch_size):
            indices = order[start:start + batch_size]
            samples = torch.from_numpy(np.ascontiguousarray(x[indices])).to(target)
            labels = torch.from_numpy(labels_int64[indices]).to(target)
            optimizer.zero_grad(set_to_none=True)
            loss = nn.functional.cross_entropy(model(samples), labels)
            if not torch.isfinite(loss).item():
                raise ValueError("training produced a nonfinite loss")
            loss.backward()
            optimizer.step()
    return flatten_parameters(model)
