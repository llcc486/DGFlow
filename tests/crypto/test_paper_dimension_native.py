"""The loaded native prover must reject full paper CNNs before allocating CRS."""

import pytest


@pytest.mark.parametrize("dimension", [582026, 878538], ids=["mnist", "cifar10"])
def test_native_lego_independently_rejects_paper_dimension(dimension):
    native = pytest.importorskip("dgfl_native")
    with pytest.raises(ValueError, match="unsupported Lego dimension"):
        native.LegoProver.development_setup(dimension, 8, 1)
