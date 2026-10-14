"""Real public CRS packaging, required by the native/Lego CI job.

The dependency-free packaging job checks archive boundaries separately. This
integration test needs a freshly built native extension to create and decode
actual proving keys, and must run without skips in the native/Lego job.
"""
import pytest
from test_prepare_full_offline import (
    clone_source,
    prepare,
    rehash,
)
from test_prepare_full_offline import (
    full as full,
)
from test_prepare_full_offline import (
    inputs as inputs,
)


def test_optional_public_crs_roundtrip_and_corruption_are_registry_checked(full, inputs, tmp_path):
    pytest.importorskip('dgfl_native')
    runtime = tmp_path/'parameter-runtime'
    registry = full.Registry(runtime)
    parameter = registry.create_development(3, 8, workers=1)
    (runtime/'proof-parameters/installation-check-20261008.json').write_text('{"local_check":true}')
    output, manifest = prepare(full, inputs, parameters_runtime=runtime)
    assert manifest['proof_parameters'] == [registry.describe(parameter['crs_hash'], 3, 8)]
    assert not any('installation-check' in entry['path'] for entry in manifest['files'])
    target = tmp_path/'with-parameters'
    clone_source(inputs, target)
    full.restore_assets(output, root=target, runtime=target/'other-runtime')
    copied = full.Registry(target/'other-runtime').describe(parameter['crs_hash'], 3, 8)
    assert copied['setup_kind'] == 'single_party_development'
    path = output/'parameters/proof-parameters'/parameter['crs_hash']/'pk.bin'
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(data)
    rehash(full, output, manifest)
    with pytest.raises(ValueError, match='proving key digest mismatch'):
        full.verify_full_offline(output)
