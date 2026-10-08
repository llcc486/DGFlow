import importlib.util
import zipfile
from pathlib import Path

import pytest

spec=importlib.util.spec_from_file_location('freeze_source',Path(__file__).resolve().parents[2]/'scripts/freeze_source.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture
def source(tmp_path):
    for name in ('README.md','pyproject.toml','SOURCE-PACKAGE.md','src/dgfl/main.py',
                 'native/dgfl-native/src/lego.rs','native/dgfl-native/src/aggregate.rs','native/dgfl-native/src/batch.rs',
                 'native/dgfl-native/Cargo.lock',
                 'web/dist/assets/current.js','web/tests/cache.test.js','web/src/Comparison.vue'):
        path=tmp_path/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(name)
    for name in ('runtime/keys/private.key','src/dgfl/__pycache__/main.pyc',
                 'docs/DGFlow.pdf','docs/DGFlow-指导论文.pdf',
                 'native/dgfl-native/target/build.exe','web/node_modules/dependency.js'):
        path=tmp_path/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_text('excluded')
    return tmp_path


def test_freeze_archives_current_native_and_frontend_and_excludes_runtime(source):
    archive=source/'dist/release/source.zip'
    manifest=module.freeze(source,archive=archive)
    assert module.verify(source)==manifest
    assert manifest['commit'] is None
    with zipfile.ZipFile(archive) as output:
        names=set(output.namelist())
        assert 'native/dgfl-native/src/lego.rs' in names
        assert 'native/dgfl-native/src/aggregate.rs' in names
        assert 'native/dgfl-native/src/batch.rs' in names
        assert 'web/dist/assets/current.js' in names and 'SOURCE-MANIFEST.json' in names
        assert not any('private' in name or 'node_modules' in name or '__pycache__' in name for name in names)
        assert 'docs/DGFlow.pdf' not in names and 'docs/DGFlow-指导论文.pdf' not in names
    assert (archive.parent/'SHA256SUMS.txt').read_text().endswith('  source.zip\n')


@pytest.mark.parametrize('change',['edit','delete','add'])
def test_verification_detects_changed_missing_and_unlisted_delivery_files(source,change):
    module.freeze(source)
    path=source/'web/dist/assets/current.js'
    if change=='edit': path.write_text('changed')
    elif change=='delete': path.unlink()
    else: (path.parent/'new.js').write_text('new')
    with pytest.raises(ValueError,match='changed'): module.verify(source)


def test_current_manifest_cannot_claim_an_old_git_commit(source):
    first=module.freeze(source)
    (source/'src/dgfl/main.py').write_text('new implementation')
    second=module.freeze(source)
    assert first['snapshot_sha256']!=second['snapshot_sha256']
    assert first['base_commit']==second['base_commit'] and second['commit'] is None
