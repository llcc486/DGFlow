import importlib.util
import json
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


@pytest.fixture
def source_with_generated_materials(source):
    contents = {
        'docs/setup.md': '# Source setup\nBuild the frontend before starting.\n',
        'configs/demo.yaml': 'cases: []\n',
        'scripts/check.py': 'print("source fixture")\n',
        'tests/test_example.py': 'def test_example():\n    assert True\n',
        '.github/workflows/check.yml': 'name: check\non: push\n',
        'web/package.json': '{"name":"source-fixture","private":true}\n',
        'web/package-lock.json': '{"name":"source-fixture","lockfileVersion":3}\n',
        'offline/manifest.json': '{"schema_version":1,"files":[]}\n',
        'offline/data/mnist/raw/train-images-idx3-ubyte.gz': 'public offline archive fixture',
        'source-history.bundle': '# v2 git bundle\noriginal history fixture\n',
        'data/mnist/raw/train-images-idx3-ubyte.gz': 'local public data fixture',
        '.venv/pyvenv.cfg': 'home = fixture-python\n',
    }
    for name, content in contents.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf8')
    return source


def test_source_only_archive_contains_source_inputs_and_excludes_all_generated_materials(source_with_generated_materials):
    root = source_with_generated_materials
    archive = root / 'dist' / 'pure-source' / 'source.zip'
    manifest = module.freeze(root, archive=archive, source_only=True)
    assert manifest['scope']['source_only'] is True
    assert manifest['scope']['built_frontend_included'] is False
    assert module.verify(root) == manifest
    required = {'README.md', 'SOURCE-PACKAGE.md', 'pyproject.toml', 'src/dgfl/main.py',
                'native/dgfl-native/src/lego.rs', 'native/dgfl-native/Cargo.lock',
                'web/src/Comparison.vue', 'web/tests/cache.test.js', 'web/package.json', 'web/package-lock.json',
                'docs/setup.md', 'configs/demo.yaml', 'tests/test_example.py', 'scripts/check.py',
                '.github/workflows/check.yml'}
    with zipfile.ZipFile(archive) as output:
        names = set(output.namelist())
        assert required <= names
        assert names == {entry['path'] for entry in manifest['files']} | {'SOURCE-MANIFEST.json'}
        assert json.loads(output.read('SOURCE-MANIFEST.json')) == manifest
        assert 'source-history.bundle' not in names
        assert not any(name.startswith(('web/dist/', 'offline/', 'data/', '.venv/', 'runtime/',
                                        'web/node_modules/', 'native/dgfl-native/target/')) for name in names)
    assert (archive.parent / 'SHA256SUMS.txt').read_text().endswith('  source.zip\n')


@pytest.mark.parametrize('change', ['edit', 'delete', 'add'])
def test_source_only_verification_ignores_generated_material_changes(source_with_generated_materials, change):
    root = source_with_generated_materials
    manifest = module.freeze(root, source_only=True)
    generated = ('web/dist/assets/current.js', 'offline/manifest.json',
                 'offline/data/mnist/raw/train-images-idx3-ubyte.gz', 'source-history.bundle',
                 'data/mnist/raw/train-images-idx3-ubyte.gz', '.venv/pyvenv.cfg',
                 'runtime/keys/private.key', 'web/node_modules/dependency.js',
                 'native/dgfl-native/target/build.exe')
    for name in generated:
        path = root / name
        if change == 'edit':
            path.write_text('generated material changed', encoding='utf8')
        elif change == 'delete':
            path.unlink()
        else:
            (path.parent / 'new-generated.bin').write_bytes(b'new build or cache output')
    # verify derives the collection mode from the saved manifest; callers do
    # not need to remember or repeat the source-only option.
    assert module.verify(root) == manifest


@pytest.mark.parametrize('change', ['edit', 'delete', 'add'])
def test_source_only_verification_still_rejects_source_changes(source_with_generated_materials, change):
    root = source_with_generated_materials
    module.freeze(root, source_only=True)
    path = root / 'src/dgfl/main.py'
    if change == 'edit':
        path.write_text('changed source implementation', encoding='utf8')
    elif change == 'delete':
        path.unlink()
    else:
        (path.parent / 'new_source.py').write_text('new implementation', encoding='utf8')
    with pytest.raises(ValueError, match='changed'):
        module.verify(root)


def test_default_freeze_keeps_frontend_offline_and_history_materials(source_with_generated_materials):
    root = source_with_generated_materials
    archive = root / 'dist' / 'default-source' / 'source.zip'
    manifest = module.freeze(root, archive=archive)
    assert manifest['scope']['built_frontend_included'] is True
    with zipfile.ZipFile(archive) as output:
        names = set(output.namelist())
        assert {'web/dist/assets/current.js', 'offline/manifest.json',
                'offline/data/mnist/raw/train-images-idx3-ubyte.gz', 'source-history.bundle'} <= names
    assert module.verify(root) == manifest


def test_cli_source_only_archive_and_automatic_manifest_verification(source_with_generated_materials, capsys):
    root = source_with_generated_materials
    archive = root / 'dist' / 'cli-source' / 'source.zip'
    assert module.main(['--root', str(root), '--source-only', '--archive', str(archive)]) == 0
    created = json.loads(capsys.readouterr().out)
    manifest = module.verify(root)
    assert manifest['scope']['source_only'] is True
    assert manifest['scope']['built_frontend_included'] is False
    assert created['snapshot_sha256'] == manifest['snapshot_sha256']
    with zipfile.ZipFile(archive) as output:
        assert 'src/dgfl/main.py' in output.namelist()
        assert 'web/dist/assets/current.js' not in output.namelist()
    (root / 'web/dist/assets/current.js').write_text('new generated frontend', encoding='utf8')
    assert module.main(['--root', str(root), '--verify']) == 0
    assert json.loads(capsys.readouterr().out)['snapshot_sha256'] == created['snapshot_sha256']


# --- Machine-identity content scan -------------------------------------------
#
# Archived test reports and evidence JSON are delivered, and the tools that wrote
# them recorded the machine they ran on. These cases pin both directions: real
# identifiers fail the freeze, and the synthetic fixture shapes the project
# deliberately ships do not.

HOSTNAME = 'DESKTOP-' + 'GT1VP52'
PERSONAL_WINDOWS = 'C:' + chr(92) + 'Users' + chr(92) + 'someone' + chr(92) + 'project'
PERSONAL_POSIX = '/' + 'home/someone/project'
PYTEST_ROOT = 'pytest-of-' + 'someone'


def scan_of(root):
    return module.scan_identifiers(module.collect(root), root, hostnames={HOSTNAME.lower()})


@pytest.mark.parametrize('content', [
    PERSONAL_WINDOWS,
    PERSONAL_POSIX,
    PYTEST_ROOT,
    '"hostname": "' + HOSTNAME + '"',
])
def test_delivered_machine_identifiers_fail_the_freeze(source_with_generated_materials, content):
    (source_with_generated_materials / 'docs' / 'report.txt').write_text(content + '\n', encoding='utf8')
    findings, _unscannable = scan_of(source_with_generated_materials)
    assert findings, f'{content!r} must be reported'
    with pytest.raises(ValueError, match='Machine-identifying content'):
        module.freeze(source_with_generated_materials)


def test_delivered_identity_scan_names_the_offending_file(source_with_generated_materials):
    root = source_with_generated_materials
    (root / 'docs' / 'leak.json').write_text('{"root": "' + PERSONAL_WINDOWS + '"}\n', encoding='utf8')
    findings, _unscannable = scan_of(root)
    assert {entry['path'] for entry in findings} == {'docs/leak.json'}
    assert {entry['kind'] for entry in findings} == {'personal_windows_path'}


def test_exempt_drive_fixture_is_not_reported(source_with_generated_materials):
    """A drive root plus one invented name is a UI fixture, not a checkout."""
    root = source_with_generated_materials
    (root / 'web/tests/fixture.test.js').write_text(
        "const diskPath = 'C:/runtime'\n", encoding='utf8')
    findings, _unscannable = scan_of(root)
    assert findings == []


def test_third_party_attribution_hostname_is_not_our_machine(source_with_generated_materials):
    """Upstream authors' hostnames in a required notice are not our identity."""
    root = source_with_generated_materials
    (root / 'THIRD_PARTY_NOTICES.md').write_text(
        'Some Author <author@DESKTOP-OTHER99.localdomain>\n', encoding='utf8')
    findings, _unscannable = scan_of(root)
    assert findings == []


def test_local_hostname_in_prose_is_not_reported(source_with_generated_materials):
    """The identifier only matters as a recorded value, not as documentation."""
    root = source_with_generated_materials
    prose_host = 'DESKTOP-' + 'PROSEONLY1'
    (root / 'docs' / 'notes.md').write_text('The host ' + prose_host + ' ran the suite.\n', encoding='utf8')
    findings, _unscannable = module.scan_identifiers(module.collect(root), root,
                                                     hostnames={prose_host.lower(), HOSTNAME.lower()})
    assert findings == []


def test_undecodable_delivered_text_fails_instead_of_being_passed_over(source_with_generated_materials):
    root = source_with_generated_materials
    (root / 'docs' / 'report.txt').write_bytes(b'Broken text: \xff\xfe and more')
    with pytest.raises(ValueError, match='could not be content-scanned'):
        module.freeze(root)


def test_binary_delivery_is_listed_but_allowed(source_with_generated_materials):
    root = source_with_generated_materials
    (root / 'docs' / 'figure.png').write_bytes(b'\x89PNG\r\n\x1a\n\x00\x01\x02')
    manifest = module.freeze(root)
    listed = {entry['path'] for entry in manifest['content_scan']['not_text_scanned']}
    assert 'docs/figure.png' in listed
    assert manifest['content_scan']['violations'] == 0
    assert manifest['content_scan']['checked_files'] > 0


def test_manifest_records_the_content_scan_it_passed(source_with_generated_materials):
    manifest = module.freeze(source_with_generated_materials)
    scan = manifest['content_scan']
    assert scan['violations'] == 0
    assert scan['checked_files'] + len(scan['not_text_scanned']) == manifest['file_count']
    assert module.verify(source_with_generated_materials) == manifest


def test_scan_only_cli_reports_success_and_failure(source_with_generated_materials, capsys):
    root = source_with_generated_materials
    assert module.main(['--root', str(root), '--scan-only']) == 0
    assert 'OK:' in capsys.readouterr().out
    (root / 'docs' / 'leak.txt').write_text(PYTEST_ROOT + '\n', encoding='utf8')
    assert module.main(['--root', str(root), '--scan-only']) == 1
    assert PYTEST_ROOT in capsys.readouterr().out
