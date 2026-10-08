"""Submission boundary tests use actual files and inspect the produced ZIP."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import struct
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "package_submission.py"


@pytest.fixture
def packager():
    assert SCRIPT.is_file(), "The whitelist submission packager is not implemented"
    spec = importlib.util.spec_from_file_location("submission_packager_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    files = {
        "README.md": "# Anonymous submission\nInstallation instructions.\n",
        "pyproject.toml": '[project]\nname = "submission"\nversion = "0.1.0"\n',
        "src/dgfl/__init__.py": '"""Application package."""\n',
        "src/dgfl/train.py": "def train():\n    return 1\n",
        "tests/test_train.py": "def test_training():\n    assert True\n",
        "configs/demo.yaml": "clients: 6\n",
        "web/dist/index.html": "<!doctype html><title>Application</title>",
        "web/src/App.vue": "<template><main>Application</main></template>\n",
        "web/package.json": '{"name":"frontend","scripts":{"build":"vite build"}}\n',
        "web/package-lock.json": '{"lockfileVersion":3}\n',
        "web/index.html": '<div id="app"></div>\n',
        "web/vite.config.js": 'export default {}\n',
        "requirements-lock.txt": "numpy==2.5.3\n",
        "THIRD_PARTY_NOTICES.md": "Third-party author: Yann LeCun\nUniversity attribution retained.\nLicense: CC-BY-SA-3.0\n",
        "docs/submission/design-report.md": "# Design report\nAnonymous system description.\n",
        "docs/protocol/design.md": "# Protocol\nPublic reference discussion.\n",
        "scripts/package_submission.py": "# Explicitly allowlisted packaging script\n",
    }
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def test_whitelist_and_manifest_match_actual_zip_bytes(packager, project):
    for name in ["DGFlow.pdf", "development-plan.md", ".venv/secret.txt", ".git/config",
                 ".superpowers/brief.md", "tmp/debug.txt", "runtime/identity.json",
                 "data/mnist/raw.gz", "node_modules/module.js", "web/node_modules/module.js",
                 "scripts/unknown_tool.py",
                 "tests/data/identity.json", "tests/__pycache__/test.pyc",
                 "src/dgfl/__pycache__/module.pyc", "configs/node_modules/private.pem"]:
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("excluded fixture", encoding="utf-8")
    output = project / "dist/submission"
    result = packager.build_package(project, output)
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert result == manifest
    zip_bytes = (output / "source.zip").read_bytes()
    assert manifest["archive"]["sha256"] == hashlib.sha256(zip_bytes).hexdigest()
    assert manifest["archive"]["size"] == len(zip_bytes)
    with zipfile.ZipFile(output / "source.zip") as archive:
        entries = {entry["path"]: entry for entry in manifest["files"]}
        assert set(archive.namelist()) == set(entries)
        assert set(entries) == {
            "README.md", "pyproject.toml", "src/dgfl/__init__.py", "src/dgfl/train.py",
            "tests/test_train.py", "configs/demo.yaml", "web/dist/index.html", "requirements-lock.txt",
            "web/src/App.vue", "web/package.json", "web/package-lock.json", "web/index.html", "web/vite.config.js",
            "THIRD_PARTY_NOTICES.md", "docs/submission/design-report.md", "docs/protocol/design.md",
            "scripts/package_submission.py",
        }
        for name, metadata in entries.items():
            payload = archive.read(name)
            assert metadata["size"] == len(payload)
            assert metadata["sha256"] == hashlib.sha256(payload).hexdigest()
        assert b"Yann LeCun" in archive.read("THIRD_PARTY_NOTICES.md")
    assert manifest["file_count"] == len(entries)
    assert manifest["uncompressed_bytes"] == sum(item["size"] for item in entries.values())
    assert output.joinpath("source.zip").stat().st_size + output.joinpath("manifest.json").stat().st_size < 4 * 1024**3
    assert str(project) not in json.dumps(manifest)


def test_complete_deployment_inputs_are_packaged_with_their_actual_content(packager, project):
    source_root = SCRIPT.parents[1]
    required = ("requirements-gpu.txt", "scripts/setup_environment.py", "scripts/deployment_native.py",
                "src/dgfl/crypto/gpu.py", "tests/crypto/test_gpu_detection.py",
                "src/dgfl/experiments/hardware.py", "tests/integration/test_training_backends.py")
    required += tuple(path.relative_to(source_root).as_posix()
                      for path in sorted((source_root / "src/dgfl/crypto/cuda").glob("*.cuh")))
    for relative in required:
        target = project / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source_root / relative).read_bytes())

    output = project / "dist/submission"
    manifest = packager.build_package(project, output)
    assert not set(required).intersection(manifest["missing_optional_paths"])
    with zipfile.ZipFile(output / "source.zip") as archive:
        for relative in required:
            assert archive.read(relative) == (source_root / relative).read_bytes()


@pytest.mark.parametrize("suffix", [".cu", ".cuh"])
def test_cuda_sources_are_text_scanned_before_packaging(packager, project, suffix):
    target = project / "src/dgfl/crypto/cuda" / ("kernel" + suffix)
    target.parent.mkdir(parents=True, exist_ok=True)
    source = 'extern "C" __global__ void kernel() {}\n'
    target.write_text(source, encoding="utf8")
    output = project / "dist/submission"
    packager.build_package(project, output)
    with zipfile.ZipFile(output / "source.zip") as archive:
        assert archive.read(target.relative_to(project).as_posix()) == target.read_bytes()

    target.write_text(source + "// " + str(project / "private") + "\n", encoding="utf8")
    with pytest.raises(ValueError, match="development path"):
        packager.build_package(project, output)


def test_frontend_source_checksum_is_packaged_and_text_scanned(packager, project):
    stamp = project / "web/dist/source.sha256"
    stamp.write_text(hashlib.sha256(b"frontend source fixture").hexdigest() + "\n", encoding="ascii")
    output = project / "dist/submission"
    packager.build_package(project, output)
    with zipfile.ZipFile(output / "source.zip") as archive:
        assert archive.read("web/dist/source.sha256") == stamp.read_bytes()

    stamp.write_text(str(project / "private") + "\n", encoding="utf8")
    with pytest.raises(ValueError, match="development path"):
        packager.build_package(project, output)


@pytest.mark.parametrize("required", ["README.md", "pyproject.toml", "src/dgfl", "docs/submission/design-report.md"])
def test_missing_critical_input_fails_without_empty_package(packager, project, required):
    target = project / required
    target.rename(target.with_name(target.name + ".absent"))
    output = project / "dist/submission"
    with pytest.raises(ValueError, match="[Mm]issing|required"):
        packager.build_package(project, output)
    assert not (output / "source.zip").exists()


def test_empty_source_and_empty_report_are_not_valid_submissions(packager, project):
    (project / "src/dgfl/__init__.py").unlink()
    (project / "src/dgfl/train.py").unlink()
    with pytest.raises(ValueError, match="source|src"):
        packager.build_package(project, project / "dist/submission")
    (project / "src/dgfl/__init__.py").write_text("pass", encoding="utf-8")
    (project / "docs/submission/design-report.md").write_text(" \n", encoding="utf-8")
    with pytest.raises(ValueError, match="empty|report"):
        packager.build_package(project, project / "dist/submission")


@pytest.mark.parametrize("name", ["configs/identity.json", "src/dgfl/private-key.json", "configs/client.key",
                                  "configs/server.crt", "configs/server.pem", "configs/id_ed25519",
                                  "configs/credentials.json", "configs/.env"])
def test_sensitive_files_inside_whitelist_fail_closed(packager, project, name):
    (project / name).write_text("sensitive fixture", encoding="utf-8")
    with pytest.raises(ValueError, match="[Ss]ensitive|private|identity|certificate"):
        packager.build_package(project, project / "dist/submission")


@pytest.mark.parametrize("name,content", [
    ("configs/ordinary.txt", "-----BEGIN " + "PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----\n"),
    ("configs/ordinary.json", '{"private_key": "secret-material"}'),
    ("configs/ordinary.yaml", "secret_key: serialized-secret-material\n"),
    ("configs/ordinary.txt", "-----BEGIN " + "CERTIFICATE-----\nYWJjZA==\n-----END CERTIFICATE-----\n"),
])
def test_sensitive_content_cannot_hide_under_ordinary_filename(packager, project, name, content):
    (project / name).write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="[Ss]ensitive|private|certificate|secret"):
        packager.build_package(project, project / "dist/submission")


@pytest.mark.parametrize("content", [
    "Local folder: " + "C:" + chr(92) + "Users" + chr(92) + "fixture-user" + chr(92) + "project\n",
    "Local folder: " + "/" + "home/fixture-user/project\n",
])
def test_absolute_development_paths_rejected(packager, project, content):
    (project / "README.md").write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="absolute|development|path"):
        packager.build_package(project, project / "dist/submission")


@pytest.mark.parametrize("content", ["作者：参赛学生\n", "学校：示例大学\n", "Author: Student Name\n", "Institution: Example University\n"])
def test_own_documents_reject_identifying_fields(packager, project, content):
    (project / "docs/submission/design-report.md").write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="anonymous|identity|identifying|author"):
        packager.build_package(project, project / "dist/submission")


def test_actual_archive_plus_manifest_size_is_enforced(packager, project, monkeypatch):
    monkeypatch.setattr(packager, "MAX_PACKAGE_BYTES", 64)
    output = project / "dist/submission"
    with pytest.raises(ValueError, match="size|limit|4 GiB"):
        packager.build_package(project, output)
    assert not (output / "source.zip").exists()


def test_failure_preserves_previous_valid_artifacts(packager, project):
    output = project / "dist/submission"
    packager.build_package(project, output)
    previous_zip = (output / "source.zip").read_bytes()
    previous_manifest = (output / "manifest.json").read_bytes()
    (project / "configs/identity.json").write_text("sensitive", encoding="utf-8")
    with pytest.raises(ValueError):
        packager.build_package(project, output)
    assert (output / "source.zip").read_bytes() == previous_zip
    assert (output / "manifest.json").read_bytes() == previous_manifest


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_symbolic_link_escape_rejected(packager, project, tmp_path, kind):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("must not leak", encoding="utf-8")
    link = project / "src/dgfl/link"
    try:
        link.symlink_to(outside if kind == "directory" else outside / "secret.txt", target_is_directory=kind == "directory")
    except OSError as error:
        pytest.skip(f"Host does not permit test symlinks: {error}")
    with pytest.raises(ValueError, match="[Ss]ymbolic|symlink|link|escape"):
        packager.build_package(project, project / "dist/submission")


def test_output_inside_whitelisted_tree_rejected(packager, project):
    with pytest.raises(ValueError, match="output|whitelist"):
        packager.build_package(project, project / "src/dgfl/package")


def test_archive_is_reproducible_and_optional_omissions_are_listed(packager, project):
    (project / "requirements-lock.txt").unlink()
    first = project / "dist/one"
    second = project / "dist/two"
    one = packager.build_package(project, first)
    two = packager.build_package(project, second)
    assert (first / "source.zip").read_bytes() == (second / "source.zip").read_bytes()
    assert one == two
    assert "requirements-lock.txt" in one["missing_optional_paths"]


def test_cli_uses_explicit_root_and_reports_failures(project):
    assert SCRIPT.is_file(), "The required command-line packager is missing"
    success = subprocess.run([sys.executable, str(SCRIPT), "--root", str(project), "--output", "dist/submission"], capture_output=True, text=True)
    assert success.returncode == 0, success.stderr
    assert (project / "dist/submission/source.zip").exists()
    (project / "README.md").unlink()
    failure = subprocess.run([sys.executable, str(SCRIPT), "--root", str(project), "--output", "dist/failure"], capture_output=True, text=True)
    assert failure.returncode != 0
    assert "README.md" in failure.stderr


@pytest.mark.parametrize("name", ["start_demo.ps1", "start_demo.sh", "prepare_offline.py", "run_experiments.py", "validate_release.py", "run_fault_checks.py", "benchmark_lego_proof.py", "setup_lego_parameters.py", "benchmark_lego_roles.py"])
def test_exact_optional_scripts_are_included_without_whitelisting_directory(packager, project, name):
    (project / "scripts" / name).write_text("# released helper\n", encoding="utf-8")
    (project / "scripts/unknown.py").write_text("not allowlisted\n", encoding="utf-8")
    result = packager.build_package(project, project / "dist/submission")
    names = {item["path"] for item in result["files"]}
    assert f"scripts/{name}" in names
    assert "scripts/unknown.py" not in names


def test_native_source_is_explicitly_allowlisted_without_compiled_or_private_trees(packager, project):
    source = {
        'native/dgfl-native/Cargo.toml': '[package]\nname="dgfl-native"\nversion="0.2.0"\n',
        'native/dgfl-native/Cargo.lock': '# reproducible Cargo dependency lock\nversion = 4\n',
        'native/dgfl-native/pyproject.toml': '[project]\nname="dgfl-native"\nversion="0.2.0"\n',
        'native/dgfl-native/src/lib.rs': 'mod lego;\nmod sigma;\nmod linked;\nmod aggregate;\npub fn checked_decode() {}\n',
        'native/dgfl-native/src/lego.rs': 'pub fn numeric_proof() {}\n',
        'native/dgfl-native/src/sigma.rs': 'pub fn ciphertext_link() {}\n',
        'native/dgfl-native/src/linked.rs': 'pub fn complete_linked_proof() {}\n',
        'native/dgfl-native/src/aggregate.rs': 'pub fn complete_aggregate_proof() {}\n',
        'native/dgfl-native/src/batch.rs': 'pub fn exact_batched_arithmetic() {}\n',
        'scripts/build_native.ps1': '# Build from the pinned native source\n',
        'scripts/benchmark_lego_proof.py': '# Fresh full-relation benchmark\n',
        'scripts/setup_lego_parameters.py': '# Explicit offline trusted parameter generation\n',
        'docs/research/evidence/acceleration-lego/validation.json': '{"accepted": true}\n',
    }
    excluded = ['native/dgfl-native/target/release/debug.key', 'native/dgfl-native/target/release/library.dll',
                'native/dgfl-native/src/unlisted.rs', 'native/wheels/dgfl_native-0.1.0-cp312-cp312-win_amd64.whl',
                'native/runtime/identity.json', 'tmp/native-wheels/private.pem']
    for name, content in {**source, **dict.fromkeys(excluded, 'excluded fixture')}.items():
        target = project/name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding='utf8')
    result = packager.build_package(project, project/'dist/native-source')
    names = {item['path'] for item in result['files']}
    assert set(source) <= names
    assert not names.intersection(excluded)
    assert not any('/target/' in name or name.startswith('tmp/') or name.endswith('.whl') for name in names)
    assert packager.verify_package(project/'dist/native-source') == result


@pytest.mark.parametrize('filename', ['lib.rs', 'lego.rs', 'sigma.rs', 'linked.rs', 'aggregate.rs', 'batch.rs'])
def test_native_rust_source_is_subject_to_content_checks(packager, project, filename):
    target = project/'native/dgfl-native/src'/filename
    target.parent.mkdir(parents=True)
    target.write_text('const KEY: &str = r#"\n-----BEGIN ' + 'PRIVATE KEY-----\nmaterial\n"#;', encoding='utf8')
    with pytest.raises(ValueError, match='Sensitive private key'):
        packager.build_package(project, project/'dist/rejected-native')


def test_independent_verification_rejects_tampered_archive(packager, project):
    output = project / "dist/submission"
    packager.build_package(project, output)
    assert packager.verify_package(output)["file_count"] > 0
    with (output / "source.zip").open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(ValueError, match="hash|size"):
        packager.verify_package(output)


@pytest.mark.parametrize("unsafe_name,symlink", [("../outside.txt", False), ("/absolute.txt", False), ("C:" + "/outside.txt", False), ("src/dgfl/link", True)])
def test_zip_verification_rejects_traversal_and_links_even_with_matching_hashes(packager, tmp_path, unsafe_name, symlink):
    output = tmp_path / "crafted"
    output.mkdir()
    path = output / "source.zip"
    content = b"outside"
    with zipfile.ZipFile(path, "w") as archive:
        info = zipfile.ZipInfo(unsafe_name)
        info.create_system = 3
        info.external_attr = ((stat.S_IFLNK if symlink else stat.S_IFREG) | 0o644) << 16
        archive.writestr(info, content)
    manifest = {"schema_version": 1,
                "archive": {"path": "source.zip", "size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
                "file_count": 1, "uncompressed_bytes": len(content),
                "files": [{"path": unsafe_name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}],
                "missing_optional_paths": []}
    (output / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsafe|link"):
        packager.verify_package(output)


def test_size_limit_applies_to_archive_plus_manifest_with_strict_inequality(packager, project, monkeypatch):
    output = project / "dist/submission"
    packager.build_package(project, output)
    size = (output / "source.zip").stat().st_size + (output / "manifest.json").stat().st_size
    monkeypatch.setattr(packager, "MAX_PACKAGE_BYTES", size + 1)
    packager.verify_package(output)
    monkeypatch.setattr(packager, "MAX_PACKAGE_BYTES", size)
    with pytest.raises(ValueError, match="size limit"):
        packager.verify_package(output)


@pytest.mark.parametrize("content", ["| 作者 | Student Name |\n", "\\author{Student Name}\n", '<meta name="author" content="Student Name">\n'])
def test_identity_in_markdown_table_tex_and_html_is_rejected(packager, project, content):
    (project / "docs/submission/design-report.md").write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="anonymous|identifying|author"):
        packager.build_package(project, project / "dist/submission")


def png_fixture(metadata=(), *, pixel_path=False):
    def chunk(kind, payload):
        return struct.pack('>I', len(payload)) + kind + payload + struct.pack('>I', zlib.crc32(kind + payload))
    # Stored DEFLATE contains bytes that resemble a drive path, but are RGB pixels.
    pixels = b'C:' + b'/pixel-values!' if pixel_path else b'\x80' * 18
    pixels += b'\x00' * (-len(pixels) % 3)
    header = struct.pack('>IIBBBBB', len(pixels) // 3, 1, 8, 2, 0, 0, 0)
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header)
            + b''.join(chunk(kind, payload) for kind, payload in metadata)
            + chunk(b'IDAT', zlib.compress(b'\0' + pixels, level=0)) + chunk(b'IEND', b''))


def test_png_pixel_bytes_that_resemble_drive_paths_do_not_trigger_text_scan(packager, project):
    name = 'docs/submission/architecture.png'
    image = png_fixture(pixel_path=True)
    (project / name).write_bytes(image)
    result = packager.build_package(project, project / 'dist/submission')
    assert name in {item['path'] for item in result['files']}
    with zipfile.ZipFile(project / 'dist/submission/source.zip') as archive:
        assert archive.read(name) == image


@pytest.mark.parametrize('kind', [b'tEXt', b'zTXt', b'iTXt'])
def test_png_metadata_private_paths_are_rejected(packager, project, kind):
    private_path = b'C:' + b'/' + b'Users/fixture-user/private'
    payload = {b'tEXt': b'Description\0' + private_path,
               b'zTXt': b'Description\0\0' + zlib.compress(private_path),
               b'iTXt': b'Description\0\x01\0en\0Description\0' + zlib.compress(private_path)}[kind]
    (project / 'docs/submission/architecture.png').write_bytes(png_fixture([(kind, payload)]))
    with pytest.raises(ValueError, match='development path'):
        packager.build_package(project, project / 'dist/submission')


def test_png_metadata_identifying_author_is_rejected(packager, project):
    (project / 'docs/submission/architecture.png').write_bytes(png_fixture([(b'tEXt', b'Author\0Student Name')]))
    with pytest.raises(ValueError, match='anonymous|identifying|author'):
        packager.build_package(project, project / 'dist/submission')


def test_invalid_text_encoding_fails_instead_of_silently_dropping_bytes(packager, project):
    (project / 'configs/broken.txt').write_bytes(b'Broken text: \xff')
    with pytest.raises((ValueError, UnicodeError), match='text|decode|encoding'):
        packager.build_package(project, project / 'dist/submission')


def test_unknown_binary_format_is_rejected(packager, project):
    (project / 'docs/submission/opaque.bin').write_bytes(b'\0\xffopaque payload')
    with pytest.raises(ValueError, match='[Uu]nsupported|[Uu]nknown'):
        packager.build_package(project, project / 'dist/submission')


def test_international_png_author_keyword_is_checked_even_with_translation(packager, project):
    payload = b'Author\0\x01\0en\0Translated author\0' + zlib.compress(b'Student Name')
    (project / 'docs/submission/architecture.png').write_bytes(png_fixture([(b'iTXt', payload)]))
    with pytest.raises(ValueError, match='anonymous|identifying|author'):
        packager.build_package(project, project / 'dist/submission')


def test_png_metadata_cannot_hide_pem_material_in_a_description(packager, project):
    value = b'Description\0-----BEGIN ' + b'PRIVATE KEY-----\nYWJjZA==\n'
    (project / 'docs/submission/architecture.png').write_bytes(png_fixture([(b'tEXt', value)]))
    with pytest.raises(ValueError, match='Sensitive private key'):
        packager.build_package(project, project / 'dist/submission')


def test_malformed_png_error_identifies_source_file(packager, project):
    (project / 'docs/submission/broken.png').write_bytes(b'not a PNG image')
    with pytest.raises(ValueError, match='docs/submission/broken.png'):
        packager.build_package(project, project / 'dist/submission')


def test_pdf_without_parser_fails_closed(packager, project, monkeypatch):
    import builtins
    importer = builtins.__import__
    def without_pdf(name, *args, **kwargs):
        if name == 'pypdf':
            raise ImportError('controlled unavailable optional dependency')
        return importer(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', without_pdf)
    (project / 'docs/submission/report.pdf').write_bytes(b'%PDF-1.4\n%%EOF')
    with pytest.raises(ValueError, match='requires optional pypdf'):
        packager.build_package(project, project / 'dist/submission')


@pytest.mark.parametrize('metadata, failure', [({'/Title': 'Architecture', '/Author': ''}, None),
    ({'/Title': 'C:' + '/' + 'Users/fixture-user/private'}, 'development path'),
    ({'/Author': 'Student Name'}, 'anonymous|identifying|author')])
def test_pdf_info_metadata_is_parsed_when_optional_parser_is_available(packager, project, metadata, failure):
    pypdf = pytest.importorskip('pypdf')
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=100, height=100)
    writer.add_metadata(metadata)
    writer.write(project / 'docs/submission/report.pdf')
    if failure:
        with pytest.raises(ValueError, match=failure):
            packager.build_package(project, project / 'dist/submission')
    else:
        packager.build_package(project, project / 'dist/submission')


def test_compressed_pdf_xmp_private_path_is_rejected(packager, project):
    pypdf = pytest.importorskip('pypdf')
    from pypdf.generic import DecodedStreamObject, NameObject
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=100, height=100)
    metadata = DecodedStreamObject()
    metadata.set_data(b'<metadata><description>C:' + b'/' + b'Users/fixture-user/private</description></metadata>')
    metadata = metadata.flate_encode()
    metadata.update({NameObject('/Type'): NameObject('/Metadata'), NameObject('/Subtype'): NameObject('/XML')})
    writer._root_object[NameObject('/Metadata')] = writer._add_object(metadata)
    writer.write(project / 'docs/submission/report.pdf')
    with pytest.raises(ValueError, match='development path'):
        packager.build_package(project, project / 'dist/submission')
