"""Build a reproducible, allowlisted submission ZIP and a verifiable manifest.

Usage from the project root:
    python scripts/package_submission.py --output dist/submission

Relative output paths are resolved against --root (the project root by default).
This is a fail-closed static packaging check, not a semantic anonymity proof.
Third-party notices and authorship are preserved without rewriting content.
"""
from __future__ import annotations

import argparse
import codecs
import hashlib
import importlib.util
import json
import os
import re
import stat
import struct
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
import zlib
from pathlib import Path, PurePosixPath

MAX_PACKAGE_BYTES = 4 * 1024**3
CHUNK_BYTES = 1024 * 1024
ALLOWED_TREES = ("src/dgfl", "tests", "configs", "web", "docs/submission", "docs/protocol",
                 "docs/research/evidence/acceleration-5b", "docs/research/evidence/acceleration-lego")
ALLOWED_FILES = ("pyproject.toml", "requirements-lock.txt", "requirements-torch.txt", "requirements-gpu.txt", "README.md", "SOURCE-PACKAGE.md", "THIRD_PARTY_NOTICES.md",
                 "scripts/package_submission.py", "scripts/start_demo.ps1", "scripts/start_demo.sh",
                 "scripts/setup_environment.py", "scripts/deployment_native.py",
                 "scripts/prepare_offline.py", "scripts/run_experiments.py", "scripts/validate_release.py",
                 "scripts/build_report.py", "scripts/build_figures.py", "scripts/run_fault_checks.py",
                 "scripts/build_native.ps1", "native/dgfl-native/Cargo.toml", "native/dgfl-native/Cargo.lock",
                 "native/dgfl-native/pyproject.toml", "native/dgfl-native/src/lib.rs",
                 "native/dgfl-native/src/lego.rs", "native/dgfl-native/src/sigma.rs",
                 "native/dgfl-native/src/linked.rs", "native/dgfl-native/src/aggregate.rs",
                 "native/dgfl-native/src/batch.rs",
                 "scripts/benchmark_crypto.py", "scripts/benchmark_compact_validation.py",
                 "scripts/benchmark_acceleration_smoke.py", "scripts/benchmark_lego_proof.py",
                 "scripts/setup_lego_parameters.py",
                 "scripts/benchmark_lego_roles.py",
                 "scripts/benchmark_combine_roles.py", "scripts/benchmark_gpu_many.py",
                 "scripts/summarize_full_optimization.py",
                 "scripts/validate_full_optimization_live.py",
                 "docs/research/evidence/full-optimization-20261005/analysis.json",
                 "docs/research/evidence/full-optimization-20261005/live-validation.json",
                 "docs/research/evidence/full-optimization-20261005/activation.json",
                 "docs/research/evidence/deployment-ready-20261008.json",
                 "docs/research/optimization-results.md")
REQUIRED_FILES = ("README.md", "pyproject.toml", "docs/submission/design-report.md")
EXCLUDED_DIRECTORIES = {"data", "__pycache__", ".venv", ".git", ".superpowers", "tmp", "runtime", "target", "node_modules", ".pytest_cache"}
SENSITIVE_SUFFIXES = {".key", ".pem", ".crt", ".cer", ".cert", ".der", ".csr", ".p12", ".pfx", ".jks", ".keystore"}
STRUCTURED_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env"}
TEXT_SUFFIXES = STRUCTURED_SUFFIXES | {".py", ".md", ".txt", ".csv", ".tsv", ".jsonl", ".html", ".htm",
    ".xml", ".svg", ".tex", ".bib", ".css", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue",
    ".ps1", ".sh", ".bat", ".cmd", ".rst", ".lock", ".map", ".rs", ".cu", ".cuh", ".sha256"}
TEXT_NAMES = {".gitignore", ".gitattributes", ".npmrc", ".nvmrc", ".editorconfig", "license", "notice", "makefile"}
MAX_METADATA_BYTES = 2 * 1024**2
IDENTITY_NAME = re.compile(r"(?:^|[-_.])(?:identit(?:y|ies)|credentials?|secrets?|private[-_]?keys?)(?:[-_.]|$)", re.I)
SSH_NAME = re.compile(r"^id_(?:rsa|dsa|ecdsa|ed25519)(?:\.|$)", re.I)
PEM_CONTENT = re.compile(r"(?m)^\s*-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|(?:X509 |TRUSTED )?CERTIFICATE)-----")
PEM_METADATA = re.compile(r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|(?:X509 |TRUSTED )?CERTIFICATE)-----")
SECRET_FIELD = re.compile(r'''(?im)(?:^\s*|[,{]\s*)["']?(?:private[_-]?key|secret[_-]?key|client[_-]?secret|identity[_-]?secret)["']?\s*[:=]\s*(?!null\b|None\b|["']{2}(?:\s|,|$))\S+''')
WINDOWS_ABSOLUTE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:[\\/][^\s\"'<>]+")
PERSONAL_POSIX = re.compile(r"(?<![A-Za-z0-9])/(?:Users|home|workspace|workspaces)/[^\s\"'<>]+")
IDENTIFYING_FIELD = re.compile(r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?(?:作者|姓名|学校|院校|学院|指导教师|指导老师|参赛队员|队员姓名|学生姓名|学号|团队成员|author|authors|student(?: name)?|school|university|institution|supervisor)(?:\*\*)?\s*[:：=]\s*\S+")
IDENTIFYING_TABLE = re.compile(r"(?im)^\s*\|\s*(?:作者|姓名|学校|院校|学院|指导教师|参赛队员|学号|author|school|university|institution)\s*\|\s*[^\s|]")
IDENTIFYING_TEX = re.compile(r"\\(?:author|institute|affiliation)\s*\{\s*[^}\s]")
IDENTIFYING_HTML = re.compile(r'''<meta\b[^>]*\bname\s*=\s*["']author["'][^>]*\bcontent\s*=\s*["'][^"']''', re.I)


def _is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _check_location(root: Path, path: Path) -> None:
    current = path
    while current != root:
        if _is_link(current):
            raise ValueError(f"Symbolic link/junction is not allowed: {path.relative_to(root).as_posix()}")
        if current == current.parent:
            raise ValueError("Source path escapes the project root")
        current = current.parent
    try:
        path.resolve().relative_to(root)
    except ValueError as exc:
        raise ValueError("Source path escapes the project root") from exc


def _validate_archive_name(name: str) -> None:
    path = PurePosixPath(name)
    if (not name or name.startswith("/") or "\\" in name or ":" in name
            or any(part in ("", ".", "..") for part in name.split("/"))
            or any(ord(char) < 32 or ord(char) == 127 for char in name)
            or path.is_absolute()):
        raise ValueError(f"Unsafe ZIP entry path: {name!r}")


def _sensitive_name(relative: str) -> bool:
    path = PurePosixPath(relative)
    name = path.name.lower()
    return (path.suffix.lower() in SENSITIVE_SUFFIXES or name == ".env" or name.startswith(".env.")
            or SSH_NAME.search(name) is not None
            or (path.suffix.lower() in STRUCTURED_SUFFIXES and IDENTITY_NAME.search(name) is not None))


def _walk(root: Path, path: Path):
    _check_location(root, path)
    if path.is_dir():
        for child in sorted(path.iterdir(), key=lambda item: item.name):
            if child.name.lower() in EXCLUDED_DIRECTORIES:
                continue
            yield from _walk(root, child)
        return
    if not path.is_file():
        raise ValueError(f"Only regular files are allowed: {path.relative_to(root).as_posix()}")
    relative = path.relative_to(root).as_posix()
    if path.suffix.lower() in {".pyc", ".pyo"}:
        return
    _validate_archive_name(relative)
    if _sensitive_name(relative):
        raise ValueError(f"Sensitive identity/private-key/certificate file in whitelist: {relative}")
    if path.suffix.lower() == ".pdf" and "dgflow" in path.name.lower():
        raise ValueError(f"Original DGFlow paper must not be packaged: {relative}")
    if path.suffix.lower() == ".md" and re.search(r"(?:development|implementation)[-_ ]plan|[-_]brief\.md$", path.name, re.I):
        raise ValueError(f"Development planning document must not be packaged: {relative}")
    yield relative, path


def _collect(root: Path):
    for name in REQUIRED_FILES:
        path = root / name
        _check_location(root, path)
        if not path.is_file():
            raise ValueError(f"Missing required file: {name}")
        if path.stat().st_size == 0 or not path.read_text(encoding="utf-8-sig").strip():
            raise ValueError(f"Required file is empty: {name}")
    source = root / "src/dgfl"
    _check_location(root, source)
    if not source.is_dir():
        raise ValueError("Missing required source directory: src/dgfl")
    collected, missing = {}, []
    for name in (*ALLOWED_TREES, *ALLOWED_FILES):
        path = root / name
        _check_location(root, path)
        if not path.exists():
            missing.append(name)
            continue
        for relative, file_path in _walk(root, path):
            collected[relative] = file_path
    if not any(name.startswith("src/dgfl/") and name.endswith(".py") and path.stat().st_size > 0
               for name, path in collected.items()):
        raise ValueError("Required src/dgfl source tree has no nonempty Python source")
    return sorted(collected.items()), sorted(missing)


def _own_document(relative: str) -> bool:
    path = PurePosixPath(relative)
    return relative == "README.md" or (relative.startswith("docs/submission/") and path.suffix.lower() in {".md", ".txt", ".html", ".tex", ".png", ".pdf"})


def _scan_text(text: str, relative: str, root_spellings: tuple[str, ...], *, metadata=False) -> None:
    if PEM_CONTENT.search(text) or (metadata and PEM_METADATA.search(text)):
        raise ValueError(f"Sensitive private key or certificate content: {relative}")
    if (metadata or PurePosixPath(relative).suffix.lower() in STRUCTURED_SUFFIXES) and SECRET_FIELD.search(text):
        raise ValueError(f"Sensitive serialized private/secret key: {relative}")
    if WINDOWS_ABSOLUTE.search(text) or PERSONAL_POSIX.search(text) or any(value in text for value in root_spellings):
        raise ValueError(f"Absolute development path in file: {relative}")
    if _own_document(relative) and any(pattern.search(text) for pattern in
                                       (IDENTIFYING_FIELD, IDENTIFYING_TABLE, IDENTIFYING_TEX, IDENTIFYING_HTML)):
        raise ValueError(f"Own submission document must be anonymous; identifying author/institution field: {relative}")


def _inflate_metadata(payload: bytes) -> bytes:
    decoder = zlib.decompressobj()
    try:
        text = decoder.decompress(payload, MAX_METADATA_BYTES + 1)
    except zlib.error as exc:
        raise ValueError('Invalid compressed PNG metadata') from exc
    if len(text) > MAX_METADATA_BYTES or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError('PNG metadata is oversized, truncated, or has trailing data')
    return text


def _png_text(kind: bytes, payload: bytes) -> str:
    keyword, separator, rest = payload.partition(b'\0')
    if not separator or not 1 <= len(keyword) <= 79:
        raise ValueError('Invalid PNG metadata keyword')
    label, extra = keyword.decode('latin-1'), ''
    if kind == b'tEXt':
        value = rest.decode('latin-1')
    elif kind == b'zTXt':
        if not rest or rest[0] != 0:
            raise ValueError('Unsupported PNG metadata compression')
        value = _inflate_metadata(rest[1:]).decode('latin-1')
    else:
        if len(rest) < 2 or rest[0] not in (0, 1) or rest[1] != 0:
            raise ValueError('Invalid PNG international text header')
        fields = rest[2:].split(b'\0', 2)
        if len(fields) != 3:
            raise ValueError('Invalid PNG international text fields')
        language, translated, value_bytes = fields
        language_text = language.decode('ascii')
        translated_label = translated.decode('utf-8')
        value = (_inflate_metadata(value_bytes) if rest[0] else value_bytes).decode('utf-8')
        extra = '\nlanguage: ' + language_text + '\n' + translated_label + ': ' + value
    if '\0' in value:
        raise ValueError('NUL is not allowed in PNG text metadata')
    return label.strip() + ': ' + value + extra


def _png_metadata(path: Path):
    """Read PNG text chunks; never regex-match compressed pixel bytes."""
    text_kinds = {b'tEXt', b'zTXt', b'iTXt'}
    safe_binary = {b'IHDR', b'PLTE', b'IDAT', b'IEND', b'tRNS', b'cHRM', b'gAMA', b'sRGB',
                   b'sBIT', b'bKGD', b'hIST', b'pHYs', b'tIME'}
    metadata_size, seen_header, seen_pixels = 0, False, False

    def exact(stream, length):
        value = stream.read(length)
        if len(value) != length:
            raise ValueError('Truncated PNG structure')
        return value

    with path.open('rb') as stream:
        if exact(stream, 8) != b'\x89PNG\r\n\x1a\n':
            raise ValueError('Invalid PNG signature')
        while True:
            size, kind = struct.unpack('>I4s', exact(stream, 8))
            if kind not in safe_binary | text_kinds:
                raise ValueError(f'Unsupported PNG chunk requiring metadata review: {kind!r}')
            if not seen_header and (kind != b'IHDR' or size != 13):
                raise ValueError('PNG must begin with one IHDR')
            if kind == b'IHDR':
                if seen_header:
                    raise ValueError('Duplicate PNG IHDR')
                seen_header = True
            if kind in text_kinds and size > MAX_METADATA_BYTES:
                raise ValueError('PNG metadata chunk is oversized')
            crc, chunks, remaining = zlib.crc32(kind), [], size
            while remaining:
                block = exact(stream, min(CHUNK_BYTES, remaining))
                crc = zlib.crc32(block, crc)
                if kind in text_kinds:
                    chunks.append(block)
                remaining -= len(block)
            if struct.unpack('>I', exact(stream, 4))[0] != crc:
                raise ValueError('PNG chunk CRC mismatch')
            if kind in text_kinds:
                text = _png_text(kind, b''.join(chunks))
                metadata_size += len(text)
                if metadata_size > MAX_METADATA_BYTES:
                    raise ValueError('Total PNG metadata is oversized')
                yield text
            seen_pixels = seen_pixels or kind == b'IDAT'
            if kind == b'IEND':
                if size or not seen_pixels or stream.read(1):
                    raise ValueError('Invalid PNG end marker or trailing data')
                break


def _pdf_metadata(path: Path):
    """Use a PDF parser for Info/XMP, with no fallback to raw byte scanning."""
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise ValueError('PDF metadata checking requires optional pypdf in the packaging environment') from exc
    try:
        reader = PdfReader(path, strict=True)
        if reader.is_encrypted:
            raise ValueError('Encrypted PDF metadata cannot be checked')
        for key, value in (reader.metadata or {}).items():
            if not isinstance(value, str):
                raise ValueError('Unsupported non-text PDF Info metadata')
            yield str(key).lstrip('/') + ': ' + value
        metadata = reader.trailer['/Root'].get('/Metadata')
        if metadata is not None:
            payload = metadata.get_object().get_data()
            if len(payload) > MAX_METADATA_BYTES:
                raise ValueError('PDF XMP metadata is oversized')
            tree = ET.fromstring(payload)
            for element in tree.iter():
                tag = element.tag.rsplit('}', 1)[-1]
                value = ' '.join(element.itertext()).strip()
                # Dublin Core creator means authors; PDF /Creator means software.
                if element.tag == '{http://purl.org/dc/elements/1.1/}creator':
                    tag = 'Author'
                if value:
                    yield tag + ': ' + value
                for key, value in element.attrib.items():
                    yield key.rsplit('}', 1)[-1] + ': ' + value
    except Exception as exc:
        raise ValueError(f'Cannot inspect PDF metadata: {exc}') from exc


def _write_member(archive: zipfile.ZipFile, relative: str, path: Path, root: Path, *, scan_text=True) -> dict:
    _check_location(root, path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"Not a regular file: {relative}")
    info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    digest, size, tail = hashlib.sha256(), 0, ""
    root_spellings = tuple({str(root), root.as_posix()})
    if scan_text:
        suffix = path.suffix.lower()
        if suffix in {'.png', '.pdf'}:
            extractor = _png_metadata if suffix == '.png' else _pdf_metadata
            try:
                for metadata_text in extractor(path):
                    _scan_text(metadata_text, relative, root_spellings, metadata=True)
            except ValueError as exc:
                raise ValueError(f'{relative}: {exc}') from exc
            scan_text = False
        elif suffix not in TEXT_SUFFIXES and path.name.lower() not in TEXT_NAMES:
            raise ValueError(f'Unsupported file type requires an explicit content checker: {relative}')
    with path.open("rb") as stream, archive.open(info, "w", force_zip64=True) as target:
        decoder = None
        while chunk := stream.read(CHUNK_BYTES):
            if scan_text:
                if decoder is None:
                    encoding = "utf-16" if chunk.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) else "utf-8-sig"
                    decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
                text = tail + decoder.decode(chunk)
                _scan_text(text, relative, root_spellings)
                tail = text[-8192:]
            digest.update(chunk)
            size += len(chunk)
            target.write(chunk)
            if archive.fp.tell() >= MAX_PACKAGE_BYTES:
                raise ValueError("Package exceeds the 4 GiB size limit")
        if decoder is not None:
            _scan_text(tail + decoder.decode(b'', final=True), relative, root_spellings)
    after = path.stat()
    _check_location(root, path)
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino) or size != before.st_size:
        raise ValueError(f"Source changed during packaging; retry from a stable tree: {relative}")
    return {"path": relative, "size": size, "sha256": digest.hexdigest()}


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def verify_package(output: Path) -> dict:
    """Independently re-read ZIP contents and verify manifest hashes and sizes."""
    output = Path(output)
    archive_path, manifest_path = output / "source.zip", output / "manifest.json"
    if archive_path.stat().st_size + manifest_path.stat().st_size >= MAX_PACKAGE_BYTES:
        raise ValueError("Actual ZIP plus manifest must be smaller than the 4 GiB size limit")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = manifest["files"]
    expected = {item["path"]: item for item in entries}
    if len(entries) != len(expected) or len(entries) != manifest["file_count"]:
        raise ValueError("Manifest has duplicate entries or incorrect file count")
    if manifest["archive"] != {"path": "source.zip", "size": archive_path.stat().st_size, "sha256": _hash_file(archive_path)}:
        raise ValueError("Archive hash or size does not match manifest")
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        if len(members) != len(expected) or {item.filename for item in members} != set(expected):
            raise ValueError("ZIP entries do not match manifest")
        for member in members:
            _validate_archive_name(member.filename)
            if stat.S_ISLNK(member.external_attr >> 16) or member.is_dir():
                raise ValueError("ZIP must contain only regular files, never symbolic links")
            digest, size = hashlib.sha256(), 0
            with archive.open(member) as stream:
                while chunk := stream.read(CHUNK_BYTES):
                    digest.update(chunk)
                    size += len(chunk)
            if expected[member.filename] != {"path": member.filename, "size": size, "sha256": digest.hexdigest()}:
                raise ValueError(f"ZIP content hash or size mismatch: {member.filename}")
        if sum(item["size"] for item in entries) != manifest["uncompressed_bytes"]:
            raise ValueError("Manifest uncompressed size mismatch")
    return manifest


def _collect_offline(root: Path):
    """Only the exact verified offline manifest set can bypass source text scans."""
    script = Path(__file__).with_name('prepare_offline.py')
    spec = importlib.util.spec_from_file_location('submission_offline_verifier', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = module.verify_offline(root/'offline')
    expected = {'offline/'+item['path']: {'path': 'offline/'+item['path'], 'size': item['size'], 'sha256': item['sha256']}
                for item in manifest['files']}
    manifest_path = root/'offline'/'manifest.json'
    expected['offline/manifest.json'] = {'path': 'offline/manifest.json', 'size': manifest_path.stat().st_size,
                                         'sha256': _hash_file(manifest_path)}
    files = [(relative, root/relative) for relative in sorted(expected)]
    for _, path in files:
        _check_location(root, path)
    return files, expected


def build_package(root: Path, output: Path, *, include_offline=False) -> dict:
    """Build source.zip and manifest.json from an explicit allowlist.

Validation failures leave any previously completed output files untouched.
No content is rewritten or redacted; sensitive content causes a visible error.
"""
    root = Path(root).absolute()
    if _is_link(root) or not root.is_dir():
        raise ValueError("Project root must be an existing directory, not a symbolic link")
    root = root.resolve()
    output = Path(output)
    output = output if output.is_absolute() else root / output
    for ancestor in (output, *output.parents):
        if _is_link(ancestor):
            raise ValueError("Output path must not contain a symbolic link/junction")
    output = output.resolve()
    input_trees = (*ALLOWED_TREES, 'offline') if include_offline else ALLOWED_TREES
    if output == root or any(output.is_relative_to(root / tree) for tree in input_trees):
        raise ValueError("Output must be outside every whitelisted input tree")
    files, missing = _collect(root)
    offline_expected = {}
    if include_offline:
        offline_files, offline_expected = _collect_offline(root)
        files = sorted(files + offline_files)
    output.mkdir(parents=True, exist_ok=True)
    for name in ("source.zip", "manifest.json"):
        destination = output / name
        if _is_link(destination) or (destination.exists() and not destination.is_file()):
            raise ValueError(f"Invalid output file target: {name}")
    with tempfile.TemporaryDirectory(prefix=".submission-build-", dir=output) as staging_name:
        staging = Path(staging_name)
        archive_path = staging / "source.zip"
        entries = []
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
            for relative, file_path in files:
                verified_binary = relative in offline_expected and file_path.suffix in ('.whl', '.gz')
                entry = _write_member(archive, relative, file_path, root, scan_text=not verified_binary)
                if relative in offline_expected and entry != offline_expected[relative]:
                    raise ValueError(f'Offline input changed after verification: {relative}')
                entries.append(entry)
        manifest = {"schema_version": 1,
                    "archive": {"path": "source.zip", "size": archive_path.stat().st_size, "sha256": _hash_file(archive_path)},
                    "file_count": len(entries), "uncompressed_bytes": sum(item["size"] for item in entries),
                    "files": entries, "missing_optional_paths": missing}
        (staging / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        verify_package(staging)
        os.replace(archive_path, output / "source.zip")
        os.replace(staging / "manifest.json", output / "manifest.json")
    return manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, default=Path("dist/submission"))
    parser.add_argument("--include-offline", action='store_true', help='Include only a verified offline/ wheel and public-data bundle')
    options = parser.parse_args(argv)
    try:
        manifest = build_package(options.root, options.output, include_offline=options.include_offline)
    except (OSError, ValueError, UnicodeError, zipfile.BadZipFile) as exc:
        print(f"Submission packaging failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"files": manifest["file_count"], "archive_bytes": manifest["archive"]["size"],
                      "archive_sha256": manifest["archive"]["sha256"],
                      "missing_optional_paths": manifest["missing_optional_paths"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
