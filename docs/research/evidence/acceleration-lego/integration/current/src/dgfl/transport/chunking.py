"""Chunked request assembly for messages larger than one RPC body.

A node accepts at most :data:`dgfl.services.node.MESSAGE_LIMIT` bytes in a single
request. Anything larger is delivered as ``_chunk`` calls whose payloads bind the
whole submission through one SHA-256 digest::

    {'action': <target action>, 'digest': <sha256 of the assembled body>,
     'index': i, 'total': n, 'data': <block bytes>}

The digest covers the complete packed ``{'action': .., 'payload': ..}`` body, so
task, round, key epoch, model digest, client, dimension and coordinate range are
all bound at once — changing any of them changes the digest and the submission
is rejected. The sender is bound by the authenticated envelope that carries each
chunk.

Every malformed combination is refused: replayed or overlapping blocks with
different content, gaps left by a truncated or reordered transfer, a block count
that changes mid-transfer, mixing two submissions under one digest, exceeding
the byte or block ceilings, and an assembled body whose digest does not match.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import secrets
import tempfile
import time

from .binary import pack_to

#: Payload bytes carried by one chunk. Stays well below the node message limit.
CHUNK_BYTES = 8 * 1024 * 1024
#: Bodies at or below this size are sent as a single request.
SEND_THRESHOLD = 24 * 1024 * 1024
#: Largest assembled submission a node will hold for one digest.
MAX_TOTAL_BYTES = 1 << 30
#: Largest number of blocks in one submission.
MAX_CHUNKS = 4096
#: Concurrent in-flight submissions accepted from one sender.
MAX_ENTRIES_PER_SENDER = 4
MAX_DISK_BYTES = 16 << 30
MAX_ENTRIES = 16
TRANSFER_TTL = 900
#: Action name reserved for the chunk carrier itself.
CHUNK_ACTION = '_chunk'
DOWNLOAD_ACTION = '_download'
DOWNLOAD_MARKER = '_rpc_download'


class EncodedMessage:
    """Canonical encoding plus digest in a bounded spool, not a giant bytes."""

    def __init__(self, value, *, directory=None, memory_limit=SEND_THRESHOLD,
                 max_total_bytes=MAX_TOTAL_BYTES, disk=False):
        if directory is not None:
            Path(directory).mkdir(parents=True, exist_ok=True)
        self.path = None
        if disk:
            handle = tempfile.NamedTemporaryFile(mode='w+b', prefix='_encode-',
                                                 dir=directory, delete=False)
            self.path = Path(handle.name)
            self.file = handle
        else:
            self.file = tempfile.SpooledTemporaryFile(max_size=memory_limit, dir=directory)
        digest = hashlib.sha256()
        self.size = 0

        class Writer:
            def write(inner, data):
                if self.size + len(data) > max_total_bytes:
                    raise ValueError('encoded message exceeds the configured size limit')
                count = self.file.write(data)
                digest.update(data)
                self.size += count
                return count

        try:
            pack_to(value, Writer())
            self.file.flush()
            self.file.seek(0)
            self.digest = digest.hexdigest()
        except BaseException:
            self.close()
            raise

    def close(self):
        self.file.close()
        if self.path is not None:
            self.path.unlink(missing_ok=True)
            self.path = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class ChunkAssembler:
    """Buffer chunked submissions; return a body only once it is complete."""

    def __init__(self, *, max_total_bytes=MAX_TOTAL_BYTES, max_chunks=MAX_CHUNKS,
                 max_entries_per_sender=MAX_ENTRIES_PER_SENDER, directory=None,
                 file_mode=False, max_disk_bytes=MAX_DISK_BYTES,
                 max_entries=MAX_ENTRIES, max_chunk_bytes=CHUNK_BYTES,
                 ttl=TRANSFER_TTL, clock=time.time):
        self.max_total_bytes = max_total_bytes
        self.max_chunks = max_chunks
        self.max_entries_per_sender = max_entries_per_sender
        self.max_disk_bytes = max_disk_bytes
        self.max_entries = max_entries
        self.max_chunk_bytes = max_chunk_bytes
        self.ttl, self.clock = ttl, clock
        self.file_mode = file_mode
        self._temp_directory = tempfile.TemporaryDirectory(prefix='dgflow-upload-') if directory is None else None
        self.directory = Path(self._temp_directory.name if directory is None else directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._entries: dict[tuple[str, str], dict] = {}
        self._held_bytes = 0
        self._restore()

    def _remove_folder(self, folder):
        # Only direct children of the owned spool directory are removed. Never
        # recursively delete a path supplied by a network packet or metadata.
        if folder.resolve().parent != self.directory.resolve():
            raise ValueError('upload spool path escapes its directory')
        for path in folder.iterdir():
            if path.is_symlink() or not path.is_file():
                raise ValueError('unexpected path inside upload spool')
            path.unlink()
        folder.rmdir()

    def _save_entry(self, sender, digest, entry):
        meta = {'sender': sender, 'digest': digest, 'action': entry['action'],
                'total': entry['total'], 'updated': entry['updated'],
                'hashes': {str(i): h for i, h in entry['hashes'].items()}}
        target = entry['folder'] / 'manifest.json'
        temp = entry['folder'] / 'manifest.tmp'
        temp.write_text(json.dumps(meta, sort_keys=True), encoding='utf8')
        temp.replace(target)

    def _restore(self):
        for folder in self.directory.glob('parts-*'):
            if not folder.is_dir() or folder.is_symlink():
                raise ValueError('unexpected upload spool directory')
            meta_path = folder / 'manifest.json'
            if not meta_path.exists():
                self._remove_folder(folder)
                continue
            meta = json.loads(meta_path.read_text('utf8'))
            if self.clock() - meta['updated'] >= self.ttl:
                self._remove_folder(folder)
                continue
            sender, digest = meta['sender'], meta['digest']
            self._spec({'action': meta['action'], 'digest': digest, 'index': 0,
                        'total': meta['total'], 'data': b'\x00'})
            if not isinstance(sender, str) or (sender, digest) in self._entries:
                raise ValueError('invalid persisted upload sender or duplicate submission')
            parts, hashes, size = {}, {}, 0
            interrupted = False
            for raw_index, block_hash in meta['hashes'].items():
                index = int(raw_index)
                if (str(index) != raw_index or not 0 <= index < meta['total']
                        or not isinstance(block_hash, str) or len(block_hash) != 64
                        or any(c not in '0123456789abcdef' for c in block_hash)):
                    raise ValueError('invalid persisted upload block metadata')
                path = folder / f'{index}.part'
                if not path.exists():
                    # A crash during bounded assembly can leave some parts
                    # consumed. Do not block the node: discard this unfinished
                    # upload so a complete client retry can restore it.
                    interrupted = True
                    break
                length = path.stat().st_size
                if path.is_symlink() or not 0 < length <= self.max_chunk_bytes:
                    raise ValueError('invalid persisted upload block size')
                parts[index], hashes[index] = path, block_hash
                size += length
            if interrupted:
                self._remove_folder(folder)
                continue
            if size > self.max_total_bytes or self._held_bytes + size > self.max_disk_bytes:
                raise ValueError('persisted uploads exceed the configured disk capacity')
            self._reserve(sender)
            self._entries[(sender, digest)] = {'action': meta['action'], 'total': meta['total'],
                                              'parts': parts, 'hashes': hashes, 'size': size,
                                              'folder': folder, 'updated': meta['updated']}
            self._held_bytes += size
        for path in self.directory.glob('complete-*'):
            if self.clock() - path.stat().st_mtime >= self.ttl:
                path.unlink()

    # -- validation ---------------------------------------------------------

    def _spec(self, payload):
        if not isinstance(payload, dict) or set(payload) != {'action', 'digest', 'index', 'total', 'data'}:
            raise ValueError('invalid chunk specification')
        action = payload['action']
        digest = payload['digest']
        index = payload['index']
        total = payload['total']
        blob = payload['data']
        if not isinstance(action, str) or not action or action.startswith('_'):
            raise ValueError('chunk cannot carry a reserved or empty action')
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('chunk digest must be 64 lowercase hex characters')
        if type(total) is not int or not 1 <= total <= self.max_chunks:
            raise ValueError('chunk count outside the configured limit')
        if type(index) is not int or not 0 <= index < total:
            raise ValueError('chunk index outside its declared range')
        if not isinstance(blob, bytes) or not blob:
            raise ValueError('chunk data must be non-empty bytes')
        if len(blob) > self.max_chunk_bytes:
            raise ValueError('chunk exceeds the configured block size limit')
        return action, digest, index, total, blob

    # -- public API ---------------------------------------------------------

    def accept(self, sender, payload):
        """Add one chunk.

        Returns ``{'complete': False, 'received': k, 'total': n}`` while more
        blocks are needed, or ``{'complete': True, 'action': str, 'body': bytes}``
        exactly once, after which the buffered state for that digest is dropped.
        """
        action, digest, index, total, blob = self._spec(payload)
        self.cleanup_expired()
        key = (sender, digest)
        entry = self._entries.get(key)
        if entry is None:
            self._reserve(sender)
            folder = Path(tempfile.mkdtemp(prefix='parts-', dir=self.directory))
            entry = self._entries[key] = {'action': action, 'total': total, 'parts': {},
                                         'size': 0, 'folder': folder, 'updated': self.clock(), 'hashes': {}}
        elif entry['action'] != action or entry['total'] != total:
            raise ValueError('chunk does not match the submission already in progress')
        if index in entry['parts']:
            if entry['parts'][index].read_bytes() != blob:
                raise ValueError('chunk index replayed with different content')
            entry['updated'] = self.clock()
            self._save_entry(sender, digest, entry)
            if len(entry['parts']) == total:
                return self._finish(sender, digest, entry)
            return {'complete': False, 'received': len(entry['parts']), 'total': total}
        if entry['size'] + len(blob) > self.max_total_bytes:
            self.discard(sender, digest)
            raise ValueError('chunked submission exceeds the configured size limit')
        if self._held_bytes + len(blob) + min(self.max_chunk_bytes, entry['size'] + len(blob)) > self.max_disk_bytes:
            self.discard(sender, digest)
            raise ValueError('chunked submissions exceed the configured disk capacity')
        part_path = entry['folder'] / f'{index}.part'
        try:
            part_path.write_bytes(blob)
        except BaseException:
            self.discard(sender, digest)
            raise
        entry['size'] += len(blob)
        self._held_bytes += len(blob)
        entry['updated'] = self.clock()
        entry['parts'][index] = part_path
        entry['hashes'][index] = hashlib.sha256(blob).hexdigest()
        self._save_entry(sender, digest, entry)
        if len(entry['parts']) < total:
            return {'complete': False, 'received': len(entry['parts']), 'total': total}
        return self._finish(sender, digest, entry)

    def _finish(self, sender, digest, entry):
        action, total = entry['action'], entry['total']
        output = tempfile.NamedTemporaryFile(mode='wb', prefix='complete-', dir=self.directory, delete=False)
        output_path = Path(output.name)
        hasher = hashlib.sha256()
        try:
            with output:
                for i in range(total):
                    with entry['parts'][i].open('rb') as part:
                        while block := part.read(65536):
                            hasher.update(block)
                            output.write(block)
                    # Reclaim each part as it is copied; assembly adds at most
                    # one block to disk usage instead of a second whole body.
                    entry['parts'][i].unlink()
            if hasher.hexdigest() != digest:
                raise ValueError('assembled submission does not match its digest')
            self.discard(sender, digest)
            if self.file_mode or entry['size'] > SEND_THRESHOLD:
                return {'complete': True, 'action': action, 'path': output_path,
                        'block_hashes': [entry['hashes'][i] for i in range(total)]}
            body = output_path.read_bytes()
            output_path.unlink()
            return {'complete': True, 'action': action, 'body': body}
        except BaseException:
            output_path.unlink(missing_ok=True)
            self.discard(sender, digest)
            raise

    def pending(self):
        """Number of submissions currently buffered (diagnostics and tests)."""
        return len(self._entries)

    def discard(self, sender, digest):
        entry = self._entries.pop((sender, digest), None)
        if entry is not None:
            self._held_bytes -= entry['size']
            self._remove_folder(entry['folder'])

    def cleanup_expired(self):
        for sender, digest in list(self._entries):
            if self.clock() - self._entries[(sender, digest)]['updated'] >= self.ttl:
                self.discard(sender, digest)

    def close(self):
        for sender, digest in list(self._entries):
            self.discard(sender, digest)
        if self._temp_directory is not None:
            self._temp_directory.cleanup()

    def _reserve(self, sender):
        if len(self._entries) >= self.max_entries:
            raise ValueError('too many concurrent chunked submissions')
        held = sum(1 for (owner, _) in self._entries if owner == sender)
        if held >= self.max_entries_per_sender:
            raise ValueError('too many concurrent chunked submissions from one sender')


class ResponseStore:
    """Bounded, persistent response files available through authenticated RPC.

    The token never grants access by itself: every download also binds the
    original request ID and its canonical fingerprint. Files expire after an
    idle interval. Expiry invalidates retrieval, never reexecutes the action.
    """

    def __init__(self, directory, *, max_total_bytes=MAX_TOTAL_BYTES,
                 max_disk_bytes=MAX_DISK_BYTES, max_entries=MAX_ENTRIES,
                 chunk_bytes=CHUNK_BYTES, ttl=TRANSFER_TTL, clock=time.time):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.max_total_bytes, self.max_disk_bytes = max_total_bytes, max_disk_bytes
        self.max_entries, self.chunk_bytes = max_entries, chunk_bytes
        self.ttl, self.clock = ttl, clock
        self.cleanup_expired()

    @staticmethod
    def _token(token):
        if not isinstance(token, str) or len(token) != 64 or any(c not in '0123456789abcdef' for c in token):
            raise ValueError('invalid response transfer token')
        return token

    @staticmethod
    def _binding(context, fingerprint):
        return hashlib.sha256((context + '\x00' + fingerprint).encode()).hexdigest()

    def _meta(self, token):
        token = self._token(token)
        path = self.directory / (token + '.json')
        try:
            meta = json.loads(path.read_text('utf8'))
        except FileNotFoundError as exc:
            raise ValueError('response transfer expired or unavailable') from exc
        if self.clock() - meta['updated'] >= self.ttl:
            self._discard(token)
            raise ValueError('response transfer expired or unavailable')
        return meta

    def _save(self, token, meta):
        target = self.directory / (token + '.json')
        temp = target.with_suffix('.tmp')
        temp.write_text(json.dumps(meta, sort_keys=True), encoding='utf8')
        temp.replace(target)

    def _discard(self, token):
        self._token(token)
        (self.directory / (token + '.bin')).unlink(missing_ok=True)
        (self.directory / (token + '.json')).unlink(missing_ok=True)

    def cleanup_expired(self):
        for path in self.directory.glob('*.json'):
            token = self._token(path.stem)
            meta = json.loads(path.read_text('utf8'))
            if self.clock() - meta['updated'] >= self.ttl:
                self._discard(token)
        for path in self.directory.glob('*.bin'):
            if not path.with_suffix('.json').exists() and self.clock() - path.stat().st_mtime >= self.ttl:
                self._token(path.stem)
                path.unlink()
        for path in self.directory.glob('_encode-*'):
            if self.clock() - path.stat().st_mtime >= self.ttl:
                path.unlink()

    def publish(self, encoded, context, fingerprint):
        self.cleanup_expired()
        existing = list(self.directory.glob('*.json'))
        held = sum((self.directory / (p.stem + '.bin')).stat().st_size for p in existing)
        if encoded.size > self.max_total_bytes:
            raise ValueError('response exceeds the configured size limit')
        if len(existing) >= self.max_entries or held + encoded.size > self.max_disk_bytes:
            raise ValueError('response transfers exceed the configured disk capacity')
        token = secrets.token_hex(32)
        target = self.directory / (token + '.bin')
        try:
            if encoded.path is not None:
                encoded.file.close()
                encoded.path.replace(target)
                encoded.path = None
            else:
                encoded.file.seek(0)
                with target.open('wb') as out:
                    while block := encoded.file.read(65536):
                        out.write(block)
            meta = {'digest': encoded.digest, 'bytes': encoded.size,
                    'total': math.ceil(encoded.size / self.chunk_bytes),
                    'chunk_bytes': self.chunk_bytes, 'updated': self.clock(),
                    'bindings': [self._binding(context, fingerprint)]}
            self._save(token, meta)
            return self.descriptor(token, context, fingerprint)
        except BaseException:
            self._discard(token)
            raise

    def encoding_budget(self):
        """Include the response being encoded in the aggregate disk budget."""
        self.cleanup_expired()
        held = sum(path.stat().st_size for path in self.directory.glob('*.bin'))
        return max(0, min(self.max_total_bytes, self.max_disk_bytes - held))

    def descriptor(self, token, context, fingerprint):
        meta = self._meta(token)
        binding = self._binding(context, fingerprint)
        if binding not in meta['bindings']:
            if len(meta['bindings']) >= 64:
                raise ValueError('response transfer request binding limit exceeded')
            meta['bindings'].append(binding)
        meta['updated'] = self.clock()
        self._save(token, meta)
        return {'version': 1, 'token': token, 'request_id': context,
                'request_fingerprint': fingerprint,
                **{key: meta[key] for key in ('digest', 'bytes', 'total', 'chunk_bytes')}}

    def fetch(self, payload):
        fields = {'token', 'request_id', 'request_fingerprint', 'digest', 'index'}
        if not isinstance(payload, dict) or set(payload) != fields:
            raise ValueError('invalid response download specification')
        meta = self._meta(payload['token'])
        if (not isinstance(payload['request_id'], str)
                or not isinstance(payload['request_fingerprint'], str)
                or self._binding(payload['request_id'], payload['request_fingerprint']) not in meta['bindings']
                or payload['digest'] != meta['digest']):
            raise ValueError('response download does not match its original request')
        index = payload['index']
        if type(index) is not int or not 0 <= index < meta['total']:
            raise ValueError('response chunk index outside its declared range')
        with (self.directory / (payload['token'] + '.bin')).open('rb') as stream:
            stream.seek(index * meta['chunk_bytes'])
            block = stream.read(meta['chunk_bytes'])
        if len(block) != min(meta['chunk_bytes'], meta['bytes'] - index * meta['chunk_bytes']):
            raise ValueError('response transfer file is truncated')
        meta['updated'] = self.clock()
        self._save(payload['token'], meta)
        return {**payload, 'data': block,
                **{key: meta[key] for key in ('bytes', 'total', 'chunk_bytes')}}
