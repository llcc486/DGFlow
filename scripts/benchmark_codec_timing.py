"""Measure the encoding and decoding cost the canonical codec is on the hot path for.

Writes a small timing record so the effect of a codec change is a measurement rather
than a claim. Not a benchmark suite: it reports three operations that every round
performs, at the sizes a real round uses, with the machine named.
"""
from __future__ import annotations

import argparse
import io
import json
import platform
import statistics
import sys
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT/'src'))

from dgfl.transport import binary


def transcript(entries):
    """A structure shaped like an authenticated transcript: many small values."""
    return {'context_hash': 'ab'*32,
            'messages': {f'authority{index}': {
                'commitment': 'cd'*48, 'share': 'ef'*48, 'ack': index,
                'sender': f'authority{index}', 'signature': '12'*64} for index in range(entries)},
            'order': [f'authority{index}' for index in range(entries)]}


def measure(function, repeats):
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        function()
        samples.append(time.perf_counter()-start)
    return {'median_s': statistics.median(samples), 'min_s': min(samples),
            'max_s': max(samples), 'repeats': repeats}


def benchmark(entries, repeats):
    value = transcript(entries)
    encoded = binary.packb(value)
    operations = {
        'encode_transcript': lambda: binary.packb(value),
        'decode_transcript': lambda: binary.unpack_from(io.BytesIO(encoded)),
        'packb_snapshot_then_reencode': lambda: binary.packb(binary.CanonicalPayload(value)),
    }
    return {'entries': entries, 'encoded_bytes': len(encoded),
            'operations': {name: measure(function, repeats)
                           for name, function in operations.items()}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', type=Path, help='Write the measurements as JSON')
    parser.add_argument('--entries', type=int, nargs='+', default=[3, 16, 64],
                        help='Authority counts to encode for (default 3 16 64)')
    parser.add_argument('--repeats', type=int, default=25)
    arguments = parser.parse_args(argv)
    if arguments.repeats < 1:
        parser.error('--repeats must be at least 1')
    if any(entries < 1 for entries in arguments.entries):
        parser.error('--entries must all be at least 1')
    report = {'kind': 'canonical-codec-timing',
              'python': platform.python_version(),
              'implementation': platform.python_implementation(),
              'machine': 'redacted',
              'platform': platform.platform(),
              'scope': ('Single-process in-memory timings of the canonical codec. '
                        'No network, disk or cryptographic work; not a protocol benchmark.'),
              # A rejected change is recorded so the same reasoning is not tried again
              # without a measurement of its own.
              'rejected_changes': [{
                  'what': ('_StreamReader: a bounded read-ahead window so a varint costs '
                           'one stream.read instead of one per byte'),
                  'reason_expected': ('a varint is at most ten bytes, so a three-byte '
                                      'varint reads three times'),
                  'measured': 'decode of a 64-authority transcript: 0.4521 ms -> 1.1835 ms',
                  'verdict': 'rejected; reverted',
                  'why': ('window bookkeeping cost more per value than the reads it saved, '
                          'and the large byte-string values that dominate a transcript were '
                          'already served by a single read'),
              }],
              'results': [benchmark(entries, arguments.repeats) for entries in arguments.entries]}
    if arguments.json:
        arguments.json.parent.mkdir(parents=True, exist_ok=True)
        arguments.json.write_text(json.dumps(report, ensure_ascii=False, indent=2,
                                             sort_keys=True) + '\n', encoding='utf8')
    print(f"canonical codec timings ({report['machine']}, {report['implementation']} "
          f"{report['python']})")
    for result in report['results']:
        print(f"  {result['entries']:>4} authorities, {result['encoded_bytes']:>8} bytes")
        for name, timing in result['operations'].items():
            print(f"    {name:<32} {timing['median_s']*1e3:>8.4f} ms "
                  f"(min {timing['min_s']*1e3:.4f})")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
